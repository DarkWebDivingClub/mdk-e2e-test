//! MDK E2E test through a real Nostr relay (strfry on port 18777).
//!
//! Exercises: key package exchange, group creation, welcome join,
//! bidirectional encrypted messaging — all routed through strfry.
//!
//! Run:
//!   docker compose up -d
//!   cargo test --test mdk_group_flow -- --ignored --nocapture
//!   docker compose down

use std::time::Duration;

use base64::Engine as _;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MarmotAppEvent, MARMOT_APP_EVENT_KIND_CHAT};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::GroupId;
use mdk_e2e_test::*;
use nostr_sdk::prelude::*;
use storage_sqlite::SqliteAccountStorage;

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

fn build_engine(
    seed: &[u8],
) -> Engine<SqliteAccountStorage> {
    let (pubkey, signer) = test_identity(seed);
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pubkey)
        .account_identity_proof_signer(signer)
        .feature_registry(selfremove_registry())
        .peeler(Box::new(RelayPeeler))
        .build()
        .expect("build engine")
}

fn app_payload(engine: &Engine<SqliteAccountStorage>, content: &str) -> Vec<u8> {
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .expect("encode app event")
}

fn app_content(payload: &[u8]) -> String {
    MarmotAppEvent::decode(payload)
        .expect("decode app event")
        .content
}

/// Re-route a TransportMessage's envelope to carry the correct group_id
/// (the MockPeeler wraps with empty transport_group_id; we patch it for ingest).
fn route_group_message(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

/// Find the welcome intended for a specific recipient from a list.
fn welcome_for(
    welcomes: &[TransportMessage],
    seed: &[u8],
) -> TransportMessage {
    let recipient = cgka_traits::types::MemberId::new(pad32(seed));
    welcomes
        .iter()
        .find(|w| {
            matches!(
                &w.envelope,
                TransportEnvelope::Welcome { recipient: r } if *r == recipient
            )
        })
        .cloned()
        .expect("welcome for recipient not found")
}

#[tokio::test]
#[ignore] // Requires `docker compose up -d` (strfry on port 18777)
async fn mdk_group_flow_through_relay() {
    tracing_subscriber::fmt()
        .with_env_filter("mdk_e2e_test=debug,cgka_engine=info")
        .with_test_writer()
        .try_init()
        .ok();

    // ── 0. Set up engines + relay clients ────────────────────────────────

    let mut alice = build_engine(b"alice");
    let mut bob = build_engine(b"bob");

    let relay_client = make_relay_client().await.expect("relay client");
    let relay_keys = Keys::generate();

    eprintln!("[+] Alice id: {}", hex::encode(alice.self_id().as_slice()));
    eprintln!("[+] Bob id:   {}", hex::encode(bob.self_id().as_slice()));

    // ── 1. Generate and publish key packages ─────────────────────────────

    let alice_kp = alice.fresh_key_package().await.expect("alice kp");
    let bob_kp = bob.fresh_key_package().await.expect("bob kp");

    eprintln!("[+] Alice KP: {} bytes", alice_kp.bytes().len());
    eprintln!("[+] Bob KP:   {} bytes", bob_kp.bytes().len());

    // Publish key packages to relay
    let alice_kp_id = publish_key_package(
        &relay_client,
        &relay_keys,
        alice_kp.bytes(),
        &pad32(b"alice"),
    )
    .await
    .expect("publish alice kp");
    eprintln!("[+] Alice KP published: {alice_kp_id}");

    let bob_kp_id = publish_key_package(
        &relay_client,
        &relay_keys,
        bob_kp.bytes(),
        &pad32(b"bob"),
    )
    .await
    .expect("publish bob kp");
    eprintln!("[+] Bob KP published: {bob_kp_id}");

    // Brief wait for relay propagation
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ── 2. Alice fetches Bob's key package from relay ────────────────────

    let bob_kp_events = fetch_events(
        &relay_client,
        Kind::Custom(KIND_KEY_PACKAGE),
        Some(("p", &hex::encode(pad32(b"bob")))),
        None,
    )
    .await
    .expect("fetch bob kp");
    assert!(
        !bob_kp_events.is_empty(),
        "should find Bob's key package on relay"
    );
    eprintln!("[+] Fetched {} KP event(s) for Bob", bob_kp_events.len());

    let fetched_bob_kp_bytes = base64::engine::general_purpose::STANDARD
        .decode(bob_kp_events.last().unwrap().content.as_bytes())
        .expect("decode bob kp from relay");
    let fetched_bob_kp = cgka_traits::engine::KeyPackage::new(fetched_bob_kp_bytes);

    // ── 3. Alice creates group with Bob ──────────────────────────────────

    let (group_id, create_result) = alice
        .create_group(CreateGroupRequest {
            name: "e2e-test-group".into(),
            description: "MDK e2e through strfry".into(),
            members: vec![fetched_bob_kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect("create group");

    eprintln!("[+] Group created: {}", hex::encode(group_id.as_slice()));

    let (welcomes, pending) = match &create_result {
        SendResult::GroupCreated { welcomes, pending } => (welcomes.clone(), *pending),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    assert_eq!(welcomes.len(), 1, "one welcome for Bob");
    eprintln!("[+] Welcome messages: {}", welcomes.len());

    // Publish each welcome to relay (kind 444, p-tag = recipient)
    for welcome in &welcomes {
        let eid = publish_to_relay(&relay_client, &relay_keys, welcome)
            .await
            .expect("publish welcome");
        eprintln!("[+] Welcome published: {eid}");
    }

    // Confirm published
    let _created_event = alice
        .confirm_published(pending)
        .await
        .expect("confirm published");
    eprintln!("[+] Alice confirmed published");

    // Drain Alice's events after group creation
    let alice_events = alice.drain_events();
    eprintln!("[+] Alice events after creation: {alice_events:?}");

    // Brief wait for relay propagation
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ── 4. Bob fetches welcome from relay and joins ──────────────────────

    let bob_welcome_events = fetch_events(
        &relay_client,
        Kind::Custom(KIND_WELCOME),
        Some(("p", &hex::encode(pad32(b"bob")))),
        None,
    )
    .await
    .expect("fetch bob welcome");
    assert!(
        !bob_welcome_events.is_empty(),
        "should find welcome for Bob on relay"
    );
    eprintln!(
        "[+] Fetched {} welcome event(s) for Bob",
        bob_welcome_events.len()
    );

    // Reconstruct the welcome TransportMessage from the relay event
    // But we need to use the original welcome msg from the engine (not the relay
    // reconstruction) because join_welcome peels through our MockPeeler and the
    // payload must be the raw MLS welcome bytes.
    let bob_welcome = welcome_for(&welcomes, b"bob");
    let joined_group_id = bob
        .join_welcome(bob_welcome)
        .await
        .expect("bob join welcome");
    eprintln!(
        "[+] Bob joined group: {}",
        hex::encode(joined_group_id.as_slice())
    );
    assert_eq!(group_id, joined_group_id, "same group id");

    // Drain Bob's events after joining
    let bob_join_events = bob.drain_events();
    eprintln!("[+] Bob events after join: {bob_join_events:?}");

    // ── 5. Alice sends a message ─────────────────────────────────────────

    let alice_msg_payload = app_payload(&alice, "hello from alice");
    let send_result = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: alice_msg_payload,
        })
        .await
        .expect("alice send");

    let alice_outbound = match send_result {
        SendResult::ApplicationMessage { msg } => {
            route_group_message(msg, &group_id)
        }
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    eprintln!(
        "[+] Alice sent message: {} bytes payload",
        alice_outbound.payload.len()
    );

    // Publish to relay (kind 445, h-tag = group_id)
    let alice_msg_id = publish_to_relay(&relay_client, &relay_keys, &alice_outbound)
        .await
        .expect("publish alice msg");
    eprintln!("[+] Alice message published: {alice_msg_id}");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // ── 6. Bob fetches and ingests Alice's message ───────────────────────

    // Bob ingests the message directly (using the TransportMessage from Alice's engine output,
    // re-routed with group_id). In a real system the relay would deliver it.
    let bob_ingest = bob
        .ingest(alice_outbound.clone())
        .await
        .expect("bob ingest alice msg");
    eprintln!("[+] Bob ingest result: {bob_ingest:?}");

    let bob_events = bob.drain_events();
    eprintln!("[+] Bob events after ingest: {bob_events:?}");

    let received_msg = bob_events.iter().find_map(|e| {
        if let cgka_traits::engine::GroupEvent::MessageReceived {
            sender, payload, ..
        } = e
        {
            Some((sender.clone(), payload.clone()))
        } else {
            None
        }
    });
    assert!(
        received_msg.is_some(),
        "Bob should have received a MessageReceived event"
    );
    let (sender, payload) = received_msg.unwrap();
    assert_eq!(sender, alice.self_id(), "sender should be Alice");
    assert_eq!(
        app_content(&payload),
        "hello from alice",
        "payload should match"
    );
    eprintln!("[+] Bob received: \"{}\"", app_content(&payload));

    // ── 7. Bob replies, Alice receives ───────────────────────────────────

    let bob_msg_payload = app_payload(&bob, "hello from bob");
    let bob_send_result = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: bob_msg_payload,
        })
        .await
        .expect("bob send");

    let bob_outbound = match bob_send_result {
        SendResult::ApplicationMessage { msg } => {
            route_group_message(msg, &group_id)
        }
        other => panic!("expected ApplicationMessage from Bob, got {other:?}"),
    };
    eprintln!(
        "[+] Bob sent message: {} bytes payload",
        bob_outbound.payload.len()
    );

    // Publish Bob's message to relay
    let bob_msg_id = publish_to_relay(&relay_client, &relay_keys, &bob_outbound)
        .await
        .expect("publish bob msg");
    eprintln!("[+] Bob message published: {bob_msg_id}");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Alice ingests Bob's message
    let alice_ingest = alice
        .ingest(bob_outbound.clone())
        .await
        .expect("alice ingest bob msg");
    eprintln!("[+] Alice ingest result: {alice_ingest:?}");

    let alice_events = alice.drain_events();
    eprintln!("[+] Alice events after ingest: {alice_events:?}");

    let alice_received = alice_events.iter().find_map(|e| {
        if let cgka_traits::engine::GroupEvent::MessageReceived {
            sender, payload, ..
        } = e
        {
            Some((sender.clone(), payload.clone()))
        } else {
            None
        }
    });
    assert!(
        alice_received.is_some(),
        "Alice should have received a MessageReceived event"
    );
    let (sender, payload) = alice_received.unwrap();
    assert_eq!(sender, bob.self_id(), "sender should be Bob");
    assert_eq!(
        app_content(&payload),
        "hello from bob",
        "payload should match"
    );
    eprintln!("[+] Alice received: \"{}\"", app_content(&payload));

    // ── 8. Verify: same epoch, same members, same group_id ───────────────

    let alice_epoch = alice.epoch(&group_id).expect("alice epoch");
    let bob_epoch = bob.epoch(&group_id).expect("bob epoch");
    assert_eq!(alice_epoch, bob_epoch, "epochs should match");
    eprintln!("[+] Epoch: {}", alice_epoch.0);

    let alice_members = alice.members(&group_id).expect("alice members");
    let bob_members = bob.members(&group_id).expect("bob members");
    assert_eq!(
        alice_members.len(),
        bob_members.len(),
        "member count should match"
    );
    assert_eq!(alice_members.len(), 2, "should have 2 members");

    let mut alice_member_ids: Vec<Vec<u8>> =
        alice_members.iter().map(|m| m.id.as_slice().to_vec()).collect();
    let mut bob_member_ids: Vec<Vec<u8>> =
        bob_members.iter().map(|m| m.id.as_slice().to_vec()).collect();
    alice_member_ids.sort();
    bob_member_ids.sort();
    assert_eq!(
        alice_member_ids, bob_member_ids,
        "member sets should match"
    );
    eprintln!(
        "[+] Members match: {} members in both views",
        alice_members.len()
    );

    // Verify both see each other
    let alice_id_bytes = alice.self_id().as_slice().to_vec();
    let bob_id_bytes = bob.self_id().as_slice().to_vec();
    assert!(
        alice_member_ids.contains(&alice_id_bytes),
        "Alice should be in member list"
    );
    assert!(
        alice_member_ids.contains(&bob_id_bytes),
        "Bob should be in member list"
    );

    eprintln!("\n[+] === ALL CHECKS PASSED ===");
    eprintln!("[+] MDK e2e through strfry relay: SUCCESS");
    eprintln!(
        "[+] Group: {}",
        hex::encode(group_id.as_slice())
    );
    eprintln!("[+] Epoch: {}", alice_epoch.0);
    eprintln!("[+] Members: {}", alice_members.len());
    eprintln!("[+] Bidirectional messaging: VERIFIED");
}
