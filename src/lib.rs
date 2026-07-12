//! Test harness for MDK e2e through a real Nostr relay (strfry).
//!
//! Provides:
//! - `RelayPeeler`: pass-through TransportPeeler (no encryption layer)
//! - `test_identity`: deterministic secp256k1 identity from seed
//! - Relay publish/fetch helpers
//! - `event_to_transport_message`: reconstruct TransportMessage from Nostr event

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as B64Engine;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::schnorr::SigningKey;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};

// ── Event kinds ──────────────────────────────────────────────────────────────

pub const KIND_KEY_PACKAGE: u16 = 443;
pub const KIND_WELCOME: u16 = 444;
pub const KIND_GROUP_MESSAGE: u16 = 445;

// ── RelayPeeler (pass-through) ───────────────────────────────────────────────

pub struct RelayPeeler;

fn hash_id(bytes: &[u8]) -> MessageId {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

#[async_trait]
impl TransportPeeler for RelayPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("relay-test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: ctx.transport_group_id().unwrap_or_default().to_vec(),
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("relay-test".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

// ── Test identity ────────────────────────────────────────────────────────────

fn signing_key(seed: &[u8]) -> SigningKey {
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk;
        }
        counter += 1;
    }
}

/// Derive a deterministic 32-byte x-only secp256k1 pubkey from a human seed.
pub fn pad32(name: &[u8]) -> Vec<u8> {
    signing_key(name).verifying_key().to_bytes().to_vec()
}

struct TestAccountIdentityProofSigner(SigningKey);

impl AccountIdentityProofSigner for TestAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.0.verifying_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match test key".into());
        }
        let event_id = request.proof_event_id()?;
        let signature: k256::schnorr::Signature = self
            .0
            .sign_prehash(&event_id)
            .map_err(|e: k256::ecdsa::Error| e.to_string())?;
        Ok(signature.to_bytes())
    }
}

/// Returns (32-byte x-only pubkey, proof signer).
pub fn test_identity(seed: &[u8]) -> (Vec<u8>, Arc<dyn AccountIdentityProofSigner>) {
    let sk = signing_key(seed);
    let pubkey = sk.verifying_key().to_bytes().to_vec();
    (pubkey, Arc::new(TestAccountIdentityProofSigner(sk)))
}

// ── Relay helpers ────────────────────────────────────────────────────────────

/// Publish a TransportMessage as a base64-encoded Nostr event to the relay.
pub async fn publish_to_relay(
    client: &Client,
    keys: &Keys,
    msg: &TransportMessage,
) -> Result<EventId, Box<dyn std::error::Error>> {
    let content = B64.encode(&msg.payload);

    let kind = match &msg.envelope {
        TransportEnvelope::Welcome { .. } => Kind::Custom(KIND_WELCOME),
        TransportEnvelope::GroupMessage { .. } => Kind::Custom(KIND_GROUP_MESSAGE),
    };

    let mut tags = Vec::new();
    match &msg.envelope {
        TransportEnvelope::Welcome { recipient } => {
            tags.push(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
                vec![hex::encode(recipient.as_slice())],
            ));
        }
        TransportEnvelope::GroupMessage {
            transport_group_id,
        } => {
            tags.push(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::H)),
                vec![hex::encode(transport_group_id)],
            ));
        }
    }

    let builder = EventBuilder::new(kind, content).tags(tags);
    let event = builder.sign_with_keys(keys)?;
    let event_id = event.id;
    client.send_event(&event).await?;
    Ok(event_id)
}

/// Publish a raw KeyPackage to the relay (kind 443).
pub async fn publish_key_package(
    client: &Client,
    keys: &Keys,
    kp_bytes: &[u8],
    owner_pubkey: &[u8],
) -> Result<EventId, Box<dyn std::error::Error>> {
    let content = B64.encode(kp_bytes);
    let tags = vec![Tag::custom(
        TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
        vec![hex::encode(owner_pubkey)],
    )];
    let builder = EventBuilder::new(Kind::Custom(KIND_KEY_PACKAGE), content).tags(tags);
    let event = builder.sign_with_keys(keys)?;
    let event_id = event.id;
    client.send_event(&event).await?;
    Ok(event_id)
}

/// Fetch events of a given kind, optionally filtered by tag.
pub async fn fetch_events(
    client: &Client,
    kind: Kind,
    tag_filter: Option<(&str, &str)>,
    since: Option<nostr_sdk::Timestamp>,
) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let mut filter = Filter::new().kind(kind);
    if let Some(ts) = since {
        filter = filter.since(ts);
    }
    if let Some((tag, value)) = tag_filter {
        match tag {
            "p" => {
                let pk = PublicKey::from_hex(value)?;
                filter = filter.pubkey(pk);
            }
            "h" => {
                filter = filter.custom_tag(
                    SingleLetterTag::lowercase(Alphabet::H),
                    value.to_string(),
                );
            }
            _ => {}
        }
    }
    let events = client
        .fetch_events(filter, Duration::from_secs(5))
        .await?;
    let mut events: Vec<Event> = events.into_iter().collect();
    events.sort_by_key(|e| e.created_at);
    Ok(events)
}

/// Reconstruct a TransportMessage from a Nostr event.
pub fn event_to_transport_message(event: &Event) -> TransportMessage {
    let payload = B64
        .decode(event.content.as_bytes())
        .expect("event content is valid base64");

    let envelope = match event.kind {
        Kind::Custom(k) if k == KIND_WELCOME => {
            let recipient_hex = event
                .tags
                .iter()
                .find_map(|t| {
                    let tag = t.as_slice();
                    if tag.len() >= 2 && tag[0] == "p" {
                        Some(tag[1].clone())
                    } else {
                        None
                    }
                })
                .expect("welcome event must have p-tag");
            let recipient_bytes = hex::decode(&recipient_hex).expect("p-tag is valid hex");
            TransportEnvelope::Welcome {
                recipient: MemberId::new(recipient_bytes),
            }
        }
        Kind::Custom(k) if k == KIND_GROUP_MESSAGE => {
            let group_id_hex = event
                .tags
                .iter()
                .find_map(|t| {
                    let tag = t.as_slice();
                    if tag.len() >= 2 && tag[0] == "h" {
                        Some(tag[1].clone())
                    } else {
                        None
                    }
                })
                .expect("group message event must have h-tag");
            let group_id_bytes = hex::decode(&group_id_hex).expect("h-tag is valid hex");
            TransportEnvelope::GroupMessage {
                transport_group_id: group_id_bytes,
            }
        }
        other => panic!("unexpected event kind: {other:?}"),
    };

    TransportMessage {
        id: MessageId::new(event.id.to_bytes().to_vec()),
        payload,
        timestamp: Timestamp(event.created_at.as_secs()),
        causal_deps: vec![],
        source: TransportSource("nostr".into()),
        envelope,
    }
}

/// Create a nostr-sdk Client connected to the local strfry relay.
pub async fn make_relay_client() -> Result<Client, Box<dyn std::error::Error>> {
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay("ws://localhost:18777").await?;
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(client)
}

/// Create a nostr-sdk Client with specific keys connected to the local strfry relay.
pub async fn make_relay_client_with_keys(
    keys: Keys,
) -> Result<Client, Box<dyn std::error::Error>> {
    let client = Client::new(keys);
    client.add_relay("ws://localhost:18777").await?;
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(client)
}
