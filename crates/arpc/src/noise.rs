use arp_common::Pubkey;
use lru::LruCache;
use snow::{Builder, HandshakeState, TransportState};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;

/// Maximum Noise message size (snow limitation).
const MAX_NOISE_MSG: usize = 65535;

/// AEAD tag overhead per encrypted message.
const TAG_LEN: usize = 16;

/// Payload prefix bytes to distinguish message types on the wire.
pub mod prefix {
    /// Plaintext message (noise disabled or peer doesn't support it).
    pub const PLAINTEXT: u8 = 0x00;
    /// Noise IK handshake message 1 (initiator → responder).
    pub const HANDSHAKE_INIT: u8 = 0x01;
    /// Noise IK handshake message 2 (responder → initiator).
    pub const HANDSHAKE_RESP: u8 = 0x02;
    /// Noise-encrypted transport data.
    pub const ENCRYPTED: u8 = 0x03;
}

/// Convert an Ed25519 `SigningKey` into an X25519 keypair for Noise DH.
///
/// Uses the standard birational map: Ed25519 secret → SHA-512 left half → X25519 scalar,
/// Ed25519 public → Montgomery u-coordinate.
pub fn ed25519_to_x25519(signing_key: &ed25519_dalek::SigningKey) -> snow::Keypair {
    let private = signing_key.to_scalar_bytes().to_vec();
    let public = signing_key
        .verifying_key()
        .to_montgomery()
        .to_bytes()
        .to_vec();
    snow::Keypair { private, public }
}

/// Convert an Ed25519 public key (32 bytes) to X25519 public key (32 bytes).
///
/// # Errors
///
/// Returns [`NoiseError::InvalidPeerKey`] if the 32-byte array is not a valid
/// Ed25519 public key (not all byte patterns represent valid curve points).
pub fn ed25519_pub_to_x25519(ed_pub: &Pubkey) -> Result<[u8; 32], NoiseError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(ed_pub).map_err(NoiseError::InvalidPeerKey)?;
    Ok(vk.to_montgomery().to_bytes())
}

/// Errors arising from Noise IK encryption/decryption operations.
#[derive(Debug, Error)]
pub enum NoiseError {
    /// Snow protocol error.
    #[error("noise: {0}")]
    Snow(#[from] snow::Error),
    /// Message too short or malformed.
    #[error("noise: malformed: {0}")]
    Malformed(&'static str),
    /// Peer sent a handshake response but we have no pending handshake.
    #[error("noise: unexpected handshake message")]
    UnexpectedHandshake,
    /// Payload exceeds Noise maximum message size.
    #[error("noise: payload too large")]
    PayloadTooLarge,
    /// The peer's Ed25519 public key is not a valid curve point.
    #[error("noise: invalid peer key: {0}")]
    InvalidPeerKey(ed25519_dalek::SignatureError),
}

/// Result of processing an inbound noise-framed message.
pub enum InboundResult {
    /// Decrypted plaintext payload ready for the application.
    Payload(Vec<u8>),
    /// Handshake response that must be sent back to the peer.
    HandshakeResponse {
        /// Destination peer public key.
        to: Pubkey,
        /// Handshake response data to send.
        data: Vec<u8>,
    },
    /// Handshake completed, no payload to deliver (the init message carried no app data).
    HandshakeComplete,
}

/// Manages Noise IK sessions for E2E encryption between agents.
///
/// Handles the full lifecycle: Ed25519→X25519 key conversion, IK handshake
/// initiation/response, session caching, and encrypt/decrypt.
pub struct NoiseSessionManager {
    local_keypair: snow::Keypair,
    /// Completed sessions (both directions).
    sessions: LruCache<Pubkey, TransportState>,
    /// Pending handshakes we initiated (waiting for response) with timestamps.
    pub(crate) pending_handshakes: HashMap<Pubkey, (HandshakeState, Instant)>,
}

impl NoiseSessionManager {
    /// Creates a new session manager, converting the Ed25519 key to X25519.
    pub fn new(signing_key: &ed25519_dalek::SigningKey) -> Self {
        // 256 is a compile-time constant that is definitely non-zero,
        // so this unwrap will never fail at runtime
        #[allow(clippy::unwrap_used)]
        let cache_size = NonZeroUsize::new(256).unwrap();
        Self {
            local_keypair: ed25519_to_x25519(signing_key),
            sessions: LruCache::new(cache_size),
            pending_handshakes: HashMap::new(),
        }
    }

    /// Check if we have an established session with a peer.
    pub fn has_session(&self, peer: &Pubkey) -> bool {
        // LruCache::contains doesn't exist with &K on older versions,
        // use peek which doesn't update recency
        self.sessions.peek(peer).is_some()
    }

    /// Encrypt a payload for a peer with an established session.
    ///
    /// Returns `prefix::ENCRYPTED | ciphertext`.
    /// Returns `None` if no session exists (caller should initiate handshake).
    pub fn encrypt(
        &mut self,
        peer: &Pubkey,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        if payload.len() + TAG_LEN > MAX_NOISE_MSG {
            return Err(NoiseError::PayloadTooLarge);
        }
        let Some(transport) = self.sessions.get_mut(peer) else {
            return Ok(None);
        };
        let mut buf = vec![0u8; payload.len() + TAG_LEN];
        let len = transport.write_message(payload, &mut buf)?;
        buf.truncate(len);
        let mut framed = Vec::with_capacity(1 + len);
        framed.push(prefix::ENCRYPTED);
        framed.extend_from_slice(&buf);
        Ok(Some(framed))
    }

    /// Initiate a Noise IK handshake with a peer.
    ///
    /// Returns the framed handshake init message (`prefix::HANDSHAKE_INIT | handshake_bytes`).
    /// The caller should send this as the ARP payload to the peer.
    pub fn initiate_handshake(&mut self, peer: &Pubkey) -> Result<Vec<u8>, NoiseError> {
        // Clean up expired handshakes before starting new one
        self.cleanup_expired_handshakes();

        let x25519_remote = ed25519_pub_to_x25519(peer)?;
        // Parse the Noise pattern at compile time to avoid runtime failure
        static NOISE_PARAMS: std::sync::OnceLock<snow::params::NoiseParams> =
            std::sync::OnceLock::new();
        let params = NOISE_PARAMS.get_or_init(|| {
            NOISE_PATTERN
                .parse()
                .expect("hardcoded noise pattern is valid")
        });
        let mut hs = Builder::new(params.clone())
            .local_private_key(&self.local_keypair.private)
            .remote_public_key(&x25519_remote)
            .build_initiator()?;

        // IK msg1: → e, es, s, ss (no application payload in handshake)
        let mut buf = vec![0u8; 256];
        let len = hs.write_message(&[], &mut buf)?;
        buf.truncate(len);

        self.pending_handshakes.insert(*peer, (hs, Instant::now()));

        let mut framed = Vec::with_capacity(1 + len);
        framed.push(prefix::HANDSHAKE_INIT);
        framed.extend_from_slice(&buf);

        debug!("initiated noise handshake with peer");
        Ok(framed)
    }

    /// Process an inbound noise-framed message from a peer.
    ///
    /// Handles all prefix types: plaintext passthrough, handshake messages,
    /// and encrypted transport data.
    pub fn process_inbound(
        &mut self,
        from: &Pubkey,
        data: &[u8],
    ) -> Result<InboundResult, NoiseError> {
        if data.is_empty() {
            return Err(NoiseError::Malformed("empty payload"));
        }

        match data[0] {
            prefix::PLAINTEXT => {
                // Passthrough — peer sent plaintext (noise disabled on their end)
                Ok(InboundResult::Payload(data[1..].to_vec()))
            }

            prefix::HANDSHAKE_INIT => {
                // Peer is initiating a handshake with us
                self.handle_handshake_init(from, &data[1..])
            }

            prefix::HANDSHAKE_RESP => {
                // Peer is responding to our handshake
                self.handle_handshake_resp(from, &data[1..])
            }

            prefix::ENCRYPTED => {
                // Encrypted transport data
                self.handle_encrypted(from, &data[1..])
            }

            _ => Err(NoiseError::Malformed("unknown prefix byte")),
        }
    }

    fn handle_handshake_init(
        &mut self,
        from: &Pubkey,
        hs_data: &[u8],
    ) -> Result<InboundResult, NoiseError> {
        // Concurrent handshake tiebreaker: if we have a pending outgoing
        // handshake to this same peer, both sides initiated simultaneously.
        // Use deterministic tiebreaker: lower X25519 public key wins as initiator.
        if self.pending_handshakes.contains_key(from) {
            let remote_x25519 = ed25519_pub_to_x25519(from)?;
            if self.local_keypair.public < remote_x25519.to_vec() {
                // Our key is lower → we keep initiator role, reject their init
                debug!("concurrent handshake collision: we win as initiator (lower key)");
                return Err(NoiseError::UnexpectedHandshake);
            }
            // Their key is lower → they win as initiator, we yield and become responder
            debug!("concurrent handshake collision: we yield to peer (higher key)");
            self.pending_handshakes.remove(from);
        }

        let x25519_remote = ed25519_pub_to_x25519(from)?;

        // Build a responder. IK responder knows nothing about initiator's static key
        // upfront — it learns it from the handshake message.
        // Parse the Noise pattern at compile time to avoid runtime failure
        static NOISE_PARAMS_RESP: std::sync::OnceLock<snow::params::NoiseParams> =
            std::sync::OnceLock::new();
        let params = NOISE_PARAMS_RESP.get_or_init(|| {
            NOISE_PATTERN
                .parse()
                .expect("hardcoded noise pattern is valid")
        });
        let mut hs = Builder::new(params.clone())
            .local_private_key(&self.local_keypair.private)
            .remote_public_key(&x25519_remote)
            .build_responder()?;

        // Read msg1: ← e, es, s, ss
        let mut payload_buf = vec![0u8; hs_data.len()];
        let _payload_len = hs.read_message(hs_data, &mut payload_buf)?;

        // Write msg2: → e, ee, se
        let mut resp_buf = vec![0u8; 256];
        let resp_len = hs.write_message(&[], &mut resp_buf)?;
        resp_buf.truncate(resp_len);

        // Handshake complete on responder side
        let transport = hs.into_transport_mode()?;
        self.sessions.put(*from, transport);
        // Clean up any pending handshake we might have had with this peer
        self.pending_handshakes.remove(from);

        let mut framed = Vec::with_capacity(1 + resp_len);
        framed.push(prefix::HANDSHAKE_RESP);
        framed.extend_from_slice(&resp_buf);

        debug!("completed noise handshake as responder");
        Ok(InboundResult::HandshakeResponse {
            to: *from,
            data: framed,
        })
    }

    fn handle_handshake_resp(
        &mut self,
        from: &Pubkey,
        hs_data: &[u8],
    ) -> Result<InboundResult, NoiseError> {
        let Some((mut hs, _)) = self.pending_handshakes.remove(from) else {
            warn!("received handshake response from peer with no pending handshake");
            return Err(NoiseError::UnexpectedHandshake);
        };

        // Read msg2: ← e, ee, se
        let mut payload_buf = vec![0u8; hs_data.len()];
        let _payload_len = hs.read_message(hs_data, &mut payload_buf)?;

        // Handshake complete on initiator side
        let transport = hs.into_transport_mode()?;
        self.sessions.put(*from, transport);

        debug!("completed noise handshake as initiator");
        Ok(InboundResult::HandshakeComplete)
    }

    fn handle_encrypted(
        &mut self,
        from: &Pubkey,
        encrypted: &[u8],
    ) -> Result<InboundResult, NoiseError> {
        let Some(transport) = self.sessions.get_mut(from) else {
            warn!("received encrypted data from peer with no session");
            return Err(NoiseError::Malformed("no session for encrypted data"));
        };

        let mut buf = vec![0u8; encrypted.len()];
        let len = transport.read_message(encrypted, &mut buf)?;
        buf.truncate(len);

        Ok(InboundResult::Payload(buf))
    }

    /// Frame a plaintext payload (when noise is disabled or during fallback).
    pub fn frame_plaintext(payload: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(1 + payload.len());
        framed.push(prefix::PLAINTEXT);
        framed.extend_from_slice(payload);
        framed
    }

    /// Returns true if there's a pending (incomplete) handshake with this peer.
    pub fn has_pending_handshake(&self, peer: &Pubkey) -> bool {
        self.pending_handshakes.contains_key(peer)
    }

    /// Remove expired pending handshakes (older than HANDSHAKE_TIMEOUT_SECONDS).
    /// Returns number of removed handshakes.
    pub fn cleanup_expired_handshakes(&mut self) -> usize {
        let now = Instant::now();
        let timeout = Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS);
        let expired: Vec<Pubkey> = self
            .pending_handshakes
            .iter()
            .filter(|(_, (_, timestamp))| now.duration_since(*timestamp) >= timeout)
            .map(|(key, _)| *key)
            .collect();

        let count = expired.len();
        for key in expired {
            self.pending_handshakes.remove(&key);
            warn!(pubkey = %arp_common::base58::encode(&key), "noise handshake timed out");
        }
        count
    }

    /// Drop a pending handshake (e.g. on timeout).
    pub fn drop_pending_handshake(&mut self, peer: &Pubkey) {
        self.pending_handshakes.remove(peer);
    }

    /// Remove a completed session.
    pub fn remove_session(&mut self, peer: &Pubkey) {
        self.sessions.pop(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn ed25519_to_x25519_produces_valid_keypair() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let x_kp = ed25519_to_x25519(&signing_key);
        assert_eq!(x_kp.private.len(), 32);
        assert_eq!(x_kp.public.len(), 32);
    }

    #[test]
    fn ed25519_pub_to_x25519_is_consistent() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        let x_pub = ed25519_pub_to_x25519(&pubkey).unwrap();
        let x_kp = ed25519_to_x25519(&signing_key);
        assert_eq!(x_pub.to_vec(), x_kp.public);
    }

    #[test]
    fn full_handshake_and_transport() {
        let alice_ed = SigningKey::generate(&mut OsRng);
        let bob_ed = SigningKey::generate(&mut OsRng);

        let alice_pubkey: Pubkey = alice_ed.verifying_key().to_bytes();
        let bob_pubkey: Pubkey = bob_ed.verifying_key().to_bytes();

        let mut alice = NoiseSessionManager::new(&alice_ed);
        let mut bob = NoiseSessionManager::new(&bob_ed);

        // Alice initiates handshake with Bob
        let hs_init = alice.initiate_handshake(&bob_pubkey).unwrap();
        assert_eq!(hs_init[0], prefix::HANDSHAKE_INIT);
        assert!(alice.has_pending_handshake(&bob_pubkey));

        // Bob processes the handshake init
        let result = bob.process_inbound(&alice_pubkey, &hs_init).unwrap();
        let hs_resp = match result {
            InboundResult::HandshakeResponse { to, data } => {
                assert_eq!(to, alice_pubkey);
                assert_eq!(data[0], prefix::HANDSHAKE_RESP);
                data
            }
            _ => panic!("expected HandshakeResponse"),
        };
        assert!(bob.has_session(&alice_pubkey));

        // Alice processes the handshake response
        let result = alice.process_inbound(&bob_pubkey, &hs_resp).unwrap();
        assert!(matches!(result, InboundResult::HandshakeComplete));
        assert!(alice.has_session(&bob_pubkey));
        assert!(!alice.has_pending_handshake(&bob_pubkey));

        // Alice encrypts a message for Bob
        let plaintext = b"hello from alice";
        let encrypted = alice.encrypt(&bob_pubkey, plaintext).unwrap().unwrap();
        assert_eq!(encrypted[0], prefix::ENCRYPTED);

        // Bob decrypts it
        let result = bob.process_inbound(&alice_pubkey, &encrypted).unwrap();
        match result {
            InboundResult::Payload(data) => assert_eq!(data, plaintext),
            _ => panic!("expected Payload"),
        }

        // Bob encrypts a message for Alice
        let plaintext2 = b"hello from bob";
        let encrypted2 = bob.encrypt(&alice_pubkey, plaintext2).unwrap().unwrap();

        // Alice decrypts it
        let result = alice.process_inbound(&bob_pubkey, &encrypted2).unwrap();
        match result {
            InboundResult::Payload(data) => assert_eq!(data, plaintext2),
            _ => panic!("expected Payload"),
        }
    }

    #[test]
    fn plaintext_framing_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let peer_key = SigningKey::generate(&mut OsRng);
        let peer_pubkey = peer_key.verifying_key().to_bytes();

        let mut mgr = NoiseSessionManager::new(&signing_key);
        let payload = b"test payload";
        let framed = NoiseSessionManager::frame_plaintext(payload);
        assert_eq!(framed[0], prefix::PLAINTEXT);

        let result = mgr.process_inbound(&peer_pubkey, &framed).unwrap();
        match result {
            InboundResult::Payload(data) => assert_eq!(data, payload),
            _ => panic!("expected Payload"),
        }
    }

    #[test]
    fn encrypt_without_session_returns_none() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let peer_key = SigningKey::generate(&mut OsRng);
        let peer_pubkey = peer_key.verifying_key().to_bytes();

        let mut mgr = NoiseSessionManager::new(&signing_key);
        let result = mgr.encrypt(&peer_pubkey, b"test").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn multiple_messages_after_handshake() {
        let alice_ed = SigningKey::generate(&mut OsRng);
        let bob_ed = SigningKey::generate(&mut OsRng);
        let alice_pubkey = alice_ed.verifying_key().to_bytes();
        let bob_pubkey = bob_ed.verifying_key().to_bytes();

        let mut alice = NoiseSessionManager::new(&alice_ed);
        let mut bob = NoiseSessionManager::new(&bob_ed);

        // Complete handshake
        let hs_init = alice.initiate_handshake(&bob_pubkey).unwrap();
        let result = bob.process_inbound(&alice_pubkey, &hs_init).unwrap();
        let hs_resp = match result {
            InboundResult::HandshakeResponse { data, .. } => data,
            _ => panic!("expected HandshakeResponse"),
        };
        alice.process_inbound(&bob_pubkey, &hs_resp).unwrap();

        // Send 10 messages each direction
        for i in 0..10 {
            let msg = format!("alice msg {i}");
            let enc = alice.encrypt(&bob_pubkey, msg.as_bytes()).unwrap().unwrap();
            let result = bob.process_inbound(&alice_pubkey, &enc).unwrap();
            match result {
                InboundResult::Payload(data) => assert_eq!(data, msg.as_bytes()),
                _ => panic!("expected Payload"),
            }

            let msg = format!("bob msg {i}");
            let enc = bob.encrypt(&alice_pubkey, msg.as_bytes()).unwrap().unwrap();
            let result = alice.process_inbound(&bob_pubkey, &enc).unwrap();
            match result {
                InboundResult::Payload(data) => assert_eq!(data, msg.as_bytes()),
                _ => panic!("expected Payload"),
            }
        }
    }

    #[test]
    fn ed25519_pub_to_x25519_rejects_invalid_key() {
        // [0x02; 32] does not decompress to a valid Ed25519 curve point
        let bad_pubkey: Pubkey = [0x02; 32];
        let result = ed25519_pub_to_x25519(&bad_pubkey);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NoiseError::InvalidPeerKey(_)));
    }

    #[test]
    fn test_cleanup_expired_handshakes_removes_old() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let peer_key = SigningKey::generate(&mut OsRng);
        let peer_pubkey = peer_key.verifying_key().to_bytes();

        let mut mgr = NoiseSessionManager::new(&signing_key);

        // Manually insert an expired handshake
        let hs = create_dummy_handshake_state(&signing_key, &peer_pubkey);
        let old_timestamp = Instant::now() - Duration::from_secs(31);
        mgr.pending_handshakes
            .insert(peer_pubkey, (hs, old_timestamp));

        assert!(mgr.has_pending_handshake(&peer_pubkey));

        // Cleanup should remove expired handshake
        let removed = mgr.cleanup_expired_handshakes();
        assert_eq!(removed, 1, "Should remove 1 expired handshake");
        assert!(
            !mgr.has_pending_handshake(&peer_pubkey),
            "Expired handshake should be removed"
        );
    }

    #[test]
    fn test_initiate_handshake_calls_cleanup() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let peer1_key = SigningKey::generate(&mut OsRng);
        let peer1_pubkey = peer1_key.verifying_key().to_bytes();
        let peer2_key = SigningKey::generate(&mut OsRng);
        let peer2_pubkey = peer2_key.verifying_key().to_bytes();

        let mut mgr = NoiseSessionManager::new(&signing_key);

        // Insert expired handshake for peer1
        let hs1 = create_dummy_handshake_state(&signing_key, &peer1_pubkey);
        let old_timestamp = Instant::now() - Duration::from_secs(31);
        mgr.pending_handshakes
            .insert(peer1_pubkey, (hs1, old_timestamp));

        // Initiate new handshake with peer2 - should trigger cleanup
        let _ = mgr.initiate_handshake(&peer2_pubkey);

        // peer1's expired handshake should be cleaned up
        assert!(
            !mgr.has_pending_handshake(&peer1_pubkey),
            "Expired handshake should be cleaned"
        );
        assert!(
            mgr.has_pending_handshake(&peer2_pubkey),
            "New handshake should exist"
        );
    }

    /// Simulates the exact relay.rs flow for a first message:
    /// 1. Initiator has no session → initiate_handshake → queue payload
    /// 2. Responder process_inbound(hs_init) → creates session + handshake response
    /// 3. Initiator process_inbound(hs_resp) → HandshakeComplete
    /// 4. Initiator encrypts queued payload
    /// 5. Responder process_inbound(encrypted) → should decrypt
    #[test]
    fn relay_flow_first_message() {
        let alice_ed = SigningKey::generate(&mut OsRng);
        let bob_ed = SigningKey::generate(&mut OsRng);
        let alice_pubkey = alice_ed.verifying_key().to_bytes();
        let bob_pubkey = bob_ed.verifying_key().to_bytes();

        let mut alice = NoiseSessionManager::new(&alice_ed);
        let mut bob = NoiseSessionManager::new(&bob_ed);

        let first_msg = b"hello from alice";

        // Step 1: No session, encrypt returns None
        assert!(alice.encrypt(&bob_pubkey, first_msg).unwrap().is_none());

        // Step 2: Initiate handshake (queued payload handled by relay, not noise)
        let hs_init = alice.initiate_handshake(&bob_pubkey).unwrap();
        assert!(alice.has_pending_handshake(&bob_pubkey));

        // Step 3: Bob processes handshake init
        let hs_resp = match bob.process_inbound(&alice_pubkey, &hs_init).unwrap() {
            InboundResult::HandshakeResponse { to, data } => {
                assert_eq!(to, alice_pubkey);
                data
            }
            _ => panic!("expected HandshakeResponse"),
        };
        assert!(
            bob.has_session(&alice_pubkey),
            "bob should have session after processing init"
        );

        // Step 4: Alice processes handshake response → HandshakeComplete
        match alice.process_inbound(&bob_pubkey, &hs_resp).unwrap() {
            InboundResult::HandshakeComplete => {}
            _ => panic!("expected HandshakeComplete"),
        }
        assert!(
            alice.has_session(&bob_pubkey),
            "alice should have session after handshake"
        );

        // Step 5: Alice encrypts the queued first message (relay flush)
        let encrypted = alice
            .encrypt(&bob_pubkey, first_msg)
            .unwrap()
            .expect("should encrypt with established session");
        assert_eq!(encrypted[0], prefix::ENCRYPTED);

        // Step 6: Bob decrypts the first message
        match bob.process_inbound(&alice_pubkey, &encrypted).unwrap() {
            InboundResult::Payload(data) => {
                assert_eq!(data, first_msg, "first message should decrypt correctly");
            }
            _ => panic!("expected Payload"),
        }
    }

    /// Test that the concurrent handshake tiebreaker resolves collisions.
    /// When both peers initiate handshakes simultaneously, the peer with the
    /// lower X25519 public key wins as initiator. The other peer yields and
    /// becomes responder. The result is a single compatible session.
    #[test]
    fn concurrent_handshake_collision() {
        let alice_ed = SigningKey::generate(&mut OsRng);
        let bob_ed = SigningKey::generate(&mut OsRng);
        let alice_pubkey = alice_ed.verifying_key().to_bytes();
        let bob_pubkey = bob_ed.verifying_key().to_bytes();
        let mut alice = NoiseSessionManager::new(&alice_ed);
        let mut bob = NoiseSessionManager::new(&bob_ed);
        // Determine who has the lower X25519 key (will be the initiator winner)
        let bob_x25519 = ed25519_pub_to_x25519(&bob_pubkey).unwrap();
        let alice_is_initiator = alice.local_keypair.public < bob_x25519.to_vec();
        // Both sides initiate handshakes simultaneously
        let hs_init_alice = alice.initiate_handshake(&bob_pubkey).unwrap();
        let hs_init_bob = bob.initiate_handshake(&alice_pubkey).unwrap();
        // The winner's init should be rejected by the loser (loser keeps its pending handshake).
        // The loser's init should be accepted by the winner (winner yields and becomes responder).
        if alice_is_initiator {
            // Alice wins as initiator:
            // Alice receives Bob's init → rejects (her key is lower, she keeps her pending HS)
            let alice_result = alice.process_inbound(&bob_pubkey, &hs_init_bob);
            assert!(
                alice_result.is_err(),
                "initiator winner should reject incoming init"
            );
            assert!(
                alice.has_pending_handshake(&bob_pubkey),
                "winner keeps pending handshake"
            );

            // Bob receives Alice's init → yields, becomes responder
            let bob_resp = match bob.process_inbound(&alice_pubkey, &hs_init_alice).unwrap() {
                InboundResult::HandshakeResponse { data, .. } => data,
                _ => panic!("loser should yield and become responder"),
            };
            assert!(bob.has_session(&alice_pubkey), "bob has responder session");
            assert!(
                !bob.has_pending_handshake(&alice_pubkey),
                "bob dropped pending HS"
            );

            // Alice completes as initiator
            match alice.process_inbound(&bob_pubkey, &bob_resp).unwrap() {
                InboundResult::HandshakeComplete => {}
                _ => panic!("expected HandshakeComplete"),
            }
            assert!(alice.has_session(&bob_pubkey));
        } else {
            // Bob wins as initiator:
            // Bob receives Alice's init → rejects (his key is lower)
            let bob_result = bob.process_inbound(&alice_pubkey, &hs_init_alice);
            assert!(
                bob_result.is_err(),
                "initiator winner should reject incoming init"
            );
            assert!(
                bob.has_pending_handshake(&alice_pubkey),
                "winner keeps pending handshake"
            );

            // Alice receives Bob's init → yields, becomes responder
            let alice_resp = match alice.process_inbound(&bob_pubkey, &hs_init_bob).unwrap() {
                InboundResult::HandshakeResponse { data, .. } => data,
                _ => panic!("loser should yield and become responder"),
            };
            assert!(
                alice.has_session(&bob_pubkey),
                "alice has responder session"
            );
            assert!(
                !alice.has_pending_handshake(&bob_pubkey),
                "alice dropped pending HS"
            );

            // Bob completes as initiator
            match bob.process_inbound(&alice_pubkey, &alice_resp).unwrap() {
                InboundResult::HandshakeComplete => {}
                _ => panic!("expected HandshakeComplete"),
            }
            assert!(bob.has_session(&alice_pubkey));
        }

        // Both sides now have compatible sessions — verify encryption works
        let plaintext = b"hello after collision";
        let enc = alice.encrypt(&bob_pubkey, plaintext).unwrap().unwrap();
        match bob.process_inbound(&alice_pubkey, &enc).unwrap() {
            InboundResult::Payload(data) => assert_eq!(data, plaintext),
            _ => panic!("expected Payload"),
        }

        let plaintext2 = b"reply after collision";
        let enc2 = bob.encrypt(&alice_pubkey, plaintext2).unwrap().unwrap();
        match alice.process_inbound(&bob_pubkey, &enc2).unwrap() {
            InboundResult::Payload(data) => assert_eq!(data, plaintext2),
            _ => panic!("expected Payload"),
        }
    }

    // Helper function to create a dummy handshake state for testing
    fn create_dummy_handshake_state(
        signing_key: &SigningKey,
        peer_pubkey: &Pubkey,
    ) -> snow::HandshakeState {
        use snow::{Builder, Keypair};

        let private = signing_key.to_scalar_bytes().to_vec();
        let public = signing_key
            .verifying_key()
            .to_montgomery()
            .to_bytes()
            .to_vec();
        let local_keypair = Keypair { private, public };

        let peer_vk = ed25519_dalek::VerifyingKey::from_bytes(peer_pubkey).unwrap();
        let x25519_remote = peer_vk.to_montgomery().to_bytes();

        static NOISE_PARAMS: std::sync::OnceLock<snow::params::NoiseParams> =
            std::sync::OnceLock::new();
        let params =
            NOISE_PARAMS.get_or_init(|| "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());

        Builder::new(params.clone())
            .local_private_key(&local_keypair.private)
            .remote_public_key(&x25519_remote)
            .build_initiator()
            .unwrap()
    }
}
