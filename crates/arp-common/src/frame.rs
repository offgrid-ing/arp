//! ARP binary frame serialization and parsing.
//!
//! Each frame is a type-length-value (TLV) binary message sent over WebSocket.
//! The first byte identifies the frame type; remaining bytes carry the payload.

use crate::types::Pubkey;
use thiserror::Error;

/// ROUTE frame type: client → relay, requests message delivery.
pub const TYPE_ROUTE: u8 = 0x01;
/// DELIVER frame type: relay → client, delivers a routed message.
pub const TYPE_DELIVER: u8 = 0x02;
/// STATUS frame type: relay → client, delivery status notification.
pub const TYPE_STATUS: u8 = 0x03;
/// PING frame type: application-level keepalive request.
pub const TYPE_PING: u8 = 0x04;
/// PONG frame type: application-level keepalive response.
pub const TYPE_PONG: u8 = 0x05;
/// CHALLENGE frame type: relay → client, admission challenge.
pub const TYPE_CHALLENGE: u8 = 0xC0;
/// RESPONSE frame type: client → relay, admission response with signature.
pub const TYPE_RESPONSE: u8 = 0xC1;
/// ADMITTED frame type: relay → client, admission granted.
pub const TYPE_ADMITTED: u8 = 0xC2;
/// REJECTED frame type: relay → client, admission denied.
pub const TYPE_REJECTED: u8 = 0xC3;

/// Maximum payload size in bytes (64 KiB - 1).
pub const MAX_PAYLOAD: usize = 65_535;

/// Maximum total frame size (type byte + pubkey + max payload).
pub const MAX_FRAME_SIZE: usize = 1 + 32 + MAX_PAYLOAD; // 65,568 bytes

/// A parsed ARP protocol frame.
///
/// Variants map 1:1 to wire frame types defined by `TYPE_*` constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Admission challenge from relay to client.
    Challenge {
        /// Random 32-byte challenge token.
        challenge: [u8; 32],
        /// Relay's public key.
        server_pubkey: Pubkey,
        /// Required proof-of-work difficulty (leading zero bits).
        difficulty: u8,
    },
    /// Admission response from client to relay.
    Response {
        /// Client's public key.
        pubkey: Pubkey,
        /// Unix timestamp of the response.
        timestamp: u64,
        /// Ed25519 signature over the challenge and timestamp.
        signature: [u8; 64],
        /// Optional proof-of-work nonce.
        pow_nonce: Option<[u8; 8]>,
    },
    /// Admission granted by relay.
    Admitted,
    /// Admission denied by relay.
    Rejected {
        /// Rejection reason code.
        reason: u8,
    },
    /// Client-to-relay request to deliver a message.
    Route {
        /// Destination public key.
        dest: Pubkey,
        /// Message payload.
        payload: Vec<u8>,
    },
    /// Relay-to-client delivery of a routed message.
    Deliver {
        /// Sender's public key.
        src: Pubkey,
        /// Message payload.
        payload: Vec<u8>,
    },
    /// Relay-to-client delivery status notification.
    Status {
        /// Public key the status refers to.
        ref_pubkey: Pubkey,
        /// Status code.
        code: u8,
    },
    /// Application-level keepalive request.
    Ping {
        /// Keepalive payload.
        payload: Vec<u8>,
    },
    /// Application-level keepalive response.
    Pong {
        /// Keepalive payload.
        payload: Vec<u8>,
    },
}

/// Errors that can occur during frame parsing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    /// The input byte slice was empty.
    #[error("frame is empty")]
    Empty,
    /// The frame is too short for the declared type.
    #[error("frame too short")]
    TooShort {
        /// Minimum expected byte count.
        expected: usize,
        /// Actual byte count received.
        actual: usize,
    },
    /// The frame payload exceeds the maximum allowed size.
    #[error("payload too large: max {max}, got {actual}")]
    PayloadTooLarge {
        /// Maximum allowed payload size.
        max: usize,
        /// Actual payload size received.
        actual: usize,
    },
    /// The first byte does not match any known frame type.
    #[error("unknown frame type")]
    UnknownType(u8),
}

/// Safely convert a byte slice to a fixed-size array.
/// Returns `FrameError::TooShort` if the slice is the wrong length.
fn try_into_array<const N: usize>(data: &[u8]) -> Result<[u8; N], FrameError> {
    data.try_into().map_err(|_| FrameError::TooShort {
        expected: N,
        actual: data.len(),
    })
}

impl Frame {
    /// Creates a new `Challenge` frame.
    #[must_use]
    pub const fn challenge(challenge: &[u8; 32], server_pubkey: &Pubkey, difficulty: u8) -> Self {
        Self::Challenge {
            challenge: *challenge,
            server_pubkey: *server_pubkey,
            difficulty,
        }
    }

    /// Creates a new `Response` frame.
    #[must_use]
    pub const fn response(pubkey: &Pubkey, timestamp: u64, signature: &[u8; 64]) -> Self {
        Self::Response {
            pubkey: *pubkey,
            timestamp,
            signature: *signature,
            pow_nonce: None,
        }
    }

    /// Creates a new `Response` frame with a proof-of-work nonce.
    #[must_use]
    pub const fn response_with_pow(
        pubkey: &Pubkey,
        timestamp: u64,
        signature: &[u8; 64],
        nonce: [u8; 8],
    ) -> Self {
        Self::Response {
            pubkey: *pubkey,
            timestamp,
            signature: *signature,
            pow_nonce: Some(nonce),
        }
    }

    /// Creates an `Admitted` frame.
    #[must_use]
    pub const fn admitted() -> Self {
        Self::Admitted
    }

    /// Creates a `Rejected` frame with the given reason code.
    #[must_use]
    pub const fn rejected(reason: u8) -> Self {
        Self::Rejected { reason }
    }

    /// Creates a `Route` frame targeting the given destination.
    #[must_use]
    pub fn route(dest: &Pubkey, payload: &[u8]) -> Self {
        Self::Route {
            dest: *dest,
            payload: payload.to_vec(),
        }
    }

    /// Creates a `Deliver` frame from the given source.
    #[must_use]
    pub fn deliver(src: &Pubkey, payload: &[u8]) -> Self {
        Self::Deliver {
            src: *src,
            payload: payload.to_vec(),
        }
    }

    /// Creates a `Status` frame referencing the given public key.
    #[must_use]
    pub const fn status(ref_pubkey: &Pubkey, code: u8) -> Self {
        Self::Status {
            ref_pubkey: *ref_pubkey,
            code,
        }
    }

    /// Creates a `Ping` frame.
    #[must_use]
    pub fn ping(payload: &[u8]) -> Self {
        Self::Ping {
            payload: payload.to_vec(),
        }
    }

    /// Creates a `Pong` frame.
    #[must_use]
    pub fn pong(payload: &[u8]) -> Self {
        Self::Pong {
            payload: payload.to_vec(),
        }
    }

    /// Serializes this frame into a byte vector for WebSocket transmission.
    ///
    /// # Examples
    ///
    /// ```
    /// use arp_common::frame::{Frame, TYPE_ROUTE};
    /// let frame = Frame::route(&[0u8; 32], b"hello");
    /// let bytes = frame.serialize();
    /// assert_eq!(bytes[0], TYPE_ROUTE);
    /// ```
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Challenge {
                challenge,
                server_pubkey,
                difficulty,
            } => {
                let mut v = Vec::with_capacity(66);
                v.push(TYPE_CHALLENGE);
                v.extend_from_slice(challenge);
                v.extend_from_slice(server_pubkey);
                v.push(*difficulty);
                v
            }
            Self::Response {
                pubkey,
                timestamp,
                signature,
                pow_nonce,
            } => {
                let cap = if pow_nonce.is_some() { 113 } else { 105 };
                let mut v = Vec::with_capacity(cap);
                v.push(TYPE_RESPONSE);
                v.extend_from_slice(pubkey);
                v.extend_from_slice(&timestamp.to_be_bytes());
                v.extend_from_slice(signature);
                if let Some(nonce) = pow_nonce {
                    v.extend_from_slice(nonce);
                }
                v
            }
            Self::Admitted => vec![TYPE_ADMITTED],
            Self::Rejected { reason } => vec![TYPE_REJECTED, *reason],
            Self::Route { dest, payload } => {
                let mut v = Vec::with_capacity(33 + payload.len());
                v.push(TYPE_ROUTE);
                v.extend_from_slice(dest);
                v.extend_from_slice(payload);
                v
            }
            Self::Deliver { src, payload } => {
                let mut v = Vec::with_capacity(33 + payload.len());
                v.push(TYPE_DELIVER);
                v.extend_from_slice(src);
                v.extend_from_slice(payload);
                v
            }
            Self::Status { ref_pubkey, code } => {
                let mut v = Vec::with_capacity(34);
                v.push(TYPE_STATUS);
                v.extend_from_slice(ref_pubkey);
                v.push(*code);
                v
            }
            Self::Ping { payload } => {
                let mut v = Vec::with_capacity(1 + payload.len());
                v.push(TYPE_PING);
                v.extend_from_slice(payload);
                v
            }
            Self::Pong { payload } => {
                let mut v = Vec::with_capacity(1 + payload.len());
                v.push(TYPE_PONG);
                v.extend_from_slice(payload);
                v
            }
        }
    }

    /// Serializes a Deliver frame directly from raw parts.
    ///
    /// This avoids the intermediate `Frame::Deliver` allocation when
    /// the source pubkey and payload are already available as slices.
    /// Preferred on the relay hot path where payloads can be up to 64 KiB.
    #[must_use]
    pub fn serialize_deliver(src: &Pubkey, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(33 + payload.len());
        v.push(TYPE_DELIVER);
        v.extend_from_slice(src);
        v.extend_from_slice(payload);
        v
    }

    /// Parses a byte slice into a typed `Frame`.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] if the data is empty, too short for the
    /// declared type, or has an unrecognized type byte.
    ///
    /// # Examples
    ///
    /// ```
    /// use arp_common::frame::Frame;
    /// let frame = Frame::route(&[0u8; 32], b"hello");
    /// let bytes = frame.serialize();
    /// let parsed = Frame::parse(&bytes).unwrap();
    /// assert_eq!(frame, parsed);
    /// ```
    #[allow(clippy::too_many_lines)]
    pub fn parse(data: &[u8]) -> Result<Self, FrameError> {
        if data.is_empty() {
            return Err(FrameError::Empty);
        }
        match data[0] {
            TYPE_CHALLENGE => {
                if data.len() < 66 {
                    return Err(FrameError::TooShort {
                        expected: 66,
                        actual: data.len(),
                    });
                }
                Ok(Self::Challenge {
                    challenge: try_into_array(&data[1..33])?,
                    server_pubkey: try_into_array(&data[33..65])?,
                    difficulty: data[65],
                })
            }
            TYPE_RESPONSE => {
                if data.len() < 105 {
                    return Err(FrameError::TooShort {
                        expected: 105,
                        actual: data.len(),
                    });
                }
                let pow_nonce = if data.len() >= 113 {
                    Some(try_into_array(&data[105..113])?)
                } else {
                    None
                };
                Ok(Self::Response {
                    pubkey: try_into_array(&data[1..33])?,
                    timestamp: u64::from_be_bytes(try_into_array(&data[33..41])?),
                    signature: try_into_array(&data[41..105])?,
                    pow_nonce,
                })
            }
            TYPE_ADMITTED => Ok(Self::Admitted),
            TYPE_REJECTED => {
                if data.len() < 2 {
                    return Err(FrameError::TooShort {
                        expected: 2,
                        actual: data.len(),
                    });
                }
                Ok(Self::Rejected { reason: data[1] })
            }
            TYPE_ROUTE => {
                if data.len() < 33 {
                    return Err(FrameError::TooShort {
                        expected: 33,
                        actual: data.len(),
                    });
                }
                let payload_len = data.len() - 33;
                if payload_len > MAX_PAYLOAD {
                    return Err(FrameError::PayloadTooLarge {
                        max: MAX_PAYLOAD,
                        actual: payload_len,
                    });
                }
                Ok(Self::Route {
                    dest: try_into_array(&data[1..33])?,
                    payload: data[33..].to_vec(),
                })
            }
            TYPE_DELIVER => {
                if data.len() < 33 {
                    return Err(FrameError::TooShort {
                        expected: 33,
                        actual: data.len(),
                    });
                }
                let payload_len = data.len() - 33;
                if payload_len > MAX_PAYLOAD {
                    return Err(FrameError::PayloadTooLarge {
                        max: MAX_PAYLOAD,
                        actual: payload_len,
                    });
                }
                Ok(Self::Deliver {
                    src: try_into_array(&data[1..33])?,
                    payload: data[33..].to_vec(),
                })
            }
            TYPE_STATUS => {
                if data.len() < 34 {
                    return Err(FrameError::TooShort {
                        expected: 34,
                        actual: data.len(),
                    });
                }
                Ok(Self::Status {
                    ref_pubkey: try_into_array(&data[1..33])?,
                    code: data[33],
                })
            }
            TYPE_PING => {
                let payload_len = data.len().saturating_sub(1);
                if payload_len > MAX_PAYLOAD {
                    return Err(FrameError::PayloadTooLarge {
                        max: MAX_PAYLOAD,
                        actual: payload_len,
                    });
                }
                Ok(Self::Ping {
                    payload: data[1..].to_vec(),
                })
            }
            TYPE_PONG => {
                let payload_len = data.len().saturating_sub(1);
                if payload_len > MAX_PAYLOAD {
                    return Err(FrameError::PayloadTooLarge {
                        max: MAX_PAYLOAD,
                        actual: payload_len,
                    });
                }
                Ok(Self::Pong {
                    payload: data[1..].to_vec(),
                })
            }
            t => Err(FrameError::UnknownType(t)),
        }
    }

    /// Returns the wire type byte for this frame.
    ///
    /// # Examples
    ///
    /// ```
    /// use arp_common::frame::{Frame, TYPE_ROUTE};
    /// let frame = Frame::route(&[0u8; 32], b"data");
    /// assert_eq!(frame.frame_type(), TYPE_ROUTE);
    /// ```
    #[must_use]
    pub const fn frame_type(&self) -> u8 {
        match self {
            Self::Challenge { .. } => TYPE_CHALLENGE,
            Self::Response { .. } => TYPE_RESPONSE,
            Self::Admitted => TYPE_ADMITTED,
            Self::Rejected { .. } => TYPE_REJECTED,
            Self::Route { .. } => TYPE_ROUTE,
            Self::Deliver { .. } => TYPE_DELIVER,
            Self::Status { .. } => TYPE_STATUS,
            Self::Ping { .. } => TYPE_PING,
            Self::Pong { .. } => TYPE_PONG,
        }
    }

    /// Returns the challenge bytes if this is a `Challenge` frame.
    #[must_use]
    pub const fn challenge_bytes(&self) -> Option<&[u8; 32]> {
        if let Self::Challenge { challenge, .. } = self {
            Some(challenge)
        } else {
            None
        }
    }

    /// Returns the server public key if this is a `Challenge` frame.
    #[must_use]
    pub const fn server_pubkey(&self) -> Option<&Pubkey> {
        if let Self::Challenge { server_pubkey, .. } = self {
            Some(server_pubkey)
        } else {
            None
        }
    }

    /// Returns the difficulty if this is a `Challenge` frame.
    #[must_use]
    pub const fn difficulty(&self) -> Option<u8> {
        if let Self::Challenge { difficulty, .. } = self {
            Some(*difficulty)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize_route_frame() {
        let dest = [0x01u8; 32];
        let payload = b"hello";
        let frame = Frame::route(&dest, payload);
        let bytes = frame.serialize();

        assert_eq!(bytes[0], TYPE_ROUTE);
        assert_eq!(&bytes[1..33], &dest);
        assert_eq!(&bytes[33..], payload);
    }

    #[test]
    fn reject_frame_too_short() {
        let result = Frame::parse(&[TYPE_ROUTE]);
        assert!(matches!(result, Err(FrameError::TooShort { .. })));
    }

    #[test]
    fn challenge_round_trip() {
        let challenge = [0xABu8; 32];
        let server_pk = [0xCDu8; 32];
        let frame = Frame::challenge(&challenge, &server_pk, 0x00);
        let bytes = frame.serialize();
        let parsed = Frame::parse(&bytes).unwrap();

        assert_eq!(parsed.frame_type(), TYPE_CHALLENGE);
        assert_eq!(parsed.challenge_bytes(), Some(&challenge));
        assert_eq!(parsed.server_pubkey(), Some(&server_pk));
        assert_eq!(parsed.difficulty(), Some(0x00));
    }

    #[test]
    fn deliver_round_trip() {
        let src = [0x02u8; 32];
        let payload = b"agent message payload";
        let frame = Frame::deliver(&src, payload);
        let bytes = frame.serialize();
        let parsed = Frame::parse(&bytes).unwrap();

        assert!(matches!(parsed, Frame::Deliver { .. }));
        if let Frame::Deliver {
            src: parsed_src,
            payload: parsed_payload,
        } = parsed
        {
            assert_eq!(parsed_src, src);
            assert_eq!(parsed_payload, payload);
        }
    }

    #[test]
    fn status_round_trip() {
        let ref_key = [0x03u8; 32];
        let frame = Frame::status(&ref_key, 0x01).serialize();
        let parsed = Frame::parse(&frame).unwrap();
        assert!(matches!(parsed, Frame::Status { code: 0x01, .. }));
    }

    #[test]
    fn empty_frame_is_error() {
        assert_eq!(Frame::parse(&[]), Err(FrameError::Empty));
    }

    #[test]
    fn unknown_type_is_error() {
        assert!(matches!(
            Frame::parse(&[0xFF]),
            Err(FrameError::UnknownType(0xFF))
        ));
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn response_round_trip() {
        let pk = [0x01u8; 32];
        let sig = [0x02u8; 64];
        let frame = Frame::response(&pk, 1234567890, &sig);
        let bytes = frame.serialize();
        let parsed = Frame::parse(&bytes).unwrap();
        assert!(matches!(
            parsed,
            Frame::Response {
                timestamp: 1234567890,
                ..
            }
        ));
    }

    #[test]
    fn admitted_round_trip() {
        let bytes = Frame::admitted().serialize();
        assert_eq!(Frame::parse(&bytes).unwrap(), Frame::Admitted);
    }

    #[test]
    fn rejected_round_trip() {
        let bytes = Frame::rejected(0x02).serialize();
        let parsed = Frame::parse(&bytes).unwrap();
        assert!(matches!(parsed, Frame::Rejected { reason: 0x02 }));
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn ping_pong_round_trip() {
        let ping = Frame::ping(b"keepalive").serialize();
        let parsed = Frame::parse(&ping).unwrap();
        assert!(matches!(parsed, Frame::Ping { .. }));

        let pong = Frame::pong(b"keepalive").serialize();
        let parsed = Frame::parse(&pong).unwrap();
        assert!(matches!(parsed, Frame::Pong { .. }));
    }

    #[test]
    fn route_empty_payload() {
        let dest = [0xFFu8; 32];
        let frame = Frame::route(&dest, &[]);
        let bytes = frame.serialize();
        let parsed = Frame::parse(&bytes).unwrap();
        if let Frame::Route { payload, .. } = parsed {
            assert!(payload.is_empty());
        } else {
            panic!("expected Route frame");
        }
    }

    #[test]
    fn all_frame_types_have_correct_type_byte() {
        assert_eq!(
            Frame::challenge(&[0; 32], &[0; 32], 0).frame_type(),
            TYPE_CHALLENGE
        );
        assert_eq!(
            Frame::response(&[0; 32], 0, &[0; 64]).frame_type(),
            TYPE_RESPONSE
        );
        assert_eq!(Frame::admitted().frame_type(), TYPE_ADMITTED);
        assert_eq!(Frame::rejected(0).frame_type(), TYPE_REJECTED);
        assert_eq!(Frame::route(&[0; 32], &[]).frame_type(), TYPE_ROUTE);
        assert_eq!(Frame::deliver(&[0; 32], &[]).frame_type(), TYPE_DELIVER);
        assert_eq!(Frame::status(&[0; 32], 0).frame_type(), TYPE_STATUS);
        assert_eq!(Frame::ping(&[]).frame_type(), TYPE_PING);
        assert_eq!(Frame::pong(&[]).frame_type(), TYPE_PONG);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_pubkey() -> impl Strategy<Value = [u8; 32]> {
        prop::array::uniform32(any::<u8>())
    }

    fn arb_signature() -> impl Strategy<Value = [u8; 64]> {
        prop::collection::vec(any::<u8>(), 64).prop_map(|v| {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&v);
            arr
        })
    }

    fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..1024)
    }

    proptest! {
        #[test]
        fn route_serialize_parse_roundtrip(dest in arb_pubkey(), payload in arb_payload()) {
            let frame = Frame::route(&dest, &payload);
            let bytes = frame.serialize();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(frame, parsed);
        }

        #[test]
        fn deliver_serialize_parse_roundtrip(src in arb_pubkey(), payload in arb_payload()) {
            let frame = Frame::deliver(&src, &payload);
            let bytes = frame.serialize();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(frame, parsed);
        }

        #[test]
        fn status_serialize_parse_roundtrip(pk in arb_pubkey(), code in any::<u8>()) {
            let frame = Frame::status(&pk, code);
            let bytes = frame.serialize();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(frame, parsed);
        }

        #[test]
        fn challenge_serialize_parse_roundtrip(
            challenge in arb_pubkey(),
            server_pk in arb_pubkey(),
            difficulty in any::<u8>()
        ) {
            let frame = Frame::challenge(&challenge, &server_pk, difficulty);
            let bytes = frame.serialize();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(frame, parsed);
        }

        #[test]
        fn response_serialize_parse_roundtrip(
            pk in arb_pubkey(),
            ts in any::<u64>(),
            sig in arb_signature()
        ) {
            let frame = Frame::response(&pk, ts, &sig);
            let bytes = frame.serialize();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(frame, parsed);
        }

        #[test]
        fn ping_serialize_parse_roundtrip(payload in arb_payload()) {
            let frame = Frame::ping(&payload);
            let bytes = frame.serialize();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(frame, parsed);
        }

        #[test]
        fn pong_serialize_parse_roundtrip(payload in arb_payload()) {
            let frame = Frame::pong(&payload);
            let bytes = frame.serialize();
            let parsed = Frame::parse(&bytes).unwrap();
            prop_assert_eq!(frame, parsed);
        }

        #[test]
        fn first_byte_is_always_frame_type(
            dest in arb_pubkey(),
            payload in arb_payload()
        ) {
            let route_bytes = Frame::route(&dest, &payload).serialize();
            prop_assert_eq!(route_bytes[0], TYPE_ROUTE);

            let deliver_bytes = Frame::deliver(&dest, &payload).serialize();
            prop_assert_eq!(deliver_bytes[0], TYPE_DELIVER);
        }
    }
}
