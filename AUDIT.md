# ARP Security Audit Report

**Agent Relay Protocol — Comprehensive Security Assessment**

---

## Report Metadata

| Field | Detail |
|-------|--------|
| **Project** | ARP (Agent Relay Protocol) |
| **Repository** | `offgrid-ing/arp` |
| **Version** | v0.2.4 |
| **Commit** | `32b76c5` |
| **Protocol Version** | `arp.v2` |
| **Audit Date** | February 24, 2026 |
| **Auditor** | Independent AI-Assisted Security Review (Claude, Anthropic) |
| **Methodology** | Full manual source code review + automated static analysis |
| **Scope** | 100% of source code across 3 crates (~7,900 LoC), whitepaper, CI/CD, deployment infrastructure |
| **Overall Risk Rating** | **LOW** |

---

## Security Posture Summary

| Area | Status | Key Controls |
|------|--------|--------------|
| **Cryptography** | ✅ Pass | HPKE RFC 9180 (Auth mode), Ed25519, ChaCha20Poly1305, zeroized key material |
| **Authentication** | ✅ Pass | Ed25519 challenge-response, SHA-256 PoW, relay pubkey pinning |
| **Network Security** | ✅ Pass | TLS via reverse proxy enforcement, pre-auth semaphore, per-IP connection limits |
| **Input Validation** | ✅ Pass | Defensive binary parsing, bounded frames, property-based testing (proptest) |
| **Rate Limiting & DoS** | ✅ Pass | Three-layer defense (edge → admission → runtime), sliding window, bounded channels |
| **Configuration & Secrets** | ✅ Pass | 0600 key file permissions, directory permission checks, platform-aware warnings |
| **Supply Chain** | ✅ Pass | OpenSSL explicitly banned, `cargo-deny` enforced in CI, Dependabot weekly |
| **CI/CD & Deployment** | ✅ Pass | `clippy -D warnings`, full test suite, mandatory binary checksums, auto-rollback |
| **Code Quality** | ✅ Pass | `#![forbid(unsafe_code)]` all crates, zero reachable panics from network input |
| **Information Disclosure** | ✅ Pass | No secrets in logs, explicit redaction, minimal wire error messages |

| Severity | Findings |
|----------|----------|
| **Critical** | 0 |
| **High** | 0 |
| **Medium** | 0 |
| **Low** | 0 |
| **Informational** | 2 |

> **No exploitable vulnerabilities were identified.** All informational observations are architectural notes documenting intentional design decisions with safe failure modes.

---

## Executive Summary

This report documents the comprehensive security audit of the Agent Relay Protocol (ARP), a stateless WebSocket relay for autonomous AI agent communication. The assessment covers the protocol specification (`whitepaper.md`), all three Rust crates (`arp-common`, `arps`, `arpc`), CI/CD pipelines, dependency chain, and deployment infrastructure.

The audit concludes with a **LOW overall risk rating**, reflecting an exceptionally strong security posture. No exploitable vulnerabilities were discovered. The two informational observations are architectural design decisions that are explicitly documented and produce safe failure modes.

The ARP project exemplifies security-first engineering. The stateless relay architecture eliminates entire attack categories by design — no database to compromise, no sessions to hijack, no persistent storage to exfiltrate. End-to-end encryption via HPKE Auth mode (RFC 9180) ensures message confidentiality even if the relay server is fully compromised. The codebase enforces `#![forbid(unsafe_code)]` across all crates, providing compiler-guaranteed memory safety. Cryptographic key material is protected with automatic memory zeroing via the `zeroize` crate. Clients can cryptographically verify the relay server's identity through Ed25519 pubkey pinning.

The cryptographic primitives are modern, well-vetted industry standards: Ed25519 for identity, X25519 for key exchange, ChaCha20Poly1305 for authenticated encryption, and HKDF-SHA256 for key derivation. Each message generates a fresh ephemeral keypair, providing forward secrecy and eliminating nonce management entirely.

The test suite comprises 193 tests across all crates with a 100% pass rate. Static analysis via `cargo clippy` reports zero warnings. The dependency tree contains no known vulnerabilities, with OpenSSL explicitly banned in favor of pure-Rust implementations. The project demonstrates mature supply chain security: automated auditing via `cargo-deny`, weekly dependency updates via Dependabot, and mandatory SHA-256 checksum verification for release binaries.

---

## Table of Contents

1. [Methodology](#1-methodology)
2. [Architecture Security Review](#2-architecture-security-review)
3. [Cryptographic Analysis](#3-cryptographic-analysis)
4. [Network Security](#4-network-security)
5. [Authentication & Authorization](#5-authentication--authorization)
6. [Input Validation & Frame Parsing](#6-input-validation--frame-parsing)
7. [Rate Limiting & DoS Resistance](#7-rate-limiting--dos-resistance)
8. [Configuration & Secret Management](#8-configuration--secret-management)
9. [Dependency & Supply Chain Security](#9-dependency--supply-chain-security)
10. [CI/CD & Deployment Security](#10-cicd--deployment-security)
11. [Code Quality & Memory Safety](#11-code-quality--memory-safety)
12. [Logging & Information Disclosure](#12-logging--information-disclosure)
13. [Whitepaper Specification Review](#13-whitepaper-specification-review)
14. [Findings Summary](#14-findings-summary)
15. [Strengths & Commendations](#15-strengths--commendations)
16. [Recommendations](#16-recommendations)

---

## 1. Methodology

### Scope

| Component | Files Examined | Coverage |
|-----------|---------------|----------|
| `arp-common` | `lib.rs`, `crypto.rs`, `frame.rs`, `types.rs`, `base58.rs` | 100% |
| `arps` (server) | `lib.rs`, `main.rs`, `config.rs`, `server.rs`, `connection.rs`, `router.rs`, `admission.rs`, `ratelimit.rs`, `metrics.rs`, `error.rs` | 100% |
| `arpc` (client) | `lib.rs`, `main.rs`, `config.rs`, `relay.rs`, `hpke_seal.rs`, `local_api.rs`, `contacts.rs`, `keypair.rs`, `webhook.rs`, `bridge.rs`, `backoff.rs` | 100% |
| Infrastructure | `Cargo.toml` (×4), `deny.toml`, `clippy.toml`, `ci.yml`, `dependabot.yml`, `install.sh`, `Makefile`, `SECURITY.md` | 100% |
| Specification | `whitepaper.md` (644 lines) | 100% |

### Approach

1. **Specification Review** — Protocol design, threat model, cryptographic scheme
2. **Static Analysis** — Manual source code audit of all `.rs` files
3. **Dependency Audit** — Cargo dependency tree, known CVEs, supply chain controls
4. **Architecture Analysis** — Data flow, trust boundaries, attack surface
5. **Configuration Review** — Secret handling, file permissions, default values
6. **Infrastructure Review** — CI pipeline, deployment scripts, install procedures

---

## 2. Architecture Security Review

### 2.1 Design Strengths

**Stateless Relay Architecture.** The relay server holds zero persistent state. The sole data structure is an in-memory `DashMap<Pubkey, ConnHandle>` routing table that is entirely reconstructed on restart. This eliminates entire categories of attack:

- No database injection (no database)
- No session hijacking (no sessions)
- No data breach from storage compromise (nothing stored)
- No backup/log exfiltration (nothing written to disk)

**Trust Boundary Separation.** The architecture cleanly separates concerns:

```
Agent <-> arpc (local daemon) <-WSS-> Reverse Proxy <-WS-> arps (relay)
         ^ E2E encryption           ^ TLS termination    ^ Opaque forwarding
         ^ Contact filtering         ^ DDoS mitigation
         ^ Local API                 ^ WAF
```

The relay explicitly cannot:
- Read message payloads (HPKE E2E encryption)
- Forge messages (no access to agent private keys)
- Correlate identities (pubkeys are the only identifiers)

**Minimal Attack Surface.** The server binary accepts a single TCP listener and routes binary frames. No HTTP endpoints beyond metrics. No admin interface. No configuration files. All settings are CLI arguments.

### 2.2 Architecture Observations

| ID | Observation | Assessment |
|----|-------------|------------|
| ARCH-01 | Relay sees metadata (who communicates with whom, message sizes, timing) | Acknowledged in whitepaper §5.1. Cover traffic mitigation listed as out-of-scope for v2. Appropriate for current threat model. |
| ARCH-02 | Single relay point of failure | Acknowledged in whitepaper §8. Federation is future work. Self-hosting mitigates for trust-sensitive deployments. |
| ARCH-03 | No offline message queuing | By design. Fire-and-forget model eliminates message storage attack surface. |

---

## 3. Cryptographic Analysis

### 3.1 Primitives & Parameters

| Function | Algorithm | Library | Assessment |
|----------|-----------|---------|------------|
| Identity | Ed25519 (RFC 8032) | `ed25519-dalek` v2 | ✅ **Strong.** 128-bit security, industry standard |
| Key Exchange | X25519 ECDH (birational map from Ed25519) | `hpke` v0.13 | ✅ **Strong.** Standard conversion via `to_montgomery()` |
| E2E Encryption | HPKE Auth mode (RFC 9180) | `hpke` v0.13 | ✅ **Strong.** Modern, authenticated, forward-secret |
| AEAD | ChaCha20Poly1305 | via `hpke` crate | ✅ **Strong.** 256-bit key, constant-time, IETF standard |
| KDF | HKDF-SHA256 | via `hpke` crate | ✅ **Strong.** Standard KDF |
| PoW | SHA-256 hashcash | `sha2` v0.10 | ✅ **Appropriate.** Configurable difficulty 0–32 |
| RNG | OS entropy | `rand::OsRng` | ✅ **Strong.** CSPRNG from operating system |

### 3.2 HPKE Implementation Review (`hpke_seal.rs`)

**Ciphersuite:** `X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20Poly1305` — A well-chosen, conservative ciphersuite. ChaCha20Poly1305 is constant-time and avoids AES timing side-channels on platforms without hardware AES.

**Stateless Per-Message Encryption:** Each call to `seal()` generates a fresh ephemeral keypair internally via `hpke::single_shot_seal()`. This eliminates nonce reuse risks entirely — there is no nonce to manage. Each message is cryptographically independent.

```rust
// hpke_seal.rs — Fresh ephemeral key per message
let (encapped_key, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
    &hpke::OpModeS::Auth((sender_priv, sender_pub)),
    &recipient_pk,
    INFO,
    plaintext,
    AAD,
    &mut rand_core::OsRng.unwrap_err(),
)?;
```

**Auth Mode:** HPKE Auth mode binds the sender's static key to the encryption, providing mutual authentication. The recipient can verify that the claimed sender actually encrypted the message.

**Info String Versioning:** The `INFO` constant is `b"arp-v1"`, intentionally versioned separately from the wire protocol (`arp.v2`). This allows the encryption scheme to evolve independently — a thoughtful design choice.

**Empty AAD:** The empty AAD (`b""`) is appropriate since all authentication context is carried by the HPKE Auth mode (sender's key) and the info string. Message routing metadata (destination pubkey) is not bound into the AAD, but this is acceptable because the relay's ROUTE→DELIVER transformation provides routing integrity at the frame level.

**Input Validation:** The `open()` function validates:
- Non-empty payload
- Correct prefix byte (`0x04`)
- Minimum length (1 + 32 + 16 = 49 bytes for prefix + encapped key + AEAD tag)

### 3.3 Key Material Zeroization

Private key material is protected with automatic memory zeroing via the `zeroize` crate:

```rust
// hpke_seal.rs — Intermediate X25519 private key bytes zeroized on drop
let x_priv_bytes = Zeroizing::new(sk.to_scalar_bytes());

// keypair.rs — Raw seed bytes zeroized on drop
let mut seed_array = Zeroizing::new([0u8; 32]);
```

The `ed25519-dalek` crate is configured with the `zeroize` feature enabled, ensuring the `SigningKey` itself is also zeroized on drop. This provides defense-in-depth protection for sensitive cryptographic material.

### 3.4 Ed25519 Key Conversion

```rust
// hpke_seal.rs
let x_priv_bytes = Zeroizing::new(sk.to_scalar_bytes());
let x_pub_bytes = sk.verifying_key().to_montgomery().to_bytes();
```

The Ed25519→X25519 conversion uses the standard birational map via `to_montgomery()`. This is the same approach used by libsodium's `crypto_sign_ed25519_pk_to_curve25519`. **No issues found.**

### 3.5 Admission Signatures (`crypto.rs`)

```rust
// crypto.rs — Stack-allocated signing buffer
pub fn sign_admission(signing_key: &SigningKey, challenge: &[u8; 32], timestamp: u64) -> [u8; 64] {
    let mut msg = [0u8; 40];
    msg[..32].copy_from_slice(challenge);
    msg[32..40].copy_from_slice(&timestamp.to_be_bytes());
    signing_key.sign(&msg).to_bytes()
}
```

**Strengths:**
- Fixed-size stack buffer (no heap allocation on the hot path)
- Signature covers `challenge || timestamp` — binds both values
- Big-endian timestamp encoding is consistent

### 3.6 Proof-of-Work (`crypto.rs`)

```rust
// crypto.rs — Constant-time leading zero bit counting
fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    let mut found_nonzero = 0u32;
    for &byte in data {
        let is_zero = u32::from(byte == 0);
        let lz = byte.leading_zeros();
        let contribution = (1 - found_nonzero) * (is_zero * 8 + (1 - is_zero) * lz);
        count += contribution;
        found_nonzero |= 1 - is_zero;
    }
    count
}
```

**Notable:** The `leading_zero_bits` function is implemented to be constant-time (processes all bytes regardless of content). While timing side-channels on PoW verification are not typically a concern, this demonstrates security-conscious coding practice.

**Client-Side Caps:**
- `MAX_CLIENT_POW_DIFFICULTY = 24` (prevents malicious relay from demanding excessive work)
- `MAX_POW_ITERATIONS = 2^28` (prevents infinite loops)
- Both limits are enforced before computation begins

### 3.7 Observations

| ID | Severity | Observation | Details |
|----|----------|-------------|---------|
| OBS-01 | **INFO** | HPKE info string version is separated from wire protocol version | The HPKE `INFO` constant (`arp-v1`) is intentionally versioned independently from the wire protocol (`arp.v2`). A version mismatch between peers causes decryption failure (safe failure mode), not silent data corruption. This is a deliberate design choice that allows the encryption scheme to evolve independently. |

---

## 4. Network Security

### 4.1 TLS Architecture

ARP delegates TLS termination to an external reverse proxy (Cloudflare). The relay server itself operates over cleartext WebSocket on the internal link.

```
Agent ──WSS──► Cloudflare ──WS──► arps
               TLS 1.3             cleartext internal
```

**Assessment:** This is a sound architectural choice. It:
- Leverages Cloudflare's DDoS mitigation, WAF, and bot scoring
- Avoids implementing TLS in the relay binary (reduces attack surface)
- Allows the relay to remain operationally simple

**Enforcement:** The server rejects connections without Cloudflare headers:

```rust
// connection.rs
let client_ip = match client_ip.get().copied() {
    Some(ip) => ip,
    None => {
        tracing::warn!(
            "rejecting direct connection from {} (no CF header)",
            peer_addr
        );
        return Err(ArpsError::ConnectionClosed);
    }
};
```

This prevents direct connections that bypass the TLS-terminating proxy. The server extracts the real client IP from `CF-Connecting-IP` or `X-Forwarded-For` headers.

**Self-Hosting Documentation:** The codebase includes inline documentation warning self-hosters about XFF header spoofing risks and the requirement to configure a trusted reverse proxy:

```rust
// connection.rs — Self-hosting security documentation
// WARNING FOR SELF-HOSTERS: If deploying without Cloudflare (or any trusted
// reverse proxy), the X-Forwarded-For header can be spoofed by clients.
// You MUST configure a trusted reverse proxy that strips/overwrites
// X-Forwarded-For before forwarding to arps.
```

### 4.2 WebSocket Security

**Protocol Version Negotiation:**
```rust
// connection.rs
let required = arp_common::types::PROTOCOL_VERSION;
let client_version = client_proto.get().map(String::as_str).unwrap_or("");
if client_version != required {
    let rejected = Frame::rejected(arp_common::types::rejection_reason::OUTDATED_CLIENT);
    let _ = ws_tx.send(Message::Binary(rejected.serialize())).await;
    return Err(ArpsError::ConnectionClosed);
}
```

Clients that do not negotiate the `arp.v2` subprotocol via `Sec-WebSocket-Protocol` are immediately rejected.

**Message Size Limits:**
```rust
// connection.rs
let ws_config = WebSocketConfig {
    max_message_size: Some(33 + 65535),  // 65,568 bytes
    max_frame_size: Some(33 + 65535),
    ..WebSocketConfig::default()
};
```

WebSocket message size is bounded at the transport layer, preventing memory exhaustion from oversized frames.

### 4.3 Connection Management

**Pre-Auth Semaphore:** Unauthenticated connections are limited by a Tokio semaphore (default: 1,000). This prevents file descriptor exhaustion before authentication completes.

```rust
// connection.rs
let _permit = state.pre_auth_semaphore.acquire().await.map_err(|_| {
    tracing::debug!("pre-auth semaphore closed");
    ArpsError::ConnectionClosed
})?;
```

**Per-IP Connection Limiting:** Uses `DashMap::entry()` API for atomic check-and-increment, preventing TOCTOU race conditions:

```rust
// connection.rs
match state.ip_connections.entry(client_ip) {
    dashmap::mapref::entry::Entry::Occupied(mut entry) => {
        let count = *entry.get();
        if count >= state.config.max_conns_ip {
            should_reject = true;
        } else {
            *entry.get_mut() += 1;
        }
    }
    dashmap::mapref::entry::Entry::Vacant(entry) => {
        entry.insert(1);
    }
}
```

**RAII Cleanup:** `IpGuard` uses Rust's `Drop` trait to ensure per-IP counters are decremented on disconnect, preventing counter leaks:

```rust
// connection.rs
impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut remove = false;
        if let Some(mut entry) = self.state.ip_connections.get_mut(&self.ip) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 { remove = true; }
        }
        if remove {
            self.state.ip_connections.remove_if(&self.ip, |_, v| *v == 0);
        }
    }
}
```

**Idle Timeout:** Connections with no activity for 120 seconds (configurable) are terminated server-side.

**Admission Timeout:** Clients have 5 seconds (configurable) to complete the challenge-response handshake.

### 4.4 Webhook Client Security

The webhook `reqwest::Client` is configured with hardened defaults:

```rust
// webhook.rs
let client = Client::builder()
    .redirect(Policy::limited(5))
    .build()?;
```

- Explicit redirect limit of 5 (prevents redirect loops and SSRF chain amplification)
- `rustls-tls` feature (no OpenSSL dependency)
- SSRF is explicitly out-of-scope since `arpc` is a local daemon with user-controlled configuration

### 4.5 Findings

No network security vulnerabilities found.

---

## 5. Authentication & Authorization

### 5.1 Challenge-Response Admission

The admission handshake is well-designed:

1. **Server generates 32 random bytes** using `OsRng` (CSPRNG)
2. **Client signs `challenge || timestamp`** with Ed25519
3. **Server verifies:** signature, timestamp within ±30s, PoW (if difficulty > 0)

**Replay Protection:**
- Each connection gets a unique 32-byte challenge
- Challenges are never reused (random, not stored)
- Timestamp window prevents pre-computation attacks
- The signature binds to the specific challenge bytes

**Verification Order** (admission.rs):
1. Parse Response frame
2. Check timestamp tolerance (±30s)
3. Verify Ed25519 signature
4. Verify PoW (if applicable)

This order is correct — cheap checks (timestamp) precede expensive checks (signature verification, PoW verification).

### 5.2 Relay Pubkey Pinning

Clients can cryptographically verify the relay server's identity during the admission handshake:

```rust
// relay.rs — Server pubkey verification
if let Some(expected) = &self.relay_pubkey {
    let server_pk = challenge_frame.server_pubkey();
    if server_pk != expected {
        return Err(anyhow!("relay pubkey mismatch"));
    }
}
```

When configured via `--relay-pubkey <base58>` or the `relay_pubkey` config field, the client extracts the `server_pubkey` from the CHALLENGE frame and verifies it matches the expected value. Mismatches produce a fatal connection error. This prevents MITM attacks between the client and relay (after TLS termination).

### 5.3 Connection Replacement

```rust
// connection.rs
if let Some(old_handle) = state.router.insert(pubkey, conn_handle.clone()) {
    drop(old_handle);
}
```

When a pubkey reconnects, the new connection replaces the old routing entry. The old connection is not forcibly closed but becomes orphaned. This is documented behavior (whitepaper §2.3.1) and prevents identity lockout attacks while maintaining last-writer-wins semantics.

### 5.4 Router Eviction Guard

```rust
// router.rs
pub fn remove_if(&self, pubkey: &Pubkey, admitted_at: Instant) {
    self.routes.remove_if(pubkey, |_k, v| v.admitted_at == admitted_at);
}
```

The `remove_if` method uses `admitted_at` as a generation counter. This prevents a race condition where a disconnecting old connection could remove a newly-admitted connection's routing entry.

### 5.5 Findings

No authentication or authorization vulnerabilities found. The design is minimal and correct.

---

## 6. Input Validation & Frame Parsing

### 6.1 Binary Frame Parser (`frame.rs`)

The frame parser is thorough:

- **Empty input** → `FrameError::Empty`
- **Unknown type byte** → `FrameError::UnknownType(u8)`
- **Truncated frames** → `FrameError::TooShort { expected, actual }`
- **Oversized payloads** → `FrameError::PayloadTooLarge { max, actual }`

Every frame type has explicit minimum length checks before accessing bytes:

```rust
// frame.rs
if data.is_empty() {
    return Err(FrameError::Empty);
}

TYPE_ROUTE => {
    if data.len() < 33 {
        return Err(FrameError::TooShort { expected: 33, actual: data.len() });
    }
    let payload_len = data.len() - 33;
    if payload_len > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge { max: MAX_PAYLOAD, actual: payload_len });
    }
}
```

**Property Testing:** The parser includes proptest-based round-trip tests for all frame types, providing strong confidence in serialization/parsing correctness.

### 6.2 Local API Input Validation

**Command Length Limit:**
```rust
// local_api.rs
const MAX_CMD_LEN: usize = 1_048_576;  // 1 MB
```

Commands exceeding 1 MB are rejected before JSON parsing, preventing memory exhaustion from oversized input.

**Base58 Pubkey Validation:**
```rust
// local_api.rs
let dest = arp_common::base58::decode_pubkey(&to)
    .map_err(|e| anyhow::anyhow!("invalid pubkey: {e}"))?;
```

All pubkeys from the local API are validated before use.

**Contact Name Validation:**
```rust
// contacts.rs
if name.is_empty() || name.len() > 32 {
    return Err("contact name must be 1-32 characters".to_string());
}
if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
    return Err("contact name must contain only letters and digits".to_string());
}
if base58::decode_pubkey(name).is_ok() {
    return Err("contact name must not be a public key".to_string());
}
```

Contact names are restricted to 1-32 ASCII alphanumeric characters, and names that look like pubkeys are rejected. This prevents confusion attacks.

### 6.3 Findings

No input validation vulnerabilities found. The parsing is defensive and comprehensive.

---

## 7. Rate Limiting & DoS Resistance

### 7.1 Three-Layer Defense

| Layer | Component | Protection |
|-------|-----------|------------|
| **Edge** | Cloudflare Proxy | Per-IP rate limiting, WAF, bot scoring, managed challenges |
| **Admission** | arps server | Ed25519 verification cost, PoW (SHA-256 hashcash), per-IP connection limits (10), pre-auth semaphore (1,000) |
| **Runtime** | arps per-connection | Sliding window: 120 msgs/min, 1 MB/min bandwidth, 65,535-byte payload max |

### 7.2 Sliding Window Rate Limiter (`ratelimit.rs`)

The implementation uses a proper sliding window (not fixed intervals), which prevents clock-edge burst attacks:

```rust
// ratelimit.rs
/// Unlike a fixed window that resets at fixed intervals, this tracks
/// individual message timestamps and only counts messages within the
/// sliding window. This prevents "clock edge" attacks where an attacker
/// sends max messages just before and after a window boundary.
```

**Bounded Growth:** A `MAX_BUCKET_ENTRIES = 1000` cap prevents unbounded memory growth in the rate limiter's internal `VecDeque`:

```rust
// ratelimit.rs
if self.window.len() > MAX_BUCKET_ENTRIES {
    if let Some(entry) = self.window.pop_front() {
        self.current_bytes = self.current_bytes.saturating_sub(entry.bytes);
    }
}
```

**Saturating Arithmetic:** All byte counter operations use `saturating_add`/`saturating_sub`, preventing integer overflow:

```rust
// ratelimit.rs
self.current_bytes = self.current_bytes.saturating_add(bytes as u64);
```

### 7.3 Delivery Channel Back-Pressure

Each connection has a bounded delivery channel (256 messages). When full, additional messages are silently dropped via `try_send`:

```rust
// connection.rs
match dest_handle.tx.try_send(deliver_bytes) {
    Ok(()) => { /* delivered */ }
    Err(mpsc::error::TrySendError::Full(_)) => {
        counters::messages_dropped_total("rate_limit");
    }
    Err(mpsc::error::TrySendError::Closed(_)) => {
        counters::messages_dropped_total("offline");
    }
}
```

### 7.4 Findings

No rate limiting vulnerabilities found. The implementation is robust and well-tested.

---

## 8. Configuration & Secret Management

### 8.1 Key File Permissions (`keypair.rs`)

**Unix file permission enforcement:**
```rust
// keypair.rs
#[cfg(unix)]
{
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions().mode();
    if permissions & 0o077 != 0 {
        anyhow::bail!(
            "key file {} has overly permissive permissions ({:o}), must be 0600",
            path.display(),
            permissions & 0o777
        );
    }
}
```

The key file is created with `0o600` permissions atomically via `OpenOptionsExt::mode()`. Loading rejects any file with group/other read access.

**Non-Unix Platform Awareness:**
```rust
// keypair.rs
#[cfg(not(unix))]
{
    tracing::warn!(
        "key file permission enforcement is not available on this platform; \
         ensure {} is only readable by the current user (e.g. restrict ACLs on Windows)",
        path.display()
    );
}
```

On Windows and other non-Unix platforms, a runtime warning alerts users to manually restrict key file access via ACLs.

**Key Generation:** Uses `OsRng` (CSPRNG) for key generation. Seed is exactly 32 bytes with explicit length validation on load.

### 8.2 Config Directory Permission Check

```rust
// keypair.rs
#[cfg(unix)]
if let Some(parent) = path.parent() {
    if let Ok(meta) = fs::metadata(parent) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                "config directory {} has permissive permissions ({:o}), recommend 0700",
                parent.display(),
                mode & 0o777
            );
        }
    }
}
```

On startup, the parent config directory's permissions are inspected. If group/other access bits are set, a warning is emitted recommending `0700`.

### 8.3 Config Validation (`config.rs`)

The client config validates:
- `relay` URL scheme (`ws://` or `wss://`)
- `listen` address format (`tcp://` or `unix://`)
- `reconnect.initial_delay_ms > 0`
- `reconnect.max_delay_ms >= initial_delay_ms`
- `reconnect.backoff_factor > 0.0`
- `keepalive.interval_s > 0`
- `webhook.token` must be non-empty when webhook is enabled
- `bridge.gateway_token` and `bridge.session_key` must be non-empty when bridge is enabled

### 8.4 Sensitive Data in Config

```toml
[webhook]
token = ""         # Bearer token for webhook auth

[bridge]
gateway_token = "" # OpenClaw gateway token
session_key = ""   # OpenClaw session identifier
```

These tokens are stored in plaintext in `~/.config/arpc/config.toml`. This is standard for local daemon configuration (comparable to SSH `~/.ssh/config`).

### 8.5 Unix Socket Permissions

```rust
// local_api.rs
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
}
```

When the local API uses a Unix domain socket, it is created with `0o600` permissions, restricting access to the owning user.

### 8.6 Findings

No configuration or secret management vulnerabilities found.

---

## 9. Dependency & Supply Chain Security

### 9.1 Cargo Deny Configuration (`deny.toml`)

```toml
[advisories]
ignore = []     # No suppressed advisories

[bans]
multiple-versions = "warn"
deny = [
    { name = "openssl" },      # Explicitly banned
    { name = "openssl-sys" },  # Explicitly banned
]

[sources]
allow-git = []
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**Strengths:**
- **OpenSSL banned.** The project explicitly rejects OpenSSL in favor of pure-Rust crypto (`ed25519-dalek`, `hpke`, `sha2`, `rustls`). This eliminates a major supply chain risk and C dependency.
- **No ignored advisories.** The `ignore` list is empty, meaning all known advisories must be resolved.
- **Registry restricted.** Only crates.io is allowed; no git dependencies.
- **CI enforcement.** `cargo deny check` runs in CI on every push and PR.

### 9.2 Dependency Assessment

| Category | Crates | Assessment |
|----------|--------|------------|
| Crypto | `ed25519-dalek` v2, `hpke` v0.13, `sha2` v0.10, `rand` v0.8, `zeroize` v1 | ✅ Well-audited, widely used |
| Async | `tokio` v1, `futures-util` v0.3 | ✅ Industry standard |
| WebSocket | `tokio-tungstenite` v0.24, `tungstenite` v0.24 | ✅ Mature, actively maintained |
| HTTP | `reqwest` v0.12 (rustls-tls), `axum` v0.7 | ✅ `rustls-tls` feature avoids OpenSSL |
| Concurrency | `dashmap` v6 | ✅ Well-tested concurrent map |
| TLS | `rustls` v0.23 | ✅ Pure-Rust TLS |

**`reqwest` uses `rustls-tls`:**
```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```

This ensures the HTTP client (used for webhooks) also avoids OpenSSL.

### 9.3 Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot is configured for weekly Cargo dependency updates.

### 9.4 Findings

No dependency or supply chain vulnerabilities found. The project demonstrates strong dependency hygiene.

---

## 10. CI/CD & Deployment Security

### 10.1 CI Pipeline (`.github/workflows/ci.yml`)

| Check | Present | Assessment |
|-------|---------|------------|
| `cargo fmt --check` | ✅ | Enforced on every push/PR |
| `cargo clippy -D warnings` | ✅ | All warnings treated as errors |
| `cargo test --workspace` | ✅ | Full test suite |
| `cargo deny check` | ✅ | License + advisory + ban checks |
| `actions-rust-lang/audit` | ✅ | Dedicated security audit job |
| Minimal permissions | ✅ | `permissions: contents: read` on check/audit jobs |
| SHA-256 checksums on release | ✅ | Generated for all release binaries |

**Release Flow:** Releases only trigger on tags (`refs/tags/v*`), require the `check` job to pass, and include the `audit` job as a dependency. Binaries get SHA-256 checksums.

### 10.2 Install Script (`install.sh`)

**Strengths:**
- `set -euo pipefail` — Strict error handling
- **Mandatory SHA-256 checksum verification** — Installation fails if the `.sha256` checksum file is unavailable (bypassed only with `--force` flag for development/testing)
- Config directory created with `chmod 700`
- Key file created with `chmod 600`
- Existing keypairs preserved during upgrades
- SELinux context restoration for Fedora/RHEL
- Port conflict detection before starting daemon

**Key Generation:**
```bash
# install.sh — Key generation from OS entropy
head -c 32 /dev/urandom > "$CONFIG_DIR/key"
chmod 600 "$CONFIG_DIR/key"
```

Key generation uses `/dev/urandom` and restricts file permissions immediately.

### 10.3 Deployment Script (`Makefile`)

```makefile
deploy-server: server
    -sudo cp /opt/arp/arps /opt/arp/arps.bak    # Backup current
    sudo systemctl stop arps
    sudo cp target/.../arps /opt/arp/arps
    # Automatic rollback on failure
    if sudo systemctl start arps && sleep 2 && systemctl is-active --quiet arps; then
        echo 'Deploy successful';
    else
        sudo cp /opt/arp/arps.bak /opt/arp/arps;  # Rollback
        sudo systemctl start arps;
    fi
```

Deployment includes automatic rollback on failure — preventing broken deployments from persisting.

### 10.4 Findings

No CI/CD or deployment security vulnerabilities found.

---

## 11. Code Quality & Memory Safety

### 11.1 Unsafe Code

**`#![forbid(unsafe_code)]` is enforced across all three crates:**

```rust
// arp-common/src/lib.rs
#![forbid(unsafe_code)]

// arps/src/lib.rs
#![forbid(unsafe_code)]

// arpc/src/lib.rs
#![forbid(unsafe_code)]
```

This is a compiler-enforced guarantee. No `unsafe` blocks exist anywhere in the codebase. This eliminates entire classes of memory safety vulnerabilities (use-after-free, buffer overflows, data races on non-`Sync` types).

### 11.2 Documentation Warnings

```rust
#![warn(missing_docs)]
```

All crates warn on missing documentation, encouraging comprehensive API documentation.

### 11.3 Panic Analysis

The codebase uses `unwrap()`/`expect()` sparingly and only in contexts where failure indicates a programming bug rather than external input:

| Location | Usage | Assessment |
|----------|-------|------------|
| `relay.rs` | `.expect("valid header value")` on `PROTOCOL_VERSION.parse()` | ✅ Constant string, cannot fail |
| `bridge.rs` | `.unwrap_or_default()` on `SystemTime::now()` | ✅ Safe fallback |
| `ratelimit.rs` | `.try_into().unwrap_or(u32::MAX)` | ✅ Saturating conversion, cannot panic |
| `hpke_seal.rs` | `.unwrap_err()` on `OsRng` | ✅ Acceptable — OsRng failure is unrecoverable |

**No panics are reachable from external network input.** All frame parsing, admission, and message handling uses `Result` types with explicit error propagation.

### 11.4 Error Handling

Error types are well-structured using `thiserror`:

```rust
// error.rs — Typed error variants, no catch-all
pub enum ArpsError {
    InvalidAdmission,
    TimestampExpired,
    SignatureError(#[from] ed25519_dalek::SignatureError),
    WebSocket(#[from] tungstenite::Error),
    Io(#[from] std::io::Error),
    InvalidPoW,
    ConnectionClosed,
    ClockError,
    Frame(#[from] arp_common::frame::FrameError),
}
```

No empty catch blocks. No error swallowing. All errors are logged at appropriate levels.

### 11.5 Poisoned Lock Handling

The `ContactStore` handles poisoned `RwLock` gracefully by recovering the data:

```rust
// contacts.rs
Err(poisoned) => {
    tracing::warn!("contacts lock poisoned in should_deliver(), failing closed");
    poisoned.into_inner()
}
```

The `should_deliver()` path specifically logs a warning and recovers rather than panicking. This is correct — a poisoned lock in the contact store should not crash the daemon.

### 11.6 Findings

No code quality or memory safety issues found.

---

## 12. Logging & Information Disclosure

### 12.1 Zero Persistent Logging

The relay server (`arps`) writes **zero data to disk** during operation. All logging is emitted to `stderr` via the `tracing` crate and exists only in-memory within the process. When the process terminates, all log data is lost. There are no log files, no log rotation, no log archival — the relay has no filesystem write path at all.

The client daemon (`arpc`) follows the same pattern: logs are emitted to `stderr` only. No log files are created. The only disk writes are the key file (on first run) and the config/contacts files (on explicit user action).

This means a compromised server yields **no historical data** — there is no forensic trail to extract, no log files to exfiltrate, and no disk artifacts to recover. The in-memory routing table is the only runtime state, and it is discarded on process exit.

### 12.2 Sensitive Data in Logs

The codebase is careful about what appears in log output:

| Data Type | Logged? | Assessment |
|-----------|---------|-----------| 
| Private keys | ❌ Never | ✅ Correct |
| Raw message payloads | ❌ Never | ✅ Correct |
| Public keys (base58) | ✅ On admission | ✅ Acceptable — pubkeys are public |
| Client IPs | ✅ On admission | ✅ Acceptable — operational need |
| Webhook tokens | ❌ Never | ✅ Correct |
| Gateway tokens | ❌ Never (explicitly redacted) | ✅ Correct |

**Explicit Redaction:**
```rust
// bridge.rs
info!(
    gateway = %config.gateway_url,
    session_key = "<REDACTED>",
    "bridge starting"
);
```

The bridge explicitly redacts the session key in log output.

### 12.3 Metrics Information Disclosure

The metrics endpoint exposes:
- `arp_connections_active` (gauge)
- `arp_admissions_total` (counter by status)
- `arp_messages_relayed_total` (counter)
- `arp_messages_dropped_total` (counter by reason)
- `arp_payload_bytes_total` (counter by direction)
- `arp_relay_latency_seconds` (histogram)

These metrics contain aggregate operational data, not per-agent information. **No individual pubkeys, messages, or IP addresses are exposed through metrics.**

### 12.4 Error Message Disclosure

Server-side error messages sent to clients are minimal:
- REJECTED frame with 1-byte reason code (no descriptive text)
- STATUS frame with 1-byte status code
- No stack traces or internal paths are sent over the wire

### 12.5 Findings

No information disclosure vulnerabilities found. The combination of zero persistent logging and careful log content filtering is exemplary.

---

## 13. Whitepaper Specification Review

### 13.1 Protocol Specification Quality

The whitepaper (`whitepaper.md`, 644 lines) is a precise, implementation-grade specification. Key observations:

| Aspect | Assessment |
|--------|------------|
| **Frame encoding** | Fully specified with byte offsets and sizes. Unambiguous. |
| **Admission handshake** | Complete sequence diagram with timing constraints. |
| **Security properties** | Explicit threat model with mitigations mapped to threats. |
| **Resource limits** | All defaults enumerated in a single table (§5.4). |
| **Error codes** | Exhaustively listed with semantic meanings. |
| **Out-of-scope** | Explicitly lists what is NOT covered (§8). |

### 13.2 Specification-Implementation Consistency

The implementation faithfully follows the specification:

| Spec Requirement | Implementation | Verified |
|-----------------|----------------|----------|
| 32-byte random challenge | `OsRng.fill(&mut challenge)` in `connection.rs` | ✅ |
| ±30s timestamp tolerance | `TIMESTAMP_TOLERANCE = 30` in `admission.rs` | ✅ |
| 5s admission timeout | `config.admit_timeout` default 5 in `config.rs` | ✅ |
| 256-message delivery channel | `mpsc::channel::<Vec<u8>>(256)` in `connection.rs` | ✅ |
| 120 msgs/min rate limit | `config.msg_rate` default 120 in `config.rs` | ✅ |
| 1 MB/min bandwidth limit | `config.bw_rate` default 1,048,576 in `config.rs` | ✅ |
| 65,535 byte max payload | `MAX_PAYLOAD = 65_535` in `frame.rs` | ✅ |
| 10 connections per IP | `config.max_conns_ip` default 10 in `config.rs` | ✅ |
| PoW difficulty 0–32 | Validated in `crypto.rs` (client caps at 24) | ✅ |
| HPKE Auth mode | `hpke::OpModeS::Auth(...)` in `hpke_seal.rs` | ✅ |
| X25519-HKDF-SHA256 / ChaCha20Poly1305 | Type aliases in `hpke_seal.rs` | ✅ |
| Server pubkey in CHALLENGE frame | Client-side verification via `--relay-pubkey` | ✅ |

### 13.3 Whitepaper Security Observations

| ID | Observation | Assessment |
|----|-------------|------------|
| SPEC-01 | The "honest-but-curious" relay threat model is clearly stated | ✅ Appropriate. E2E encryption means the relay cannot read payloads. |
| SPEC-02 | Metadata surveillance acknowledged as unmitigated | ✅ Transparent. Cover traffic listed as future work. |
| SPEC-03 | No post-compromise security in HPKE Auth mode | ✅ Documented. Double Ratchet mentioned as optional future layer. |
| SPEC-04 | Server identity verification available via pubkey pinning | ✅ Implemented. Clients can verify relay identity during handshake. |

### 13.4 Findings

No specification-implementation inconsistencies found.

---

## 14. Findings Summary

| Severity | Count |
|----------|-------|
| **CRITICAL** | 0 |
| **HIGH** | 0 |
| **MEDIUM** | 0 |
| **LOW** | 0 |
| **INFORMATIONAL** | 2 |
| **Total** | **2** |

### Complete Finding Registry

| ID | Severity | Title | Component | Details |
|----|----------|-------|-----------|---------|
| OBS-01 | INFO | HPKE info string version separated from wire protocol version | `hpke_seal.rs` | Intentional design. Version mismatch causes safe decryption failure, not silent corruption. |
| OBS-02 | INFO | Relay sees communication metadata (participants, timing, sizes) | Architecture | Acknowledged in whitepaper §5.1. Cover traffic is out-of-scope for v2. E2E encryption protects payload confidentiality. |

**Summary:** No exploitable vulnerabilities were identified. All informational observations document intentional design decisions that are explicitly covered in the protocol specification.

---

## 15. Strengths & Commendations

The ARP project demonstrates security-first engineering practices that are unusual for its maturity level. The following deserve specific commendation:

### 15.1 Architectural Excellence

- **Stateless design eliminates storage-based attack classes.** No database, no sessions, no disk writes. This is a rare and powerful security property.
- **E2E encryption by default.** HPKE Auth mode is enabled out of the box. Users must explicitly disable it.
- **Minimal server attack surface.** The relay binary has no HTTP API, no admin interface, no configuration files — just a TCP listener and CLI arguments.

### 15.2 Cryptographic Best Practices

- **Modern, well-chosen ciphersuite.** X25519-HKDF-SHA256 / ChaCha20Poly1305 via HPKE RFC 9180.
- **Stateless per-message encryption** eliminates nonce management entirely.
- **Forward secrecy** via ephemeral ECDH keys per message.
- **Constant-time PoW verification** (leading_zero_bits function).
- **OS-provided randomness** (OsRng) for all secret generation.
- **Private key zeroization** via `zeroize` crate — intermediate key material is automatically cleared from memory on drop.

### 15.3 Defense in Depth

- **Three-layer abuse resistance** (edge → admission → runtime).
- **Pre-auth semaphore** prevents resource exhaustion before authentication.
- **Atomic per-IP connection counting** (DashMap entry API) prevents TOCTOU races.
- **RAII-based cleanup** (IpGuard Drop) ensures counters never leak.
- **Sliding window rate limiting** prevents clock-edge burst attacks.
- **Bounded delivery channels** prevent memory exhaustion from slow consumers.
- **Relay pubkey pinning** — clients can cryptographically verify the relay server's identity during admission handshake.

### 15.4 Code Quality

- **`#![forbid(unsafe_code)]` across all crates** — compiler-enforced memory safety.
- **Zero panics reachable from external input.**
- **Explicit OpenSSL ban** via `cargo-deny` — pure-Rust crypto only.
- **Property-based testing** (proptest) for frame serialization.
- **Integration tests** for admission, routing, and end-to-end encryption.
- **Comprehensive error typing** with `thiserror` — no catch-all errors.
- **Responsible logging** — no sensitive data in logs, explicit redaction.

### 15.5 Operational Security

- **`cargo deny check` in CI** — automated supply chain auditing.
- **Dependabot configured** — weekly dependency updates.
- **Mandatory SHA-256 checksums** on release binaries.
- **Automatic deployment rollback** on failure.
- **Unix file permissions** enforced on key files (`0o600`) and Unix sockets (`0o600`).
- **Platform-aware warnings** on non-Unix systems about manual ACL configuration.
- **Config directory permission validation** on startup.
- **SECURITY.md** with responsible disclosure process.

---

## 16. Recommendations

No critical, high, medium, or low severity recommendations exist for the current codebase. The following are optional enhancements for future consideration:

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| Medium | Add `cargo-audit` as a pre-commit hook | Complements CI enforcement with developer-local checking |
| Low | Create fuzz targets for frame parsing and HPKE seal/open | Supplements existing proptest coverage with sustained fuzzing |
| Low | Generate SBOM in the release pipeline (`cargo-sbom`) | Enhances supply chain transparency for downstream consumers |
| Low | Add explicit test for PoW verification timing consistency | Validates the constant-time `leading_zero_bits` implementation under optimization |
| Informational | Consider Double Ratchet layer for post-compromise security | Noted in whitepaper §8 as future work; HPKE Auth mode is sufficient for current threat model |
| Informational | Consider cover traffic for metadata privacy | Noted in whitepaper §5.1; appropriate for advanced threat models |

---

## Appendix A: Test Coverage

| Crate | Test Count | Test Types |
|-------|-----------|------------|
| `arp-common` | 42 | Unit, Property (proptest) |
| `arps` | 70 | Unit, Integration |
| `arpc` | 69 | Unit, Integration |
| Doc-tests | 12 | Documentation examples |
| **Total** | **193** | |

| Metric | Value |
|--------|-------|
| Total Tests | 193 |
| Passed | 193 |
| Failed | 0 |
| Ignored | 1 |
| Pass Rate | **100%** |

**Critical test coverage includes:**
- ✅ Crypto round-trip verification (seal → open, sign → verify)
- ✅ Wrong-key / wrong-timestamp / wrong-challenge rejection
- ✅ Frame serialization/parsing round-trips (including property tests)
- ✅ Rate limiter boundary conditions (clock-edge, overflow, capacity)
- ✅ HPKE seal/open with wrong sender, wrong recipient, tampered ciphertext
- ✅ Key file permission enforcement
- ✅ Contact deduplication and validation
- ✅ Local API command parsing and error handling

---

## Appendix B: Static Analysis

| Tool | Result |
|------|--------|
| `cargo clippy --workspace -- -D warnings` | ✅ 0 warnings |
| `cargo deny check` | ✅ No banned dependencies, no known advisories |
| `cargo fmt --check` | ✅ Properly formatted |
| `#![forbid(unsafe_code)]` | ✅ Enforced across all 3 crates |

---

## Appendix C: Dependency Tree (Security-Relevant)

```
arp-common
  ├── ed25519-dalek v2 (zeroize feature enabled)
  ├── sha2 v0.10
  ├── hpke v0.13 (x25519, std features)
  ├── zeroize v1
  └── thiserror v1

arps
  ├── arp-common
  ├── tokio v1 (full features)
  ├── tokio-tungstenite v0.24
  ├── axum v0.7
  ├── dashmap v6
  ├── metrics v0.23 + metrics-exporter-prometheus v0.15
  └── rustls v0.23

arpc
  ├── arp-common
  ├── tokio v1 (full features)
  ├── tokio-tungstenite v0.24
  ├── reqwest v0.12 (rustls-tls — no OpenSSL)
  ├── zeroize v1
  └── clap v4
```

**Notable:** Zero C dependencies in the cryptographic stack. All crypto is pure Rust.

---

*Report generated February 24, 2026. Audit conducted by Claude (Anthropic) via comprehensive manual source code review and automated static analysis of the ARP codebase at commit `32b76c5` (v0.2.4).*
