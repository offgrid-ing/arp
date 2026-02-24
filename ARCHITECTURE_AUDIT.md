# ARP Architectural Audit Report

**Date:** February 24, 2026
**Auditor:** Sisyphus (AI Agent, Ultrawork Mode)
**Project:** ARP (Agent Relay Protocol) — Rust Workspace
**Version:** 0.2.2
**Scope:** Architecture, design quality, over-engineering, first principles, tech choices, code quality
**Method:** Manual review of all 27 source files + Oracle deep analysis + Librarian security research + 4 parallel explore agents

---

## Executive Summary

ARP is a 3-crate Rust workspace (~5,800 LOC) implementing a stateless WebSocket relay for agent-to-agent communication. Agents connect via Ed25519 identity, the relay routes opaque bytes by pubkey, and clients optionally encrypt with HPKE (RFC 9180).

**Overall Verdict: Well-designed, lean, principled.** The architecture adheres to its stated first principles. No over-engineering found. Sound crypto. Clean separation of concerns. The main risks are the unsigned self-update and the outdated HPKE crate — both already tracked as TODOs.

| Metric | Value |
|--------|-------|
| **Total LOC** | ~5,800 (27 source files across 3 crates) |
| **Tests** | 192/192 passing |
| **Clippy** | 0 warnings |
| **Architectural Findings** | 25 total |
| **CRITICAL** | 1 |
| **IMPORTANT** | 6 |
| **MINOR** | 14 |
| **NITPICK** | 4 |

---

## Project Structure

| Crate | LOC | Files | Purpose |
|-------|-----|-------|---------|
| **arp-common** | ~1,200 | 5 | Binary TLV framing, Ed25519 crypto, SHA-256 PoW, base58 |
| **arps** | ~1,800 | 10 | Relay server — admission, routing, rate limiting, metrics |
| **arpc** | ~2,800 | 12 | Client daemon — CLI, relay connection, HPKE encryption, local API, contacts, webhooks, bridge |

```
Your Agent ──► arpc ══WSS══► arps relay ══WSS══► arpc ──► Their Agent
              client       stateless router       client
```

---

## 1. Architecture & Design

### 1.1 Crate Decomposition

**Verdict: GOOD ✅**

The 3-crate split is the right call. `arp-common` cleanly owns the wire protocol and crypto primitives. The server knows nothing about encryption or contacts. The client knows nothing about routing tables. The dependency graph is clean: `arps` and `arpc` depend on `arp-common`, no cross-dependency. Each crate maps to a deployment artifact (two binaries + one library).

**NITPICK:** `base58.rs` in arp-common is only used by the client for display. The server never base58-encodes anything. It's not misplaced (it's a pubkey utility), but it's dead weight in the server binary (~80 LOC).

### 1.2 Wire Protocol

**Verdict: GOOD, with caveats ✅**

The custom binary TLV is the right choice over protobuf/flatbuffers/msgpack:
- Only 9 frame types, all fixed-layout — no schema evolution needed
- 33 bytes overhead vs ~50+ for protobuf with field tags
- `serialize_deliver()` zero-copy hot-path on relay is elegant — avoids full Frame parse/reserialize
- Relay is a dumb pipe; complex serialization frameworks add nothing

| Frame Category | Types | Purpose |
|----------------|-------|---------|
| Admission | CHALLENGE, RESPONSE, ADMITTED, REJECTED | Connection establishment |
| Data | ROUTE, DELIVER, STATUS | Message relay |
| Keepalive | PING, PONG | Connection health |

**MINOR — No length field.** Relies entirely on WebSocket framing for boundaries. This is fine *as long as ARP never needs to run over raw TCP*. The coupling to WebSocket framing is an implicit assumption worth documenting.

**MINOR — No version byte in frames.** Protocol evolution requires either a new frame type or WebSocket subprotocol negotiation (which is used — `arp.v2`). This works but is fragile if backward-compatible frame changes are needed.

**NITPICK — Optional PoW nonce detection is length-based.** `Frame::parse` for RESPONSE uses `if data.len() >= 113` to detect the optional nonce. Future RESPONSE extensions would be ambiguous. Acceptable given `arp.v2` gates the format.

### 1.3 Admission Handshake

**Verdict: SOUND ✅**

The challenge-response is cryptographically solid:

```
Server ──► CHALLENGE (32 random bytes + server_pubkey + difficulty)
Client ──► RESPONSE (Ed25519 sign(challenge ‖ timestamp) + optional PoW nonce)
Server ──► ADMITTED or REJECTED
```

- Server-generated 32-byte random challenge prevents client-chosen challenges
- Ed25519 signature over `challenge || timestamp` binds challenge to time
- ±30s timestamp tolerance is reasonable for clock skew
- LRU cache (10K) prevents challenge replay
- Pre-auth semaphore (1000) prevents resource exhaustion before admission

**No replay risk:** An attacker who intercepts a RESPONSE can't replay it because the challenge is server-generated and cached.

**No impersonation risk:** Without the Ed25519 private key, you can't sign the challenge.

**MINOR — Server pubkey not bound into signature.** The client signs `challenge || timestamp` but doesn't include `server_pubkey`. An identical challenge from two different servers (probabilistically impossible with 32 random bytes) would accept the same response. No practical risk, but binding `server_pubkey` into the signed message would be defense-in-depth.

**MINOR — Rejection reason codes unused.** The server sends `reason: 0x01` for all admission failures, despite `BAD_SIG`, `TIMESTAMP_EXPIRED`, `INVALID_POW` constants being defined. The client logs the reason code but can't distinguish failure modes.

### 1.4 Server Concurrency Model

**Verdict: CORRECT ✅**

- One tokio task per connection — standard pattern
- DashMap for routing — lock-free reads, sharded writes, right for high read:write ratio
- `remove_if` with `admitted_at` Instant — clever TOCTOU guard preventing slow disconnects from evicting new connections
- mpsc channels (256 cap) per connection — natural backpressure

**Race condition analysis:**

| Component | Mechanism | Verdict |
|-----------|-----------|---------|
| `active_connections` | `AtomicUsize` with `Relaxed` ordering | Safe — soft capacity limit, not security boundary |
| `ip_connections` | DashMap `entry()` API | Safe — atomic check-and-increment |
| `seen_challenges` | `Mutex<LruCache>` with poison recovery | Safe — not hot path, minimal contention |
| `Router::remove_if` | Checks `admitted_at` timestamp | Safe — prevents stale disconnect from evicting new connection |
| `IpGuard` TOCTOU | Decrement then `remove_if` with `*v == 0` guard | Safe — handles concurrent increment correctly |

**IMPORTANT — Protocol negotiation bug (latent).** In `connection.rs`, `proto_cell.set()` stores the *first* protocol the client offers, not the negotiated one. If a client sends `"arp.v3,arp.v2"`, proto_cell stores `"arp.v3"`, the server negotiates `arp.v2` in the WS header, then rejects the client because `"arp.v3" != "arp.v2"`. Current clients only send one protocol, so this is latent. **Fix: only `set()` proto_cell when the match is found.**

### 1.5 Client Channel Topology

**Verdict: WELL-DESIGNED ✅**

| Channel | Type | Direction | Purpose |
|---------|------|-----------|---------|
| `outbox` | mpsc(256) | Local API → Relay | Outbound messages |
| `inbox` | broadcast(1024) | Relay → API/Webhook/Bridge | Inbound fan-out |
| `status` | watch | Relay → All | Connection status (latest value) |
| `ack` | oneshot | Relay → API | Per-send STATUS correlation |

Each channel type is chosen for its semantics:
- **mpsc**: many producers (API connections), one consumer (relay task)
- **broadcast**: one producer (relay), many consumers (API subscribers, webhook, bridge)
- **watch**: "latest value" semantics for connection status — perfect fit
- **oneshot**: one-shot request-response for send acknowledgments

The `pending_acks` HashMap with VecDeque is a clean correlation mechanism. The 16-per-pubkey / 256-total limits prevent unbounded growth.

---

## 2. Over-Engineering Assessment

### 2.1 Is Anything Over-Engineered?

**NO ✅**

For a relay that handles admission, routing, rate limiting, metrics, encryption, contacts, webhooks, and a bridge — the codebase is remarkably lean. ~5,800 LOC for all of this is disciplined.

| Component | Assessment |
|-----------|------------|
| Rate limiter (sliding window VecDeque) | Simple and correct — needed |
| Prometheus metrics | Standard for production — needed |
| Config crate | Justified — handles TOML + env + CLI layering |
| RAII guards (IpGuard, RouteGuard) | Correct pattern — alternatives are worse |
| Proptest for frames | Valuable — catches serialization edge cases |
| Exponential backoff with jitter | Standard — not over-engineered |
| Contact store with atomic save | Appropriate — data loss prevention |

### 2.2 Is Anything Under-Engineered?

**A few areas:**

| Finding | Severity | Detail |
|---------|----------|--------|
| Self-update has no signature verification | **CRITICAL** | SHA-256 checksum only. Code has `TODO` acknowledging this. |
| `connection.rs` is 657 lines | **IMPORTANT** | Handles WS upgrade, IP extraction, Cloudflare validation, admission, AND message routing. Should split into `admission.rs` (server-side) and `message_loop.rs`. |
| No graceful shutdown for server | **MINOR** | Server accept loop runs forever. `SIGTERM` hard-kills in-flight connections. A `tokio::select!` with shutdown signal would enable draining. |
| Webhook has no retry | **MINOR** | Fire-and-forget is documented, but a single retry with backoff would improve reliability. |
| Bridge response interleaving | **MINOR** | After `chat.send`, bridge reads one WS message expecting the response. If gateway sends an unrelated event first, the response is consumed and the actual response is lost. |

### 2.3 RAII Guards

**Verdict: RIGHT PATTERN ✅**

`IpGuard` and `RouteGuard` guarantee cleanup via `Drop` on all exit paths (normal return, error, panic). The alternative — manual cleanup at every return point — is strictly worse and more error-prone.

---

## 3. First Principles Adherence

### 3.1 Zero Persistent State

**ADHERED ✅**

The server stores nothing on disk. Routing table is purely in-memory. Server restart = clean slate. Clients reconnect and re-admit.

### 3.2 Identity as Address

**ADHERED ✅**

Ed25519 pubkey IS the address. No registration, no usernames, no accounts. `DashMap<Pubkey, ConnHandle>` is literally identity→connection.

### 3.3 Operational Simplicity

**ADHERED ✅**

Single binary, config file optional (sane defaults), Prometheus for monitoring, systemd service file included. The Makefile has `deploy-server` with rollback.

### 3.4 Relay Opacity

**EXCEPTIONALLY CLEAN ✅**

The separation is the cleanest aspect of the design:

| | Relay Sees | Relay Does NOT See |
|---|---|---|
| **Data** | Pubkeys, frame types, payload sizes | Plaintext content, encryption details |
| **Logic** | Routing, rate limiting, admission | Contact filtering, HPKE, webhooks |

The server imports `arp_common::frame` and `arp_common::crypto` — never `hpke`, `contacts`, or anything client-specific. The `process_frame` function extracts `dest` from ROUTE, calls `serialize_deliver` which rewrites type byte + source pubkey without touching payload.

### 3.5 Principle of Least Surprise

**MOSTLY ✅, with violations:**

| Finding | Severity |
|---------|----------|
| HPKE info string `"arp-v1"` while wire protocol is `"arp.v2"` — version confusion | **MINOR** |
| Server config validates `pow_difficulty` max 32, client `MAX_CLIENT_POW_DIFFICULTY` is 24 — mismatch not warned | **MINOR** |
| App-level PING/PONG and WS-level pings coexist — app-level ones are unused | **MINOR** |

---

## 4. Tech Choices

### 4.1 `hpke` v0.12

**UPGRADE REQUIRED 🟡**

| Issue | Detail |
|-------|--------|
| Pinned to v0.12 | Avoids `rand_core` 0.9 conflict |
| v0.13.0 available | Has security improvements (PskBundle validation) |
| `curve25519-dalek` | Verify ≥ 4.1.3 for timing fix (RUSTSEC-2024-0344) |

The underlying algorithms (X25519-HKDF-SHA256, ChaCha20Poly1305) are identical between v0.12 and v0.13. No known vulnerabilities in v0.12. But the `rand_core` conflict should be resolved, not avoided.

**Recommendation:** Upgrade to `hpke = "0.13"`, resolve `rand_core` conflict by updating `ed25519-dalek` and `rand` to compatible versions. Verify `curve25519-dalek` ≥ 4.1.3.

### 4.2 DashMap v6

**RIGHT CHOICE ✅**

For this workload (many concurrent readers, infrequent writes), DashMap is ideal:
- `RwLock<HashMap>` — single-writer bottleneck on connection churn
- `flurry` — more complex, less maintained
- `papaya` — newer, less battle-tested
- DashMap `remove_if` API is essential for the TOCTOU guard

### 4.3 `config` Crate

**JUSTIFIED ✅**

Handles TOML + environment variable + CLI layering with minimal code. Hand-rolling this merge logic would be ~200+ lines of boilerplate.

### 4.4 `reqwest` (rustls-tls)

**ACCEPTABLE ⚠️**

Used for webhook delivery and self-update — both legitimate HTTP needs. Pulls significant dependencies, but:
- `ureq` would be simpler but blocking (needs `spawn_blocking`)
- `hyper` directly would be more code for same result
- Binary size impact is real but tolerable for a persistent daemon

### 4.5 Ed25519→X25519 Conversion

**CORRECT ✅**

Uses `to_montgomery()` for public key conversion and `to_scalar_bytes()` (clamped scalar) for private key. This is the standard birational map approach.

Two Ed25519 keys differing by negation map to the same X25519 key, but finding the twin requires a discrete log. No practical risk. Domain separation exists: admission uses `Ed25519(challenge ‖ timestamp)`, HPKE uses `info = "arp-v1"`.

### 4.6 SHA-256 Hashcash PoW

**ADEQUATE FOR NOW ⚠️**

SHA-256 hashcash is becoming marginal due to GPU/ASIC acceleration. For ARP's use case (secondary defense behind the admission handshake), it's acceptable. If anti-spam becomes critical, consider Equi-X (ASIC-resistant, used by Tor).

| Algorithm | GPU Resistance | Status |
|-----------|---------------|--------|
| SHA-256 | Low | Current — adequate |
| Equi-X | High | Consider for future |
| Argon2 | High | Overkill for connection admission |

---

## 5. Security Findings

### CRITICAL (1)

| # | Finding | Location | Impact |
|---|---------|----------|--------|
| S1 | **Self-update: no Ed25519 signature verification** | `update.rs` | SHA-256 only verifies integrity, not authenticity. Compromised release or CDN MITM → malicious binary. Code has `// TODO: Ed25519 signature`. |

### IMPORTANT (6)

| # | Finding | Location | Impact |
|---|---------|----------|--------|
| S2 | **Protocol negotiation bug (latent)** | `connection.rs` | `proto_cell.set()` stores first offered protocol, not negotiated one. Will break when v3 ships. |
| S3 | **`hpke` v0.12 outdated** | `Cargo.toml` | Missing security improvements in v0.13. Potential `curve25519-dalek` timing issue. |
| S4 | **No PoW-enabled integration test** | tests | PoW is unit-tested but never exercised end-to-end. All integration tests use `pow_difficulty: 0`. |
| S5 | **Hardcoded Cloudflare IPs** | `connection.rs` | ~80 lines of manual CIDR ranges. These change over time. Maintenance burden and potential trust bypass. |
| S6 | **`keypair.rs` Unix-only** | `keypair.rs` | Uses `std::os::unix::fs::PermissionsExt` unconditionally. Won't compile on Windows. Needs `#[cfg(unix)]` gate. |
| S7 | **`connection.rs` is 657 lines** | `connection.rs` | Handles WS upgrade, IP extraction, Cloudflare validation, admission, AND message routing. Too many concerns. |

### MINOR (14)

| # | Finding | Location |
|---|---------|----------|
| S8 | `Relaxed` ordering on `active_connections` — soft limit can be exceeded by ~concurrent-tasks count | `server.rs` |
| S9 | HPKE info string `"arp-v1"` vs protocol `"arp.v2"` — version confusion | `hpke_seal.rs` |
| S10 | PoW difficulty mismatch: server max 32, client max 24 — no clear error | config |
| S11 | `std::sync::RwLock` in async context (`ContactStore`) — can block executor | `contacts.rs` |
| S12 | SHA-256 hashcash becoming marginal against GPU/ASIC | `crypto.rs` |
| S13 | No graceful shutdown for server — SIGTERM hard-kills | `server.rs` |
| S14 | Bridge response interleaving with gateway events | `bridge.rs` |
| S15 | Rejection reason codes unused — always sends `0x01` | `connection.rs` |
| S16 | Server pubkey not bound into admission signature | `crypto.rs` |
| S17 | Double allocation on relay hot path (parse + serialize_deliver) | `connection.rs` |
| S18 | Ack queue overflow produces misleading "connection lost" error | `relay.rs` |
| S19 | App-level PING/PONG unused — WS pings handle keepalive | `frame.rs` |
| S20 | No bridge tests | `bridge.rs` |
| S21 | No relay reconnection/backoff tests | `relay.rs` |

### NITPICK (4)

| # | Finding | Location |
|---|---------|----------|
| S22 | `Router::is_full()` dead code — unused | `router.rs` |
| S23 | Enable `zeroize` feature on ed25519-dalek | `Cargo.toml` |
| S24 | `base58` in arp-common unused by server binary | `base58.rs` |
| S25 | RESPONSE frame optional nonce detection is length-based | `frame.rs` |

---

## 6. Code Quality

### 6.1 Hot Path Performance

**GOOD ✅**

The relay hot path (`process_frame` → `serialize_deliver`) is well-optimized:
- `serialize_deliver()` avoids Frame allocation — constructs wire bytes directly
- DashMap lookup is lock-free for reads
- mpsc send is non-blocking (`try_send` with capacity check)
- Rate limiter prunes expired entries efficiently

**MINOR:** Every relayed message allocates two `Vec<u8>` — one from `Frame::parse()` for payload extraction, another from `serialize_deliver()`. A zero-copy fast path could extract `dest` and `payload` directly from raw bytes, eliminating one allocation:

```rust
// Instead of Frame::parse → pattern match → serialize_deliver:
let dest: &[u8; 32] = &data[1..33];
let payload: &[u8] = &data[33..];
let deliver = Frame::serialize_deliver(src, payload);
```

### 6.2 Test Coverage

| Area | Coverage | Notes |
|------|----------|-------|
| Frame serialization | ✅ Excellent | Proptest round-trip + manual tests |
| Crypto (sign/verify/PoW) | ✅ Good | Unit tests for all paths |
| Base58 | ✅ Good | Round-trip + edge cases |
| Config validation | ✅ Good | Comprehensive validation tests |
| Contacts | ✅ Good | CRUD + filter tests |
| E2E integration | ✅ Good | 2 agents, concurrent, disconnect, replace |
| Rate limiting, admission | ✅ Good | Timeout, invalid sig, rate limit tests |
| HPKE seal/open | ⚠️ Basic | Round-trip exists, no cross-version compatibility |
| PoW with difficulty > 0 | ⚠️ Missing | All integration tests use `pow_difficulty: 0` |
| Local API | ❌ Missing | No test for API commands |
| Relay reconnection | ❌ Missing | No test for backoff/reconnect behavior |
| Bridge | ❌ Missing | No test for OpenClaw bridge |

### 6.3 Error Handling

**CLEAN ✅**

| Crate | Pattern | Verdict |
|-------|---------|---------|
| arp-common | `FrameError`, `ClockError`, `PowError` — typed errors | Good |
| arps | `ArpsError` (thiserror) — errors close connections | Good |
| arpc | `RelayError::Fatal` vs `Transient` — drives reconnection | Good |
| arpc | `BridgeError::Fatal` vs `Transient` — same clean pattern | Good |

No empty catch blocks. No swallowed errors. One gap: `broadcast::send` errors in relay are logged but messages silently dropped if all receivers gone — correct behavior (no subscribers = no delivery).

**MINOR:** `pending_acks` overflow: when per-dest queue (16) overflows, oldest oneshot is dropped. Sender receives `RecvError` mapped to "relay connection lost" — misleading since the connection is fine.

---

## 7. Data Flow Summary

### Send Path

```
Agent ──JSON──► local_api ──mpsc──► relay ──HPKE seal──► Frame::route ──WSS──► arps
                                                                                │
                                                                    serialize_deliver
                                                                                │
arps ──WSS──► relay ──Frame::parse──► HPKE open──► contact filter──► broadcast──►
    │              │                │
    ▼              ▼                ▼
 local_api      webhook          bridge
 (recv/sub)     (HTTP POST)    (OpenClaw)
```

### Connection Lifecycle

```
Disconnected → Connecting → [TCP+TLS+WS upgrade] → [Challenge-Response] → Connected
     ▲                                                                        │
     │                    Transient error → backoff.next_delay()               │
     └────────────────────────────────────────────────────────────────────────┘
                          Fatal error → break (daemon may exit)
```

### State Ownership

| State | Type | Owner | Thread-Safe |
|-------|------|-------|-------------|
| Keypair | `SigningKey` | Moved to relay task | Single-owner |
| Contacts | `Arc<ContactStore>` | Shared | `RwLock` internally |
| Config | `Arc<ClientConfig>` | Shared | Immutable after load |
| Connection status | `watch::Receiver<ConnStatus>` | Shared | Tokio watch |
| Outbox | `mpsc::Sender<OutboundMsg>` | local_api → relay | Tokio mpsc |
| Inbox | `broadcast::Sender<InboundMsg>` | relay → consumers | Tokio broadcast |
| Pending acks | `HashMap<Pubkey, VecDeque<oneshot::Sender>>` | relay (task-local) | Single-threaded |
| Routing table | `DashMap<Pubkey, ConnHandle>` | Server shared | Lock-free sharded |

---

## 8. Dependency Security

| Dependency | Version | Status | Notes |
|------------|---------|--------|-------|
| ed25519-dalek | 2.x | **SAFE** | CVE-2022-50237 is v1.x only |
| hpke (rozbb) | 0.12 | **SAFE** (upgrade recommended) | Not `hpke-rs` — no GHSA-g433 |
| curve25519-dalek | transitive | **VERIFY** | Check ≥ 4.1.3 for RUSTSEC-2024-0344 |
| dashmap | 6 | **SAFE** | RUSTSEC-2022-0002 fixed in 5.1.0+ |
| tokio-tungstenite | 0.24 | **SAFE** | RUSTSEC-2023-0053 fixed in 0.20.1+ |
| reqwest (rustls-tls) | 0.12 | **SAFE** | No known CVEs |
| rand | 0.8 | **SAFE** | Consistent across workspace |

**Recommended upgrades:**

```toml
hpke = { version = "0.13", features = ["x25519", "chacha"] }
ed25519-dalek = { version = "2.2", features = ["zeroize", "rand_core"] }
tokio-tungstenite = { version = "0.28", features = ["rustls-tls-webpki-roots"] }
```

---

## 9. Action Items (Priority Order)

### Phase 1: Immediate

| # | Finding | Effort | Action |
|---|---------|--------|--------|
| S1 | Self-update signature verification | 1-2d | Embed Ed25519 release pubkey, sign in CI, verify `.sig` |
| S2 | Protocol negotiation bug | <1h | Fix `proto_cell.set()` to store matched protocol |
| S3 | Upgrade hpke to v0.13 | 2-4h | Resolve `rand_core` conflict, verify curve25519-dalek |

### Phase 2: Short-term

| # | Finding | Effort | Action |
|---|---------|--------|--------|
| S4 | PoW integration test | <1h | Add test with `pow_difficulty > 0` |
| S5 | Cloudflare IPs | 2-4h | Externalize or add periodic refresh |
| S6 | Windows compilation | <1h | `#[cfg(unix)]` gate on `PermissionsExt` |
| S7 | Split connection.rs | 2-4h | Extract admission + message loop |

### Phase 3: Maintenance

| # | Finding | Effort | Action |
|---|---------|--------|--------|
| S9 | Version string alignment | <1h | Align `arp-v1` / `arp.v2` or document |
| S10 | PoW difficulty mismatch | <1h | Client-side error when difficulty > 24 |
| S13 | Graceful shutdown | 1-2h | `tokio::select!` with shutdown signal |
| S15 | Rejection reason codes | <1h | Use specific reason constants |
| S17 | Hot path double allocation | <1h | Zero-copy dest/payload extraction |

### Phase 4: Polish

| # | Finding | Effort | Action |
|---|---------|--------|--------|
| S18 | Ack overflow error message | <1h | Distinguish from connection loss |
| S19 | Remove unused PING/PONG | <1h | Or document rationale for keeping |
| S20-21 | Missing tests | 2-4h | Bridge mock, reconnection test |
| S22-25 | Nitpicks | <1h each | Dead code, zeroize, etc. |

---

## 10. Audit Methodology

### Sources

| Agent | Type | Duration | Contribution |
|-------|------|----------|--------------|
| Direct review | Manual file reads | — | All 27 source files + infrastructure |
| Oracle | Deep architectural analysis | ~25min | 23 audit questions, protocol bug discovery |
| Librarian | External security research | ~4min | HPKE/Ed25519/PoW best practices, CVE research |
| Explore (×4) | Codebase mapping | ~4min each | arp-common, arps, arpc, config/CI/testing |

### Files Reviewed

**arp-common** (`crates/arp-common/src/`): `lib.rs`, `types.rs`, `frame.rs`, `crypto.rs`, `base58.rs`

**arps** (`crates/arps/src/`): `main.rs`, `lib.rs`, `server.rs`, `connection.rs`, `router.rs`, `admission.rs`, `ratelimit.rs`, `metrics.rs`, `error.rs`, `config.rs`

**arpc** (`crates/arpc/src/`): `main.rs`, `lib.rs`, `config.rs`, `relay.rs`, `hpke_seal.rs`, `local_api.rs`, `contacts.rs`, `webhook.rs`, `bridge.rs`, `backoff.rs`, `keypair.rs`, `update.rs`

**Infrastructure**: `Cargo.toml`, `Makefile`, `deny.toml`, `clippy.toml`, `ARCHITECTURE.md`, `whitepaper.md`

### Verification

```
cargo test --workspace:    192/192 passed
cargo clippy:              0 warnings
```

---

*Report generated: February 24, 2026*
*Auditor: Sisyphus AI Agent (Ultrawork Mode)*
*All source files reviewed. All 192 tests verified passing.*
