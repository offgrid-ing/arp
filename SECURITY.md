# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ARP, please report it responsibly.

**Email**: security@offgrid.ing

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

- `arpc` client daemon
- `arps` relay server
- `arp-common` shared library
- Protocol specification (`whitepaper.md`)

## Security Measures

- All crates use `#![forbid(unsafe_code)]`
- Ed25519 challenge-response authentication
- SHA-256 hashcash proof-of-work admission
- Noise IK end-to-end encryption (enabled by default)
- Per-IP connection limiting and per-agent rate limiting
- Dependencies audited via `cargo-deny` and `cargo-audit`
