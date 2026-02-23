# Contributing to ARP

Contributions are welcome! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/offgrid-ing/arp.git
cd arp
cargo test --workspace
```

## Before Submitting a PR

1. **Format**: `cargo fmt --all`
2. **Lint**: `cargo clippy --workspace --all-targets -- -D warnings`
3. **Test**: `cargo test --workspace`
4. **Audit**: `cargo deny check` (if you modified dependencies)

All four checks must pass. CI enforces this.

## Code Style

- Follow existing patterns in the codebase
- All crates use `#![forbid(unsafe_code)]` — no exceptions
- Add tests for new functionality
- Keep commits atomic and well-described

## What to Contribute

- Bug fixes
- Test coverage improvements
- Documentation improvements
- Protocol enhancements (discuss in an issue first)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
