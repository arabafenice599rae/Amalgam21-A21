# Amalgam21 Token (A21)

**A proprietary post-quantum digital token.**

[![CI](https://github.com/arabafenice599rae/Amalgam21-A21/actions/workflows/ci.yml/badge.svg)](https://github.com/arabafenice599rae/Amalgam21-A21/actions/workflows/ci.yml)
[![Made with Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org)
[![Audit](https://img.shields.io/badge/cargo--audit-passing-brightgreen)](https://github.com/rustsec/rustsec)

---

## Overview

Amalgam21 (A21) is a post-quantum digital ledger with the following core properties:

- **Signatures** — ML-DSA-65 (FIPS 204, NIST security level 3)
- **Hashing** — SHAKE256 at 512-bit output
- **Ledger** — authoritative, single-signer consensus
- **Wallet** — non-custodial, encrypted with Argon2id key derivation + XChaCha20-Poly1305 AEAD

## Workspace Structure

| Crate | Purpose |
|-------|---------|
| `core/` (`token-postquantum`) | The token core: binary formats, wallet, accounts, blocks, anchor, journal, and an ERC-20-like facade, plus an end-to-end interactive demo |
| `export/` (`token-postquantum-export`) | Derived, non-authoritative views for explorers and indexers: JSON balance snapshots and a JSONL block index |

## Getting Started

### Prerequisites

- Rust (stable toolchain)

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Run the Demo

```bash
cargo run -p token-postquantum   # interactive demo (passphrase via prompt)
```

## Continuous Integration

Every push and pull request runs five independent checks:

| Check | Description |
|-------|-------------|
| `cargo fmt --check` | Consistent code formatting |
| `cargo clippy -D warnings` | Zero lints; every warning is an error |
| Build | Clean compilation of the full workspace |
| Tests | Full test suite |
| `cargo audit` | No known vulnerabilities in dependencies |

Each check runs as a separate job: the failure of one check never hides the outcome of the others.

## Token Model

| Property | Value |
|----------|-------|
| Total supply | 100,000,000 A21 |
| Decimals | 6 |
| Amount representation | Integer `u64` units — floating point is never used |
| Fees | Fixed integer fee to the system account |
| Cashback | 90% of fees, paid from a dedicated pool |
| Binary formats | Unchanged since v0.8 |

Security declarations and known limitations are documented in the source file headers.

## License

Copyright Amalgam21. All rights reserved. No license of use is granted.
