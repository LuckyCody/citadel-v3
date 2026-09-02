# SDK Integration Guide

This document explains how to integrate Citadel V3 into your application or existing codebase.

> **Note:** This guide was written before the five-crate workspace structure. The standalone
> `citadel.rs` CLI artifact (keygen/seal/open) referenced below **no longer exists**. The
> production CLI is `citadel-cli/src/main.rs` built as `citadel` binary via the workspace.

## Current workspace structure

```
citadel_v3/
├── citadel-core/       # StateEnforcer — runtime lifecycle/authorization enforcement (layer 1)
├── citadel-envelope/   # Hybrid KEM + wire format (suites 0xA3/0xA4 + AES-256-GCM)
├── citadel-signer/     # ML-DSA-65 signing + CitadelAssertion (CNA) format
├── citadel-keystore/   # Key lifecycle, hierarchy, replay, audit
├── citadel-api/        # Axum REST API (port 8443)
├── citadel-cli/        # CLI: key, migrate, doctor, audit, backup, replay commands
├── citadel-ffi/        # C/Java/Python FFI layer
└── deploy/             # systemd, docker, kubernetes templates
```

## Building the CLI

```bash
# Debug build
cargo build -p citadel-cli

# Release build with Redis support
cargo build -p citadel-cli --release --features redis-backend

# The binary lands at:
target/release/citadel
```

## SDK integration (citadel-envelope)

To embed the hybrid KEM envelope in your own crate:

```toml
[dependencies]
citadel-envelope = { path = "../citadel-envelope" }
```

```rust
use citadel_envelope::{Citadel, Aad, Context};

let citadel = Citadel::new();
let (pk, sk) = citadel.generate_keypair();
let aad = Aad::for_database("users", "row-123", "ssn");
let ctx = Context::for_application("myapp", "prod");

let ct = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();
let pt = citadel.open(&sk, &ct, &aad, &ctx).unwrap();
```

## API integration

See `citadel_example.py` for a complete Python integration example including
AAD binding, key rotation, and threat-aware behavior.

## Questions?

If you hit integration issues, the most common problems are:
- Missing `use` statements for the new types
- Feature flags not enabled for the CLI
- Path mismatches in `Cargo.toml`

See [SECURITY.md](SECURITY.md) for vulnerability reporting and [SUPPORT.md](SUPPORT.md) for support tiers.
