# SDK Integration Guide

This document explains how to integrate Citadel V3 into your application or existing codebase.

> **Note:** This guide was written before the five-crate workspace structure. The standalone
> `citadel.rs` CLI artifact (keygen/seal/open) referenced below **no longer exists**. The
> production CLI is `citadel-cli/src/main.rs` built as `citadel` binary via the workspace.

## Current workspace structure

```
citadel_v3/
├── citadel-envelope/   # Hybrid KEM + wire format (X25519 + ML-KEM-768 + AES-256-GCM)
├── citadel-keystore/   # Key lifecycle, hierarchy, replay, audit
├── citadel-api/        # Axum REST API (port 3000 dev / 8443 prod)
├── citadel-cli/        # CLI: key, migrate, doctor, backup, replay commands
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

## Files in this directory (original SDK artifacts — superseded)

```
citadel-sdk/
├── sdk.rs              # Superseded by citadel-envelope/src/sdk.rs
├── lib_updated.rs      # Superseded by citadel-envelope/src/lib.rs
├── Cargo_updated.toml  # Superseded by workspace Cargo.toml
├── README.md           # Superseded by root README.md
├── SECURITY.md         # Superseded by root SECURITY.md
├── SUPPORT.md          # Active — commercial support tiers
├── API_FREEZE.md       # Active — stability contract
└── OPEN_CORE_DECISION.md  # Active — business model
```

# Build CLI
cargo build --features cli

# Test CLI
./target/debug/citadel --help
./target/debug/citadel keygen --output /tmp/keys
./target/debug/citadel seal --key /tmp/keys/public.key \
    --aad "test" --context "test" \
    --input secret.txt --output secret.enc
./target/debug/citadel inspect secret.enc
```

## What Changes for Existing Code

### Breaking Changes (Minor)

The SDK introduces typed `Aad` and `Context` wrappers. Existing code using raw bytes:

```rust
// Before
citadel.encrypt(&pk, b"data", b"aad", b"ctx")?;

// After
citadel.seal(&pk, b"data", &Aad::raw(b"aad"), &Context::raw(b"ctx"))?;
```

### Backward Compatibility

The old `CitadelMlKem768` type is still available but deprecated:

```rust
#[deprecated(since = "0.1.0", note = "use Citadel instead")]
pub type CitadelMlKem768 = ...;
```

Existing code will compile with warnings.

## Publishing to crates.io

### Pre-flight checklist

```bash
# 1. Run all tests
cargo test --all-features

# 2. Check docs build
cargo doc --no-deps

# 3. Check package
cargo package --list

# 4. Dry run publish
cargo publish --dry-run
```

### Publish

```bash
cargo publish
```

### Post-publish

1. Tag the release: `git tag v0.1.0 && git push --tags`
2. Create GitHub release with changelog
3. Announce on relevant channels

## Next Steps

1. **Fill in placeholders** — Replace `[your-email]`, `[sales-email]`, etc.
2. **Create GitHub repo** — `mrcord77/rust_citadel`
3. **Set up CI** — GitHub Actions for tests + cargo audit
4. **Write CHANGELOG.md** — Document the 0.1.0 release

## Questions?

The SDK is designed to be a drop-in addition. Your existing tests should pass unchanged once the module paths are updated.

If you hit issues, the most common problems are:
- Missing `use` statements for the new types
- Feature flags not enabled for CLI
- Path mismatches in Cargo.toml
