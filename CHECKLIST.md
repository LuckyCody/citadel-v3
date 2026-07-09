# Citadel Envelope v1 - Verification Checklist

Run these checks before considering the implementation "repaired".

## Phase A: Documentation Alignment

- [x] README does NOT say "production-ready"
- [x] README clarifies constant-time is "inherited from dependencies"
- [x] SPEC wire format == wire.rs (both use 6-byte header with suite IDs)
- [x] SPEC KDF == kdf.rs (no roles, PROTOCOL_ID || "|aes|" || ct_hash || context)
- [x] SPEC KAT strategy is envelope-only (no ciphertext byte equality)
- [x] No role separation language (deferred to future)
- [x] MIGRATION.md explains Python vs Rust incompatibility
- [x] All docs reference hybrid X25519 + ML-KEM-768 (matches implementation)

## Phase B: Code Verification

Run these commands after `cargo build`:

```bash
# 1. No panics in attacker-reachable paths
rg "unwrap\(|expect\(|assert!\(" src
# Should return empty (all paths use Result)

# 2. Compile without warnings
cargo build --all-features 2>&1 | grep -i warning

# 3. Run all tests
cargo test

# 4. Run tests with kat feature
cargo test --features kat
```

## Phase C: Test Coverage Verification

The following invariants must be tested in `tests/kat.rs`:

- [x] Header field invariants (version=0x01, suite_kem=0xA3, suite_aead=0xB1, flags=0x00, kem_ct_len=1120)
- [x] Encrypt → decrypt roundtrip succeeds
- [x] Wrong AAD fails with DecryptionError
- [x] Wrong context fails with DecryptionError
- [x] Bit-flip in KEM region fails with DecryptionError
- [x] Bit-flip in nonce fails with DecryptionError
- [x] Bit-flip in AEAD region fails with DecryptionError
- [x] Header mutation (version) fails with DecryptionError
- [x] Header mutation (suite) fails with DecryptionError
- [x] Truncation fails with DecryptionError
- [x] All errors produce identical DecryptionError (uniform)
- [x] Error message is opaque ("decryption failed")

## Phase D: Hardening

### Hybrid KEM
- [x] X25519 ECDH via `x25519-dalek` (classical security)
- [x] ML-KEM-768 via `ml-kem` crate (post-quantum security)
- [x] Combined shared secret: x25519_ss[32] || mlkem_ss[32] fed to HKDF
- [x] Wire format carries x25519_ephemeral_pk[32] || mlkem_ct[1088]

### Zeroization
- [x] Combined shared secret wrapped in `Zeroizing<Vec<u8>>` in encrypt
- [x] Combined shared secret wrapped in `Zeroizing<Vec<u8>>` in decrypt
- [x] AES key wrapped in `Zeroizing<[u8;32]>` in encrypt
- [x] AES key wrapped in `Zeroizing<[u8;32]>` in decrypt

### Error Discipline
- [x] Encrypt path returns `EncodingError` (nonce, AEAD seal, wire encode)
- [x] Decrypt path returns `DecryptionError` (uniform, opaque)
- [x] No bidirectional error conversion between EncodingError/DecryptionError
- [x] `From<EncodingError> for DecryptionError` only (one direction, for oracle discipline)

### Fuzz Targets
- [x] `fuzz/fuzz_targets/decode_wire.rs` - tests wire parsing
- [x] `fuzz/fuzz_targets/decrypt_full.rs` - tests full decrypt path

Run fuzz tests:
```bash
cd fuzz
rustup override set nightly
cargo fuzz run decode_wire -- -runs=10000
cargo fuzz run decrypt_full -- -runs=10000
```

### Timing Benchmarks
- [x] `benches/timing.rs` - compares valid vs error paths

Run benchmarks:
```bash
cargo bench --bench timing
```

Check for large timing cliffs between:
- valid decrypt
- wrong_aad (AEAD failure)
- wrong_context (key derivation changes)
- tampered_aead
- invalid_header / truncated (early rejection)

## Phase E: Final Verification Matrix

| File | Wire Format | KDF | Hybrid KEM | Errors | Zeroization | Status |
|------|-------------|-----|------------|--------|-------------|--------|
| SPEC.md | 6-byte header, suite 0xA3 | Combined SS | X25519 + ML-KEM | N/A | N/A | ✓ |
| wire.rs | 6-byte header, suite 0xA3 | N/A | 1120-byte KEM CT | EncodingError | N/A | ✓ |
| kem.rs | N/A | N/A | X25519 + ML-KEM | Both types | N/A | ✓ |
| kdf.rs | N/A | No roles | N/A | EncodingError | N/A | ✓ |
| aead.rs | N/A | N/A | N/A | Seal→Encoding, Open→Decryption | N/A | ✓ |
| lib.rs | Uses wire.rs | Uses kdf.rs | Uses kem.rs | Both types | ✓ SS + AES key | ✓ |
| error.rs | N/A | N/A | N/A | One-way From only | N/A | ✓ |

## Summary of All Repairs Applied

1. **Hybrid KEM**: X25519 + ML-KEM-768 — security holds if either primitive remains secure
2. **Wire format**: Suite 0xA3 (hybrid), kem_ct_len=1120 (32 X25519 + 1088 ML-KEM)
3. **KDF**: Combined 64-byte shared secret (x25519_ss || mlkem_ss) → HKDF-SHA256
4. **Error semantics**: Encrypt path → EncodingError, decrypt path → DecryptionError (no bidirectional conversion)
5. **Zeroization**: Shared secrets and AES keys wrapped in `Zeroizing<>` in encrypt/decrypt
6. **Version**: 0.1.0 (honest pre-audit versioning)
7. **Panics**: All public APIs return Result, no unwrap/expect/assert in attacker paths
8. **KATs**: Envelope-only tests, no ciphertext byte equality requirements
9. **Fuzzing**: Two fuzz targets for wire parsing and full decryption
10. **Timing**: Benchmark suite comparing valid vs error path timing

## What This Is

An **unaudited Rust envelope foundation** suitable for:
- Further hardening
- Fuzzing campaigns
- Internal tooling
- Consulting IP / R&D base
- Potential future audit

## What This Is NOT

- Production-ready (not audited)
- Verified constant-time (depends on dependencies)
- Wire-compatible with Python prototype
