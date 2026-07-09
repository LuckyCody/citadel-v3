# Security Policy

## Current Status

**Citadel is unaudited software.**

The implementation:
- Uses NIST-standardized primitives (ML-KEM-768, AES-256-GCM, HKDF-SHA256)
- Follows established hybrid construction patterns (X25519 + ML-KEM)
- Has comprehensive test coverage including fuzz testing
- Has NOT undergone independent security audit

## Supported Versions

| Version | Support Status |
|---------|---------------|
| 0.1.x   | Active (security fixes) |
| < 0.1   | Unsupported |

Only the latest release receives security fixes.

## Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

### Preferred: GitHub Security Advisory

1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Provide details (see below)

### Alternative: Direct Contact

Email: andre.cordero36@gmail.com

PGP key available at: [keyserver-link]

### What to Include

- Affected versions / commit hash
- Minimal reproduction case
- Expected vs. actual behavior
- Impact assessment
- Whether timing side-channels or DoS is involved

### Response Timeline

| Severity | Initial Response | Target Fix |
|----------|-----------------|------------|
| Critical | 24 hours | 72 hours |
| High     | 48 hours | 1 week |
| Medium   | 1 week | 2 weeks |
| Low      | 2 weeks | Next release |

## Scope

### In Scope

- **Memory safety** — parsing panics, buffer overflows, use-after-free
- **Cryptographic correctness** — wrong outputs, key leakage, nonce reuse
- **Oracle behavior** — distinguishable errors that leak information
- **Misuse resistance failures** — accepting malformed inputs, downgrade attacks
- **Key handling bugs** — missing zeroization, accidental exposure
- **Wire format vulnerabilities** — version confusion, suite downgrade

### Out of Scope

- Key management, access control, or compliance certification
- Platform-level compromise (OS, hardware)
- Side-channel attacks requiring physical access
- Denial of service via large inputs (documented limitation)
- Issues in dependencies (report upstream, notify us)

## Security Guarantees

### What We Guarantee

1. **Hybrid security** — if either X25519 or ML-KEM-768 remains secure, plaintext is protected
2. **AAD/context binding** — wrong AAD or context causes decryption failure
3. **Tampering detection** — any modification to ciphertext causes failure
4. **Uniform errors** — all decryption failures produce identical error type
5. **Wire format stability** — v1 format will always be decodable

### What We Do NOT Guarantee

1. **Constant-time execution** — inherited from dependencies, not verified
2. **Side-channel resistance** — not tested against power/EM/timing attacks
3. **FIPS compliance** — uses NIST primitives, not a certified module
4. **Performance** — optimized for correctness, not speed

## Dependency Security

Citadel depends on:

| Crate | Purpose | Maintainer |
|-------|---------|-----------|
| `ml-kem` | Post-quantum KEM | RustCrypto |
| `x25519-dalek` | Classical ECDH | Dalek |
| `aes-gcm` | Symmetric encryption | RustCrypto |
| `hkdf` | Key derivation | RustCrypto |
| `sha2`, `sha3` | Hash functions | RustCrypto |
| `zeroize` | Secure memory clearing | RustCrypto |
| `subtle` | Constant-time operations | Dalek |

We track security advisories for all dependencies via `cargo audit`.

### ml-kem audit status

The `ml-kem` crate (pinned to `=0.2.2`) carries an **experimental** designation in its own README and has not received an independent security audit. It implements FIPS 203 (ML-KEM / Kyber), a finalized NIST standard, but the *implementation* has not been reviewed for constant-time properties, side-channel resistance, or correctness beyond the RustCrypto team's own testing.

**What this means in practice:**
- The mathematical construction (ML-KEM-768 + X25519 hybrid) is sound.
- The specific Rust implementation may contain implementation-level defects that an audit would catch.
- The version is exact-pinned (`=0.2.2`); any upgrade is an explicit, reviewed decision — `cargo update` will not silently pull a new patch version.

If your deployment requires audited PQ-KEM, track the [RustCrypto audit schedule](https://github.com/RustCrypto/KEMs) or evaluate a FIPS-validated commercial alternative. This constraint will be re-evaluated as the RustCrypto ecosystem matures.

### Build toolchain requirement

**Minimum build toolchain: Rust / Cargo 1.81+**

The `ml-kem` dependency chain transitively pulls `crypto-common 0.2.x` which uses
`edition = "2024"`. Cargo versions prior to 1.85 cannot parse edition-2024 manifests
at the registry level, even for crates that are not ultimately selected in the build.

This means:
- `cargo build` on Rust 1.75 (Ubuntu 24.04 LTS `apt`) fails at dependency resolution
- Use `rustup toolchain install stable` to get a current toolchain (1.85+ as of 2026)
- Docker builds using the official `rust:latest` image work correctly
- The **runtime** has no toolchain dependency — only the build does

## Upgrade Policy

### Minor Versions (0.1.x → 0.1.y)

- Bug fixes and security patches
- No breaking API changes
- Wire format compatible
- Safe to upgrade immediately

### Major Versions (0.x → 0.y before 1.0)

- May include breaking changes
- Migration guide provided
- Old versions supported for 6 months
- Announce 30 days before release

### Post-1.0 Policy

- Semantic versioning strictly followed
- LTS versions designated annually
- Security fixes backported to LTS

## Deprecation Process

1. **Announcement** — deprecated feature marked in docs
2. **Warning** — compile-time warning for 2 releases
3. **Removal** — removed in next major version

## Incident Response

If a critical vulnerability is discovered:

1. **Immediate** — assess scope and impact
2. **24 hours** — develop patch, prepare advisory
3. **48 hours** — release patched version
4. **72 hours** — publish security advisory
5. **1 week** — post-mortem published

## Cryptographic Agility

The wire format includes suite identifiers to support future algorithms:

- New KEM suites can be added (different `suite_kem` byte)
- New AEAD suites can be added (different `suite_aead` byte)
- Old suites remain decodable (no silent downgrades)

Migration path for algorithm updates:

1. New version supports both old and new suites
2. Encrypt with new suite, decrypt both
3. Re-encrypt legacy data during maintenance window
4. Eventually deprecate old suite

## Audit Status

| Component | Last Review | Reviewer |
|-----------|-------------|----------|
| Wire format | Internal | — |
| KDF construction | Internal | — |
| Error handling | Internal | — |
| Fuzz testing | Ongoing | libFuzzer |

**No independent audit has been conducted.**

If you require audited cryptography, consider:
- AWS Encryption SDK
- Google Tink
- libsodium

## Contact

- **Security issues**: andre.cordero36@gmail.com
- **General questions**: GitHub Discussions
- **Commercial support**: andre.cordero36@outlook.com
