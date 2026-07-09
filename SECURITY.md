# Security Policy

## Current Status

**Citadel is unaudited software.**

The implementation:
- Uses NIST-standardized primitives (ML-KEM-768, AES-256-GCM, HKDF-SHA256, X25519)
- Follows established hybrid construction patterns (X25519 + ML-KEM-768)
- Has comprehensive test coverage (328+ tests) including fuzz testing and ACVP KAT vectors
- Has dudect-based timing validation covering all attacker-controlled-input classes
- Has NOT undergone independent security audit

## Supported Versions

| Version | Support Status |
|---------|---------------|
| 0.2.x   | Active (security fixes) |
| < 0.2   | Unsupported |

Only the latest release receives security fixes.

## Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

### Preferred: GitHub Security Advisory

1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Provide details (see below)

### Alternative: Direct Contact

Email: andre.cordero36@gmail.com

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
- Side-channel attacks requiring physical access or co-residency
- Denial of service via large inputs (documented limitation)
- Issues in dependencies (report upstream, notify us)

## Security Guarantees

### What We Guarantee

1. **Hybrid security** — if either X25519 or ML-KEM-768 remains secure, plaintext is protected
2. **AAD/context binding** — wrong AAD or context causes decryption failure
3. **Tampering detection** — any modification to ciphertext causes failure
4. **Uniform errors** — all decryption failures produce identical error type
5. **Wire format stability** — v1 format will always be decodable
6. **Attacker-controlled-input timing** — dudect validation passes for all classes where the attacker varies the input (ciphertext, tag, AAD, KEM bytes)

### What We Do NOT Guarantee

1. **Key-material timing independence** — ML-KEM-768 decapsulation shows key-value-dependent timing on tested x86-64 hardware, reproduced across three independently developed providers (PQClean, libcrux, AWS-LC). This is a platform-level effect (Hertzbleed-class), not a code defect. See `TIMING.md` for the full finding and required wording.
2. **Side-channel resistance** — not tested against power/EM/cache attacks beyond dudect
3. **FIPS compliance** — uses NIST primitives, not a certified module
4. **Constant-time validation** — source code follows CT discipline, but hardware data-dependent execution is unresolved

## Dependency Security

Citadel depends on:

| Crate | Purpose | Version | Maintainer |
|-------|---------|---------|-----------|
| `pqcrypto-mlkem` | Post-quantum KEM (ML-KEM-768) | =0.1.1 | PQClean project |
| `pqcrypto-traits` | PQClean type traits | =0.3.5 | PQClean project |
| `x25519-dalek` | Classical ECDH | 2.x | Dalek |
| `aes-gcm` | Symmetric encryption | 0.10 | RustCrypto |
| `hkdf` | Key derivation | 0.12 | RustCrypto |
| `sha2`, `sha3` | Hash functions | 0.10 | RustCrypto |
| `zeroize` | Secure memory clearing | 1.7 | RustCrypto |
| `subtle` | Constant-time operations | 2.5 | Dalek |

All cryptographic dependencies are exact-pinned; any upgrade is an explicit, reviewed decision.

### ML-KEM provider: PQClean

The production ML-KEM-768 provider is PQClean (`pqcrypto-mlkem 0.1.1`), which wraps the PQClean C reference implementation compiled via the `cc` crate. PQClean was selected after comparative timing validation against libcrux and AWS-LC. See `PROVIDER_DECISION_LOG.md` for the full decision history and rollback instructions.

ACVP validation (60 NIST vectors — 25 keygen, 25 encap, 10 decap) is performed via the libcrux dev dependency, which exposes deterministic seed-based APIs. Both providers implement FIPS 203 ML-KEM-768; passing ACVP vectors through libcrux validates algorithmic correctness. PQClean correctness is further confirmed by round-trip and structural tests.

We track security advisories for all dependencies via `cargo audit`.

### Build toolchain requirement

**Minimum build toolchain: Rust / Cargo 1.74+**

A C compiler is required for the PQClean ML-KEM-768 provider (`cc` crate).

## Timing Validation

See `TIMING.md` for the complete timing validation model, including:
- Secret/public inventories
- Enforced invariants
- Known limitation: key-value-dependent decapsulation timing (platform-level)
- Bare-metal dudect results across three providers
- Attacker-controlled-input class pass/fail
- Required grant/security wording
- Production risk assessment and mitigations
- Follow-up work priorities

## Upgrade Policy

### Minor Versions (0.2.x → 0.2.y)

- Bug fixes and security patches
- No breaking API changes
- Wire format compatible
- Safe to upgrade immediately

### Post-1.0 Policy

- Semantic versioning strictly followed
- LTS versions designated annually
- Security fixes backported to LTS

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

## Audit Status

| Component | Last Review | Reviewer |
|-----------|-------------|----------|
| Wire format | Internal | — |
| KDF construction | Internal | — |
| Error handling | Internal | — |
| Timing validation | Internal (dudect) | — |
| ACVP KAT vectors | Automated (60/60) | — |
| Fuzz testing | Ongoing | libFuzzer |

**No independent audit has been conducted.**

## Contact

- **Security issues**: andre.cordero36@gmail.com
- **General questions**: GitHub Discussions
- **Commercial support**: andre.cordero36@outlook.com
