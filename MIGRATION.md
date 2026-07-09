# Migration Guide: Python Prototype → Rust Implementation

## Overview

This document clarifies the relationship between the Python Citadel prototype and this Rust implementation.

**Key Point**: The Rust implementation is a **port of design**, not a byte-compatible implementation. They are different protocols that cannot interoperate.

## Protocol Comparison

| Aspect | Python Citadel v3 | Rust Citadel Envelope v1 |
|--------|-------------------|--------------------------|
| **Status** | Reference prototype | Unaudited envelope foundation |
| **KEM** | Custom RLWE-KEM with FO transform | X25519 + ML-KEM-768 hybrid |
| **KEM ciphertext size** | 1024 bytes | 1120 bytes (32 + 1088) |
| **Wire format header** | `kem_len[4]` (LE u32) | `version[1] + suite_kem[1] + suite_aead[1] + flags[1] + kem_ct_len[2]` |
| **Minimum ciphertext** | ~1056 bytes | 1154 bytes |
| **Protocol ID** | Various/unspecified | `"citadel-env-v1"` |
| **AEAD** | AES-256-GCM | AES-256-GCM |
| **KDF** | HKDF-SHA256 | HKDF-SHA256 |

## What Was Ported

The Rust implementation preserves the **architectural design**:

1. **KEM → KDF → AEAD pipeline**: Same three-stage hybrid encryption flow
2. **Domain separation**: Ciphertext hash bound in KDF
3. **AAD support**: Caller-provided additional authenticated data
4. **Context binding**: Application context in key derivation
5. **Uniform errors**: Single opaque error for all decrypt failures

## What Changed

### 1. KEM Implementation

**Python**: Custom Ring-LWE KEM with Fujisaki-Okamoto transform
- Educational implementation
- Known timing vulnerabilities
- 1024-byte ciphertexts

**Rust**: Hybrid X25519 + ML-KEM-768
- X25519 provides classical ECDH security via `x25519-dalek`
- ML-KEM-768 provides post-quantum security via RustCrypto `ml-kem` (FIPS 203)
- Security holds if *either* primitive remains secure
- 1120-byte ciphertexts (32 X25519 ephemeral + 1088 ML-KEM)

### 2. Wire Format

**Python**:
```
kem_len[4] || kem_ct[1024] || nonce[12] || aead_ct[16+]
```

**Rust**:
```
version[1] || suite_kem[1] || suite_aead[1] || flags[1] ||
kem_ct_len[2] || x25519_epk[32] || mlkem_ct[1088] || nonce[12] || aead_ct[16+]
```

The Rust format includes:
- Version byte for protocol evolution
- Suite identifiers to prevent algorithm confusion
- Reserved flags for future extensions
- Hybrid KEM material (X25519 ephemeral key + ML-KEM ciphertext)

### 3. KDF Domain Separation

**Python** (various iterations):
```
info = "citadel" || role || ct_hash || context
```

**Rust**:
```
combined_ss = x25519_dh[32] || mlkem_ss[32]
info = "citadel-env-v1" || "|aes|" || ct_hash || context
key  = HKDF-SHA256(ikm=combined_ss, salt=None, info=info, len=32)
```

The Rust version:
- Feeds both shared secrets (64 bytes total) into HKDF
- Uses a fixed protocol identifier
- Removes role separation (was half-implemented)
- Explicitly binds the AEAD algorithm

### 4. Error Handling

**Python**: Mixed exceptions with varying detail
**Rust**: Single `DecryptionError` type, uniform message

## KAT Vector Compatibility

**Python KAT vectors do NOT apply to Rust.**

The Python KAT vectors test:
- Custom RLWE-KEM encapsulation
- Python-specific wire format
- Different domain separation strings

The Rust KAT tests are **envelope-only**:
- Test header invariants
- Test roundtrip correctness
- Test AAD/context binding
- Test tampering detection
- Do NOT require deterministic ciphertext bytes

## Migration Strategy

If you have data encrypted with the Python prototype:

1. **Do NOT attempt direct migration** — the formats are incompatible
2. **Re-encrypt with Rust** — decrypt with Python, re-encrypt with Rust
3. **Maintain both** — if backward compatibility is required, keep both implementations

## Why This Approach?

The Python prototype was designed for:
- Educational purposes
- Protocol exploration
- Testing concepts

The Rust implementation is designed for:
- Further hardening and eventual audit
- Standardized primitives (NIST + IETF)
- Long-term maintenance

Attempting byte-compatibility would have:
- Inherited Python's timing vulnerabilities
- Prevented use of standardized ML-KEM and X25519
- Created ongoing maintenance burden

## Questions?

If you need help migrating from the Python prototype, please open an issue with:
- Your use case
- Volume of existing encrypted data
- Compatibility requirements
