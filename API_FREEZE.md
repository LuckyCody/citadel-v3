# API Stability Contract

**Version:** 0.1.0  
**Date:** 2026-02-05  
**Status:** FROZEN

This document defines the **stable public interface** of Citadel SDK. Items listed here are guaranteed to remain compatible across minor versions.

## Stability Tiers

### Tier 1: Frozen (Never Changes)

These will NEVER change in a breaking way:

| Item | Signature | Notes |
|------|-----------|-------|
| `Citadel::new` | `fn new() -> Citadel` | Constructor |
| `Citadel::generate_keypair` | `fn generate_keypair(&self) -> (PublicKey, SecretKey)` | |
| `Citadel::seal` | `fn seal(&self, pk, plaintext, aad, context) -> Result<Vec<u8>, SealError>` | |
| `Citadel::open` | `fn open(&self, sk, ciphertext, aad, context) -> Result<Vec<u8>, OpenError>` | |
| `PublicKey::to_bytes` | `fn to_bytes(&self) -> [u8; 1216]` | Size frozen |
| `PublicKey::from_bytes` | `fn from_bytes(&[u8]) -> Result<PublicKey, _>` | |
| `SecretKey::to_bytes` | `fn to_bytes(&self) -> [u8; 2432]` | Size frozen |
| `SecretKey::from_bytes` | `fn from_bytes(&[u8]) -> Result<SecretKey, _>` | |
| Wire format v1 | 6-byte header | Decodable forever |
| `PROTOCOL_VERSION` | `0x01` | |
| `MIN_CIPHERTEXT_BYTES` | `1154` | |

### Tier 2: Stable (Additive Only)

New methods/variants may be added, but existing ones won't change:

| Item | Notes |
|------|-------|
| `Aad::*` constructors | New `for_*` methods may be added |
| `Context::*` constructors | New `for_*` methods may be added |
| `SealError` | May add error variants (non-exhaustive) |
| `OpenError` | Will remain opaque (no variants exposed) |
| `CiphertextInfo` fields | May add fields |

### Tier 3: Internal (No Guarantees)

These are NOT part of the public API:

| Module | Status |
|--------|--------|
| `wire::*` | Internal |
| `kdf::*` | Internal |
| `aead::*` | Internal |
| `kem::*` (except `PublicKey`, `SecretKey`) | Internal |
| `aad::*` (internal functions) | Internal |
| `envelope::*` | Internal |

## Frozen Constants

```rust
// Wire format
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const SUITE_KEM_HYBRID_X25519_MLKEM768: u8 = 0xA3;
pub const SUITE_AEAD_AES256GCM: u8 = 0xB1;
pub const FLAGS_V1: u8 = 0x00;

// Sizes (bytes)
pub const HEADER_BYTES: usize = 6;
pub const KEM_CIPHERTEXT_BYTES: usize = 1120;  // 32 X25519 + 1088 ML-KEM
pub const NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;
pub const MIN_CIPHERTEXT_BYTES: usize = 1154;

// Key sizes
pub const PUBLIC_KEY_BYTES: usize = 1216;   // 32 X25519 + 1184 ML-KEM
pub const SECRET_KEY_BYTES: usize = 2432;   // 32 X25519 + 2400 ML-KEM
```

## Frozen Wire Format

```
ciphertext =
    version[1]       ||  // MUST be 0x01
    suite_kem[1]     ||  // MUST be 0xA3 (X25519 + ML-KEM-768)
    suite_aead[1]    ||  // MUST be 0xB1 (AES-256-GCM)
    flags[1]         ||  // MUST be 0x00
    kem_ct_len[2]    ||  // u16 big-endian, MUST be 1120
    kem_ct[1120]     ||  // x25519_ephemeral_pk[32] || mlkem768_ct[1088]
    nonce[12]        ||  // AES-GCM nonce
    aead_ct[>=16]        // AES-GCM ciphertext + tag
```

## Frozen KDF Construction

```
combined_ss = x25519_dh[32] || mlkem_ss[32]
info        = b"citadel-env-v1" || b"|aes|" || SHA3-256(kem_ct) || context
aes_key     = HKDF-SHA256(ikm=combined_ss, salt=None, info=info, len=32)
```

## Frozen Error Semantics

| Path | Error Type | Variants Exposed |
|------|------------|------------------|
| Encryption | `SealError` | Opaque (single unit type) |
| Decryption | `OpenError` | Opaque (single unit type) |

**Critical:** All decryption failures MUST produce identical, indistinguishable errors. This is a security invariant, not just API design.

## Breaking Change Policy

To change anything in Tier 1 or Tier 2:

1. RFC document explaining rationale
2. 90-day notice period
3. Migration guide
4. Major version bump
5. 12-month deprecation window for old behavior

## Versioning

- **Pre-1.0** (0.x.y): Minor versions may have breaking changes with notice
- **Post-1.0** (x.y.z): Strict semver, Tier 1 items never break

## Attestation

This stability contract is binding. Breaking it without following the change policy constitutes a defect.

---

**Signed:** [Maintainer]  
**Date:** 2026-02-05
