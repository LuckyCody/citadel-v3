# Side-Channel Notes — Citadel V3

> **Superseded by [TIMING.md](TIMING.md)**, the full timing validation record. Known-stale here: API-key comparison now uses `subtle::ConstantTimeEq` (citadel-api/src/main.rs), not `==`.

**Status:** Unreviewed. No independent side-channel analysis has been performed.

---

## Allowed External Claim

> Citadel attempts to use uniform external error behavior and avoids known obvious
> error oracles, but has not undergone independent side-channel review.

---

## What Is Intentionally Uniform

### Error responses
All decryption failures return the same opaque error: `{"error":"decryption failed"}`.
The response does not distinguish between: wrong key, wrong AAD, wrong context,
truncated ciphertext, replay rejection, or corrupted data. This is deliberate.

### Timing at the API layer
The API returns errors without short-circuiting before the full decryption attempt
where possible. However, this is not formally verified.

---

## What Is Not Proven

- **Constant-time key comparison:** API key hash comparison uses `subtle::ConstantTimeEq`
  (`citadel-api/src/main.rs`). The constant-time property is inherited from the `subtle`
  crate and has not been independently verified on the authentication path.
- **Constant-time KEM operations:** ML-KEM-768 and X25519 constant-time behavior
  is inherited from dependencies. Not independently verified on all platforms.
- **Cache-timing:** No cache-timing analysis has been performed.
- **Power analysis:** Not applicable to software-only deployment, but not analyzed.
- **Memory scraping:** Key material exists in process memory during operations.
  Zeroization is used where supported (zeroize crate) but not audited.

---

## Crates Relied On for Timing Properties

| Crate | Claim | Verified |
|-------|-------|----------|
| `x25519-dalek` | Constant-time DH | Claimed by crate, not independently verified |
| `ml-kem` | Constant-time KEM | Experimental, not audited |
| `aes-gcm` | Constant-time AES | Claimed, platform-dependent |
| `subtle` | Constant-time primitives | Widely used, not independently verified here |
| `hmac` | HMAC-SHA256 | Generally safe for MAC, timing not analyzed for API key comparison |

---

## Sensitive Operations (External Audit Should Review)

1. API key verification — `subtle::ConstantTimeEq` comparison on HMAC hashes
2. Decryption error path — uniform response, but timing may vary
3. ML-KEM decapsulation — experimental crate, constant-time not proven
4. Key material zeroization — depends on compiler not optimizing away

---

## What External Audit Should Cover

- Constant-time API key comparison (verify the `subtle::ConstantTimeEq` path)
- ML-KEM-768 timing properties in `ml-kem` crate
- Memory layout of key material during operations
- Zeroization completeness across all key paths

---

*Last updated: 2026-05-02 | citadel-v3-beta-001*
