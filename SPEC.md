# Citadel Envelope — v1 Structured Wire Specification

This document describes the **v1 structured** wire format implemented in the Rust `citadel-envelope` crate.

---

## Purpose

Citadel is a post-quantum hybrid encryption envelope:

- **KEM:** X25519 + ML-KEM-768 (hybrid — security holds if either primitive remains secure)
- **AEAD:** AES-256-GCM
- **KDF:** HKDF-SHA256 with domain separation

This is a **port of design** from the Python prototype and is not wire-compatible with it.

---

## Parameters

| Component | Size |
|---------|------|
| X25519 ephemeral public key | 32 bytes |
| ML-KEM-768 ciphertext | 1088 bytes |
| Hybrid KEM ciphertext (combined) | 1120 bytes |
| Combined shared secret (X25519 ‖ ML-KEM) | 64 bytes |
| AES-256-GCM nonce | 12 bytes |
| AES-256-GCM tag | 16 bytes |
| Header size | 6 bytes |
| **Minimum ciphertext size** | **1154 bytes** |

---

## Key Sizes

| Key type | Size |
|---------|------|
| Hybrid public key (x25519\_pk ‖ mlkem\_ek) | 1216 bytes |
| Hybrid secret key (x25519\_sk ‖ mlkem\_dk) | 2432 bytes |

---

## Wire Format (v1 structured)

```text
ciphertext =
    version[1]       ||  // MUST be 0x01
    suite_kem[1]     ||  // MUST be 0xA3 (X25519 + ML-KEM-768 hybrid)
    suite_aead[1]    ||  // MUST be 0xB1 (AES-256-GCM)
    flags[1]         ||  // MUST be 0x00
    kem_ct_len[2]    ||  // u16 big-endian, MUST be 1120
    kem_ct[1120]     ||  // x25519_ephemeral_pk[32] || mlkem768_ct[1088]
    nonce[12]        ||  // AES-GCM nonce
    aead_ct[>=16]        // AES-GCM ciphertext + tag
```

---

## KDF

```text
combined_ss = x25519_dh_output[32] || mlkem_shared_secret[32]
info        = "citadel-env-v1" || "|aes|" || SHA3-256(kem_ct) || context
aes_key     = HKDF-SHA256(ikm=combined_ss, salt=None, info=info, len=32)
```
