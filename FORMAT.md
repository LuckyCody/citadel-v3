# Citadel Envelope Format (v1)

This document describes the high-level encoding and binding semantics used by this crate.

## Overview
A ciphertext consists of:
1) A versioned, suite-identified wire header (self-describing)
2) Hybrid KEM material (ML-KEM + X25519)
3) AEAD payload (AES-256-GCM)

The decryptor MUST reject malformed or unsupported encodings.

## Binding rules
Two caller-provided byte strings are used:
- `aad`: authenticated associated data (not encrypted)
- `context`: domain separation / application context

Both `aad` and `context` are bound into the encryption so that:
- Wrong `aad` or `context` MUST cause decryption failure.
- Implementations SHOULD treat `context` as a required domain-separation label.

Recommended conventions:
- `context` should be a stable, structured label (e.g., `b"contract:ACME-2026"`).
- `aad` can carry ephemeral metadata (build IDs, filenames, etc.) if you want it authenticated.

## Error behavior
Decryption failures SHOULD be indistinguishable to callers (single error class) to reduce oracle risk.

## Versioning
- The header includes a version and suite identifier.
- Unknown versions/suites MUST be rejected.
- Future versions may add suites or fields; decoders MUST be strict for v1.

## Interop
For cross-implementation interoperability, publish test vectors:
- recipient public key
- aad/context
- plaintext hash
- full ciphertext bytes
