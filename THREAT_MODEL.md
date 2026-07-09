# Citadel V3 — Threat Model

**Version:** citadel-v3-0.2.0
**Status:** Unaudited. Claims here are design-level and test-validated, not independently verified.

---

## What this system is

A hybrid post-quantum encryption envelope and key management system. It wraps
plaintext using X25519 + ML-KEM-768 (hybrid KEM), AES-256-GCM (AEAD), and
HKDF-SHA256 (KDF), enforces a 4-level key hierarchy, and provides stateful
replay protection.

---

## What Citadel V3 protects against

### Confirmed by tests (328+ passing, 0 failures)

| Threat | Protection | Test |
|--------|-----------|------|
| Replay attack (same ciphertext submitted twice) | Stateful nonce tracking — second attempt rejected | `p066_fail_closed_replay_store_denies_decrypt` |
| Replay attack across server restart | FileReplayStore persists nonces to disk | Live test confirmed |
| Ciphertext tampering (any bit flip) | AES-256-GCM authentication tag | `bit_flip_anywhere_fails`, `every_byte_is_authenticated` |
| Wrong key | KEM decapsulation fails — implicit rejection | `wrong_key_fails`, `wrong_key_rejected` |
| Wrong AAD (authentication context) | AEAD tag verification fails | `wrong_aad_fails`, `aad_binding_enforced` |
| Wrong context string | HKDF domain separation — different derived key | `context_isolation`, `context_binding_enforced` |
| Truncated/malformed ciphertext | Structured parsing fails safely | `truncated_fails`, `truncated_ciphertext_rejected` |
| Random garbage as ciphertext | Does not panic, returns error | `decryption_never_panics_on_garbage` |
| Key hierarchy violation (revoked parent) | Hierarchy check blocks child key access | `revoked_kek_blocks_dek_decrypt` |
| Corrupted ciphertext poisoning replay slot | Replay slot only marked after successful decrypt | `p089_corrupted_ciphertext_does_not_poison_replay_slot` |
| Malformed API input | Structured rejection before crypto operations | `it_malformed_json_returns_4xx` |
| Auth brute force / key spam | Rate limiter (20 rps default, configurable) | `it_rate_limit_activates_under_spam` |
| Auth failures leaving no evidence | Written to tamper-evident JSONL audit chain | `AuthFailed` in AuditAction |
| Replay store deleted mid-run | Store recreates safely, in-memory state preserved | `file_store_recreates_after_deletion` |
| Quantum attack on key exchange | ML-KEM-768 (NIST FIPS 203) — security holds even if X25519 broken | Hybrid KEM design |
| Attacker-varied ciphertext timing | dudect passes all attacker-controlled classes | `timing_sidechannel` bench suite |
| ACVP vector correctness | 60/60 NIST vectors byte-identical (keygen, encap, decap) | `acvp_libcrux_kat` |
| Corrupted X25519 ephemeral | Authentication fails | `corrupted_x25519_ephemeral_rejected` |
| Corrupted AEAD tag | Authentication fails | `corrupted_aead_tag_rejected` |

---

## What Citadel V3 does NOT yet claim

These are explicit non-goals or unverified properties:

### Key-material timing independence

ML-KEM-768 decapsulation shows key-value-dependent timing on tested x86-64
hardware, reproduced across three independently developed providers (PQClean,
libcrux, AWS-LC). Source inspection confirms constant-time discipline in the
code; the effect is consistent with hardware data-dependent execution
(Hertzbleed-class). All attacker-controlled-input timing classes pass dudect.
See `TIMING.md` for the full finding and required wording.

### Formal verification
No part of Citadel V3 has been formally verified. Correctness claims rest on
tests, ACVP vectors, and code review, not mathematical proof.

### Audit certification
The system has not been independently audited. No third party has reviewed the
implementation for security flaws.

### HSM-grade key protection
Keys at rest are protected by AES-256-GCM wrapping under CITADEL_MASTER_KEY.
CITADEL_MASTER_KEY is loaded from an environment variable — not from an HSM,
TPM, or hardware security boundary. Key material exists in process memory
during operations.

### Multi-node replay safety (without Redis)
The FileReplayStore is safe for single-node deployments. Multiple API instances
sharing a file replay store are NOT supported — race conditions can allow
replay. Multi-node replay safety requires the Redis backend
(`CITADEL_REPLAY_STORE=redis`).

### Network-level attack resistance
Citadel is not a transport security protocol. It does not replace TLS/HPKE
for interactive sessions. MITM, downgrade, and traffic analysis attacks at
the network layer are out of scope.

### FIPS validation
The primitives used (ML-KEM-768, AES-256-GCM, HKDF-SHA256) follow NIST
standards. Citadel itself has not undergone FIPS 140-3 validation.

---

## Attacker model

### In scope

- Attacker can observe all ciphertexts in transit and at rest
- Attacker can modify ciphertexts and feed them to the decryptor
- Attacker can attempt replay of previously captured ciphertexts
- Attacker has access to a quantum computer (ML-KEM-768 provides resistance)
- Attacker can send malformed, truncated, or garbage inputs to the API
- Attacker can attempt API key brute force
- Attacker can vary ciphertext content per query (timing classes validated)

### Out of scope

- Attacker with physical access to the server (CITADEL_MASTER_KEY in memory)
- Attacker who has compromised CITADEL_MASTER_KEY (system is broken by definition)
- Local co-resident side-channel attacker (timing, cache, power) unless dedicated tenancy is used
- Attacker with root access to the deployment host

---

## Crypto primitive status

| Primitive | Algorithm | Standard | Crate | Version | Status |
|-----------|-----------|----------|-------|---------|--------|
| KEM (classical) | X25519 ECDH | RFC 7748 | x25519-dalek | 2.x | Stable |
| KEM (post-quantum) | ML-KEM-768 | NIST FIPS 203 | pqcrypto-mlkem | =0.1.1 | PQClean reference C |
| AEAD | AES-256-GCM | NIST SP 800-38D | aes-gcm | 0.10 | Stable |
| KDF | HKDF-SHA256 | RFC 5869 | hkdf | 0.12 | Stable |
| MAC (API auth) | HMAC-SHA256 | RFC 2104 | hmac | 0.12 | Stable |
| Signing (optional) | ML-DSA-65 | NIST FIPS 204 | pqcrypto-dilithium | — | PQClean reference C |

**Hybrid security guarantee:** An attacker must break BOTH X25519 AND ML-KEM-768
to recover the shared secret. If either primitive is compromised (by cryptanalysis
or implementation flaw), the other still protects the plaintext.

---

## Service boundary protections

| Protection | Implementation |
|-----------|---------------|
| Opaque errors | All decrypt failures return identical error type and HTTP status |
| Response floor | Deadline-style minimum response time prevents timing cliff |
| Rate limiting | Three-tier (per-key, per-domain, global) with configurable thresholds |
| No raw KEM endpoint | Decapsulation is never exposed independently of the authenticated envelope |
| Audit logging | All auth failures and key lifecycle events logged to tamper-evident JSONL |

---

## Intended use

Citadel V3 is appropriate for:
- Hybrid PQC encryption for data at rest and in transit (within TLS)
- Key management with hierarchy, rotation, and lifecycle enforcement
- Backing a PQC migration assessment/reporting pipeline
- Internal tooling where the threat model above is acceptable

Not appropriate for (without further work):
- Regulated environments (FIPS, PCI-DSS, HIPAA) without audit
- Deployments requiring local co-resident side-channel resistance
- Multi-node deployments without Redis replay backend

---

*See [TIMING.md](../../TIMING.md) for the complete timing validation model.*
*See [SECURITY.md](SECURITY.md) for the security policy and disclosure process.*
*See [PROVIDER_DECISION_LOG.md](../../PROVIDER_DECISION_LOG.md) for ML-KEM provider history.*
