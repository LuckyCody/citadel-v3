# Tier 9 — Design-Soundness Review: Hybrid-KEM Combiner

**Scope:** Is Citadel's specific X25519 + ML-KEM-768 combiner an *IND-CCA2-robust*
hybrid KEM — i.e., does the derived key stay secure as long as **at least one** of
the two KEMs is secure, even against a chosen-ciphertext (decryption-oracle)
attacker? This is the single highest-stakes *design* question, and it is the kind
of thing a paid audit examines by hand. No tool produces this; it is analytical
review, and it is **not** a machine-checked proof (see Limits).

## The exact construction (from source)

Per `citadel-envelope/src/kem.rs` and `kdf.rs`:

```
ss1 = X25519(eph_sk, recipient_x25519_pk)      # 32 B, rejected if !was_contributory()
(ct2, ss2) = ML-KEM-768.Encaps(recipient_mlkem_pk)   # ct2 = 1088 B, ss2 = 32 B
ct1 = eph_x25519_pk                             # 32 B  (the DH "ciphertext")

kem_ct        = ct1 || ct2                      # 1120 B, FIXED-length fields
combined_ss   = ss1 || ss2                      # 64 B,  FIXED-length fields
ct_hash       = SHA3-256(kem_ct)                # binds BOTH ciphertexts
info          = PROTOCOL_ID || "|aes|" || ct_hash || context
K             = HKDF-SHA256(ikm = combined_ss, salt = None, info = info, len = 32)
# then AES-256-GCM(K, nonce, plaintext, aad)
```

So, expanded: `K = HKDF(ss1‖ss2, info = PID‖"|aes|"‖SHA3-256(ct1‖ct2)‖context)`.

## What the literature requires

The relevant results are Giacon–Heuer–Poettering, *KEM Combiners* (PKC 2018) and
Bindel–Brendel–Fischlin–Gonçalves–Stebila, *Hybrid KEMs and AKE* (PQCrypto 2019).
The load-bearing findings:

1. **Feeding only the shared secrets is not enough.** A naïve combiner such as
   `K = H(ss1‖ss2)` (or XOR of the secrets) is **not** generically IND-CCA2. A
   CCA attacker can maul one component ciphertext, query the decapsulation oracle,
   and learn relationships — CCA security of the *hybrid* can fail even if one KEM
   is CCA-secure.
2. **The fix is to bind both ciphertexts into the KDF** (and use a combiner modeled
   as a random oracle, or an explicit dual-PRF). The canonical robust combiner is
   `K = H(ss1, ss2, ct1, ct2)` or a split-key/dual-PRF over the same inputs. With
   the ciphertexts bound, the hybrid is IND-CCA2 if **either** KEM is IND-CCA2.
3. **Unambiguous encoding.** The concatenation must be non-ambiguous (fixed lengths
   or length-prefixing) so `a‖b` cannot collide with `a'‖b'`.

## Point-by-point evaluation

| Requirement | Citadel | Verdict |
|---|---|---|
| Both shared secrets in the KDF | `ikm = ss1‖ss2` | ✅ |
| **Both ciphertexts bound** | `info` includes `SHA3-256(ct1‖ct2)` — ct1 = X25519 ephemeral pk, ct2 = ML-KEM ct | ✅ this is the property that defeats the CCA mauling attack |
| Unambiguous concatenation | ss1‖ss2 (32‖32) and ct1‖ct2 (32‖1088) are **fixed-length** by the wire format | ✅ no canonicalization ambiguity |
| Combiner is RO/dual-PRF | HKDF-SHA256 (HMAC-based); modeled as RO / HKDF-Extract-as-dual-PRF | ✅ under standard assumption (see Caveats) |
| Component KEM CCA-secure | ML-KEM-768 is IND-CCA2 (FO transform, implicit rejection) | ✅ hybrid inherits CCA2 from ML-KEM even if X25519 fully breaks |
| Classical half hardened | X25519 `was_contributory()` rejects low-order/zero DH output | ✅ blocks the small-subgroup "force ss1 = 0" attack |
| Domain separation | `PROTOCOL_ID`, `"|aes|"` label, and `context` in `info` | ✅ separates this KDF use from any other |

**Structural conclusion:** Citadel implements the *robust* combiner shape, not the
naïve one. It feeds both secrets **and** binds both ciphertexts (via the SHA3 hash
in HKDF's `info`), with fixed-length unambiguous encoding. This is exactly what the
KEM-combiner literature prescribes for "secure if either component is secure,"
including against chosen-ciphertext attackers. It is structurally aligned with the
IETF/TLS 1.3 hybrid-KEM combiners. **No design flaw found.**

## Caveats (stated honestly)

1. **ROM / dual-PRF assumption.** Binding the ciphertexts in HKDF's `info` (the
   Expand phase, keyed by PRK) rather than in the Extract `ikm` is equivalent to
   the RO construction `H(ss1,ss2,ct1,ct2)` only when HMAC-SHA256 behaves as a
   random oracle / HKDF-Extract behaves as a dual-PRF. HKDF-Extract here uses
   `salt = None` (⇒ zero salt), so the secret entropy is in the *message*, not the
   HMAC key; robustness then rests on the RO/dual-PRF assumption — the **same**
   assumption TLS 1.3 hybrid drafts rely on. It is standard, but it *is* an
   assumption, not an unconditional result. A marginally stronger variant would key
   Extract with one secret (`HKDF-Extract(salt = ss1, ikm = ss2)`), as some IETF
   hybrid drafts do.
2. **Analytical, not machine-checked.** This is hand review consistent with the
   literature — not an EasyCrypt/CryptoVerif proof. The next rigor step (Tier 8/formal)
   is a computational proof of the exact construction.
3. **Confidentiality only.** This analysis covers KEM/key-derivation IND-CCA2. It
   does not cover the AEAD layer (AES-GCM nonce management), key hierarchy, or
   authentication — those are separate review items.

## Verdict & recommendation

- **The combiner is sound under the standard random-oracle assumption**, and it
  correctly implements the ciphertext-binding that the naïve combiner lacks. This
  is a *positive* result that free measurement tools cannot produce: the design
  question a cryptographer would ask first has a defensible answer.
- **Recommended, in priority order:** (a) document the ROM/dual-PRF assumption
  explicitly in `SPEC.md`/`WIRE_SPEC.md`; (b) optionally move to a keyed-Extract
  dual-PRF variant for belt-and-suspenders; (c) commission a machine-checked
  computational proof (EasyCrypt/CryptoVerif) as the final rigor step — this is the
  one item here that genuinely benefits from paid cryptographic expertise.

## References
- Giacon, Heuer, Poettering. *KEM Combiners.* PKC 2018.
- Bindel, Brendel, Fischlin, Gonçalves, Stebila. *Hybrid KEMs and AKE.* PQCrypto 2019.
- NIST SP 800-56C Rev. 2 (KDF guidance); RFC 5869 (HKDF).
- IETF hybrid-KEM / TLS 1.3 hybrid drafts (structural precedent).
