# Tier 12 computational combiner proof — BOTH arms verified (combiner-half)

This directory contains machine-checked proofs of **both arms** of hybrid-combiner
robustness. Both arms are verified at the **full-faithful** level
(full hybrid-ciphertext CCA + ciphertext/context binding + explicit SHA3-256
collision resistance), each resting on its component KEM's IND-CCA2 premise.

| Arm | File | Result | Premise |
|---|---|---|---|
| ML-KEM secrets-only (baseline) | `citadel_combiner_mlkem_arm.ocv` | VERIFIED | ML-KEM-768 IND-CCA2 (FIPS 203) |
| ML-KEM faithful, injective bind | `citadel_combiner_mlkem_arm_hybrid.ocv` | VERIFIED | ML-KEM-768 IND-CCA2 + collision-free binding |
| **ML-KEM FAITHFUL + explicit SHA3-CR** | `citadel_combiner_mlkem_arm_hybrid_sha3.ocv` | **VERIFIED** | ML-KEM-768 IND-CCA2 + SHA3-256 CR (`P_sha3` explicit) |
| X25519 secrets-only (Option A) | `citadel_combiner_x25519_arm.ocv` | VERIFIED | X25519-DHKEM IND-CCA2 (published GDH+ROM) |
| **X25519 FAITHFUL + explicit SHA3-CR** | `citadel_combiner_x25519_arm_hybrid.ocv` | **VERIFIED** | X25519-DHKEM IND-CCA2 + SHA3-256 CR |
| X25519 raw-GDH (abstract) | `citadel_combiner_x25519_gdh_attempt.ocv` | ⛔ PARKED | abstract prime-order Gap-DH — known Curve25519 fidelity gap |
| **P-384 CTD2 arm (suite `0xA4`)** | `citadel_combiner_ctd2_p384_arm.ocv` | **VERIFIED** | P-384-DHKEM IND-CCA2 — prime-order abstraction **faithful** (cofactor 1) |
| **ML-KEM-1024 CTD2 arm (suite `0xA4`)** | `citadel_combiner_ctd2_mlkem1024_arm.ocv` | **VERIFIED** | ML-KEM-1024 IND-CCA2 (FIPS 203, category 5) |

## Suite `0xA4` (P-384 + ML-KEM-1024)

Both arms of the CNSA-aligned suite are machine-checked at the CTD2 (production
`wire_v2`) level, exit code 0, no `admit`/`assume`. Receipts:
`receipt_ctd2_p384_arm.txt`, `receipt_ctd2_mlkem1024_arm.txt`.

```text
P-384 arm:       RESULT Proved secrecy of K up to probability
                   2 * N_kdf / |dh_secret| + 2 * P_dh_indcca2(time_1, 1, 1, N_dec)
ML-KEM-1024 arm: RESULT Proved secrecy of K up to probability
                   2 * N_kdf / |ml_secret| + 2 * P_ml_indcca2(time_1, 1, 1, N_dec)
```

- **ML-KEM-1024 arm** is instance-independent: ML-KEM is abstracted as its IND-CCA2
  premise, so 768→1024 is a strictly stronger instance of the same assumption (category
  5 vs 3). Proof structure identical to the `0xA3` ML-KEM arm; the broken classical
  component is P-384 rather than X25519 but enters as the same abstract `[fixed]`
  ciphertext type, immaterial to the secrecy theorem since it is fully broken. This is
  a re-run and re-receipt of the same proof structure, not a new argument.
- **P-384 arm is an upgrade over the X25519 arm, not just a relabel.** CryptoVerif's
  prime-order/DHKEM abstraction is *unfaithful* to Curve25519 (cofactor 8, low-order
  points), which is exactly why `citadel_combiner_x25519_gdh_attempt.ocv` stays PARKED
  as an idealization. **P-384 has cofactor 1** — a prime-order group with no low-order
  subgroup — so the abstract model is faithful to the shipped curve and that fidelity
  gap does not exist. The X25519 arm's seven-point low-order rejection suite has no
  P-384 analogue and needs none; SEC1 on-curve/not-identity validation in
  `from_sec1_bytes` covers what `was_contributory()` covered for X25519.

The verified arms establish: **the combiner key K is secret if the surviving
component KEM is IND-CCA2, even if the other component is fully broken**, now under
**full hybrid-ciphertext CCA with the KDF binding both ciphertexts + context and the
SHA3-256 collision term explicit in the bound:**

```text
RESULT Proved secrecy of K up to probability
        2 * N_kdf / |secret| + 8 * P_sha3_coll + 2 * P_indcca2(time_1, 1, 1, N_dec)
```

> **On the PARKED raw-GDH file:** it is an ABSTRACT prime-order-group model and does
> NOT faithfully model Citadel's real X25519 = Curve25519 (cofactor, low-order
> points, all-zero/non-contributory rejection). Polishing its proof script would
> validate an idealization, not Citadel. Both arms already hold under the cited,
> published X25519-DHKEM / ML-KEM IND-CCA2 premises; a raw-Curve25519 grounding
> (DH_subgroup + rejection) is future work, not a claim.

> **ADVERSARIAL REVIEW + RESOLUTION (Codex/GPT-5.6-Sol).** The review flagged the secrets-only arms:
> (F1) the KDF didn't model the real HKDF's ciphertext binding
> `SHA3-256(kem_ct)`/domain/context; (F2) the guard compared only the ML-KEM
> ciphertext, wrongly excluding the legal, load-bearing hybrid CCA query
> `(ct1' ≠ ct1*, ct2*)`. F3 (assumption) and F4 (bound) CLEARED.
>
> **RESOLVED** by `citadel_combiner_mlkem_arm_hybrid.ocv` (VERIFIED, exit 0): the
> KDF now binds the full hybrid ciphertext + context, and the decap oracle takes
> the full hybrid ciphertext, rejecting ONLY the exact challenge pair while
> **permitting and correctly answering** `(ct1' ≠ ct1*, ct2*)`. Building this also
> surfaced and fixed a real CCA modeling bug (the challenge ciphertext must be
> committed BEFORE decap queries). **One residual refinement:** SHA3-256's binding
> is modeled as an injective (collision-free) transcript rather than exposing its
> concrete collision term `P_sha3` as a separate CR primitive — the CCA logic is
> complete; the SHA3 collision probability is assumed, not accounted. The
> secrets-only files are retained as the minimal baseline.

> **FALSIFICATION AUDIT (Codex/GPT-5.6-Sol).** Independent red-team ran 8+
> falsification probes against the faithful arms — mutating the models so secrecy
> MUST break if the proof has teeth. Result: **no cryptographic façade.** Every
> load-bearing element fails correctly on removal (leak K → fails; constant info →
> fails; no guard → fails; delete SHA3 collision → fails), the assumption matches
> the built-in `IND_CCA2_KEM`, and the X25519 arm is a byte-identical relabel (same
> normalized SHA-256). The audit also caught two HONEST OVERSTATEMENTS, now FIXED in
> the `*_hybrid_sha3.ocv` / `*_x25519_arm_hybrid.ocv` files:
> - the broken-component challenge ciphertext `ct1star` was uniformly SAMPLED, not
>   adversary-chosen — now an `Ostart` parameter (adversary-supplied); re-verified,
>   **same bound**.
> - the fixed `PROTOCOL_ID/"|aes|"` domain label is NOT modeled (a constant here);
>   claim corrected — cross-protocol/domain separation is a separate, out-of-scope
>   property.
> Audit nuance (honest): machine-checked as load-bearing for the secrecy theorem is
> the **broken-component ciphertext binding**; the surviving-component ciphertext and
> context are bound faithfully-to-construction but are not individually necessary
> (removing them still proves, with a larger guessing term).

X25519 arm result on record:

```text
RESULT Proved secrecy of K up to probability
        2 * N_kdf / |dh_secret| + 2 * P_dh_indcca2(time_1, 1, 1, N_dec)
```

**Honest premise note (X25519 Option A):** the X25519-DHKEM IND-CCA2 premise is
NOT re-derived in Option A; it is the standard result machine-checked under
Gap-DH + ROM in the shipped `examples/hpke/dhkem.base.indcca2-lr.m4.ocv`. This is
the same epistemic structure as the ML-KEM arm (which assumes ML-KEM IND-CCA2).
Option B removes even this abstraction by grounding X25519 directly in Gap-DH
inside Citadel's own model.

---

## ML-KEM arm

## What is proved (and what is not)

**VERIFIED** — `citadel_combiner_mlkem_arm.ocv`:

> If ML-KEM-768 is IND-CCA2, then the combiner's KDF-derived key `K` is secret
> from the adversary **even if X25519 is fully broken** (the adversary chooses
> `ss1`). The KDF (HKDF over `ss1 || ss2 || H(kem_ct)`) is modeled as a random
> oracle.

CryptoVerif result:

```text
RESULT Proved secrecy of K up to probability
        2 * N_kdf / |ml_secret| + 2 * P_ml_indcca2(time_1, 1, 1, N_dec)
```

The advantage is the expected shape: a negligible ROM-collision term
(`N_kdf / |ml_secret|`, and `ml_secret` is the large ML-KEM shared-secret space)
plus twice the ML-KEM IND-CCA2 advantage. No `admit`, no `assume`, exit code 0.

**NOT yet proved** (named remaining lemmas, no claim made):

- The **X25519 arm**: `K` secret if ML-KEM breaks but X25519 holds (needs the
  PRF-ODH / DDH assumption on the X25519 secret).
- The **dual-binding KDF step**: both shared secrets and both ciphertexts bound
  by HKDF/SHA3 in one derivation.

So the honest one-line claim is: **"ML-KEM arm of combiner robustness is
machine-checked (ROM model); full hybrid robustness is not yet."** This is a
model of the abstract combiner, not the Rust — the model↔code gap is covered by
the other gauntlet tiers (Wycheproof, proptest, Miri, ctgrind), not by this file.

## Tool

CryptoVerif 2.12, official Windows binary from INRIA:
`https://bblanche.gitlabpages.inria.fr/CryptoVerif/cryptoverifbin2.12.zip`.
No SMT backend is used by CryptoVerif.

## Reproduce

From this directory, after unpacking the official binary:

```powershell
& 'C:\tmp\cryptoverif-2.12\cryptoverif2.12\cryptoverif.exe' `
  'citadel_combiner_mlkem_arm.ocv'
```

The decisive judge line is `RESULT Proved secrecy of K up to probability ...`.
Full verbatim output is `receipt_mlkem_arm.txt`.

## How it verified (the honest trail)

1. `citadel_hybrid_combiner.ocv` (design input, Codex): asked CryptoVerif to
   prove the ML-KEM assumption *from itself* (a `query_equiv` restating the
   `equiv`) — vacuous, stalled at game merge. Kept for the record.
2. Corrected goal → prove combiner-key secrecy *using* the assumption. Automatic
   search stalled on ROM collision elimination.
3. Guided proof script (`crypto mlkem_indcca2_assumption; crypto rom(kdf);
   success`, same shape as `examples/hpke/hpke.base.indcca2.ocv`) pushed through
   both hops but left `K` unproved.
4. Root cause: the decapsulation oracle would decapsulate the **challenge
   ciphertext** — a real attack. Forbidding it (`if c = ct then yield`), which is
   the correct CCA2 threat model, closes the proof.

Per-step evidence is in `citadel/eem/016_attempt_*.md` and `016_receipt.md`.
