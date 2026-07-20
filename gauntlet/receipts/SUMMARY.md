# Citadel Gauntlet — run summary (2026-07-20)

Environment: Ubuntu WSL2, stable 1.96.1 / nightly 1.99.0. All tooling free/OSS.
Every result below is machine-checked external-tool output, not self-assessment.

| Tier | Tool | Result | Evidence |
|---|---|---|---|
| **1** Wycheproof vectors | google/wycheproof through exact pinned primitives | ✅ **PASS** | AES-256-GCM 66/66, X25519 265/265 valid, HKDF-SHA256 86/86; 0 failures. `receipts/tier1_vectors.txt` |
| **1b** Envelope composition | proptest vs real `Citadel::seal/open` (256 cases/property) | ✅ **PASS** | roundtrip, single-bit-flip, wrong-key, wrong-AAD, wrong-context, truncation, no-silent-downgrade — 7/7, 0 counterexamples |
| **2** Memory safety | `cargo miri` on citadel-ffi | ✅ **PASS** | 13/13 under interpretation, **0 UB**; incl. free-length-trust, zeroize-before-dealloc, double/null-free, concurrency. `receipts/tier2_miri.txt` |
| **2b** Supply chain | cargo-deny + cargo-audit + cargo-vet | ✅ **PASS (0 vulns)** | 3 HIGH **fixed** by bumping the libcrux **dev**-oracle 0.0.9→0.0.10 (patched code swapped in). `cargo audit` 0 vulns; 4 dev-only unmaintained/unsound warnings kept **visible** (not ignored) + documented in `SUPPLY_CHAIN.md`. `cargo deny` advisories ok. `receipts/tier2b_supplychain.txt` |
| **3** Extended fuzzing | cargo-fuzz (libFuzzer, nightly+ASan) smoke | ✅ **PASS (smoke)** | ~71M execs across decode_envelope_v2 (39.9M) + decrypt_full (31.2M), **0 crashes / 0 leaks**; sustained + AFL++ + OSS-Fuzz = follow-on. `receipts/tier3_fuzz_smoke.txt` |
| **4** Constant-time | dudect (+DATA/MicroWalk follow-on) | prior evidence in `../TIMING.md` | attacker-controlled-input classes pass; key-material effect documented, binary CT analysis pending |

## Verdict so far

Citadel **passes** the decisive free adversarial gates that were runnable end-to-end:
primitive conformance to Google's attack corpus, its own envelope composition under
property fuzzing, memory safety under Miri, and a clean supply chain. No shipped
vulnerability; 0 advisories after the libcrux dev-oracle bump.

This is necessary-but-not-sufficient for a paid audit — it does not replace one. It
does establish that the money would not be wasted on something that fails free tests.

## Cleared next steps (own packet)

1. ~~Clear Tier 2b optics~~ **DONE 2026-07-20** — bumped libcrux dev-oracle to 0.0.10
   (fixes RUSTSEC-2026-0207/0208/0212 with patched code). 4 residual dev-only
   unmaintained/unsound warnings kept **visible** in `cargo audit` (no per-ID
   ignore) and documented in `SUPPLY_CHAIN.md`. Suite unchanged at 353/0/8.
2. **Tier 3 sustained**: OSS-Fuzz onboarding (AGPL-eligible, free perpetual fuzzing) +
   AFL++ second engine; run each target hours, track coverage.
3. **Tier 4 binary CT**: run DATA/MicroWalk on the ML-KEM decapsulation path to localize
   or bound the documented key-material timing effect.
