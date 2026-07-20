# Citadel Gauntlet — run summary (2026-07-20)

Environment: Ubuntu WSL2, stable 1.96.1 / nightly 1.99.0. All tooling free/OSS.
Every result below is machine-checked external-tool output, not self-assessment.

| Tier | Tool | Result | Evidence |
|---|---|---|---|
| **1** Wycheproof vectors | google/wycheproof through exact pinned primitives | ✅ **PASS** | AES-256-GCM 66/66, X25519 265/265 valid, HKDF-SHA256 86/86; 0 failures. `receipts/tier1_vectors.txt` |
| **1b** Envelope composition | proptest vs real `Citadel::seal/open` (256 cases/property) | ✅ **PASS** | roundtrip, single-bit-flip, wrong-key, wrong-AAD, wrong-context, truncation, no-silent-downgrade — 7/7, 0 counterexamples |
| **2** Memory safety | `cargo miri` on citadel-ffi | ✅ **PASS** | 13/13 under interpretation, **0 UB**; incl. free-length-trust, zeroize-before-dealloc, double/null-free, concurrency. `receipts/tier2_miri.txt` |
| **2b** Supply chain | cargo-deny + cargo-audit + cargo-vet | ⚠️ **1 reviewed finding** | 3 HIGH advisories, ALL via `libcrux-ml-kem 0.0.9` **(dev)-dep** oracle — not the shipped `ml-kem 0.3.2` path. `receipts/tier2b_supplychain.txt` |
| **3** Extended fuzzing | cargo-fuzz (libFuzzer, nightly+ASan) smoke | ✅ **PASS (smoke)** | ~71M execs across decode_envelope_v2 (39.9M) + decrypt_full (31.2M), **0 crashes / 0 leaks**; sustained + AFL++ + OSS-Fuzz = follow-on. `receipts/tier3_fuzz_smoke.txt` |
| **4** Constant-time | dudect (+DATA/MicroWalk follow-on) | prior evidence in `../TIMING.md` | attacker-controlled-input classes pass; key-material effect documented, binary CT analysis pending |

## Verdict so far

Citadel **passes** the decisive free adversarial gates that were runnable end-to-end:
primitive conformance to Google's attack corpus, its own envelope composition under
property fuzzing, and memory safety under Miri. No shipped vulnerability. The single
red is a **test-only** supply-chain advisory that must be cleared for auditor optics.

This is necessary-but-not-sufficient for a paid audit — it does not replace one. It
does establish that the money would not be wasted on something that fails free tests.

## Cleared next steps (own packet)

1. **Clear Tier 2b optics**: bump libcrux dev-dep ≥0.0.10 OR scope dev-deps out of the
   advisory gate in `deny.toml`/`audit.toml` with written rationale.
2. **Tier 3 sustained**: OSS-Fuzz onboarding (AGPL-eligible, free perpetual fuzzing) +
   AFL++ second engine; run each target hours, track coverage.
3. **Tier 4 binary CT**: run DATA/MicroWalk on the ML-KEM decapsulation path to localize
   or bound the documented key-material timing effect.
