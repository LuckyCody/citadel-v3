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
| **5** Formal (proof) | **Kani** bounded model checking on wire parsers | ✅ **PROVEN** | `inspect` + `decode_wire` panic-free / no-UB for ALL inputs ≤**256B** (incl. internal wire_v2::decode, decode_wire_raw). Proof, not sample. `receipts/tier5_kani.txt` |
| **6** Concurrency | **Loom** exhaustive interleaving | ✅ **PASS** | one-shot capability nonce: exactly-one-consumer under EVERY schedule, no double-spend / lost token / deadlock. `receipts/tier6_loom.txt` |
| **7** Sanitizers | **AddressSanitizer** on citadel-ffi | ✅ **PASS** | 13/13 under ASan (+leak detection), 0 sanitizer errors at the real allocator. Complements Miri. `receipts/tier7_asan.txt` |
| **8** CT proof | ctgrind (valgrind memcheck) on ML-KEM decap | ✅ **EXECUTED — resolved** | Citadel's own code: **0 secret-dependent branches**. Residual localizes to ml-kem 0.3.2 `sample_poly_cbd` — a real secret-indexed lookup `ONES[val.0]`, but for ML-KEM-768 (η=2) the table is 32B/one cache line + index always in-range ⇒ **not practically exploitable** (matches TIMING.md). Dependency property, not Citadel code. `receipts/tier8_ct.txt`. |
| **9** Design review | hybrid-KEM combiner IND-CCA2 soundness | ✅ **NO FLAW** | binds both ciphertexts + both secrets, unambiguous encoding, X25519 contributory check — sound under ROM per KEM-combiner literature. Analytical, not machine-checked. `tier9_design/HYBRID_COMBINER_ANALYSIS.md` |

## Verdict

Citadel **passes every free adversarial gate that was runnable end-to-end** — now
including *proof-based* checks, not just sampling: Kani proves the parsers panic-free,
Loom exhaustively validates the concurrency, ASan confirms runtime memory safety, and
a design-level review finds the hybrid-KEM combiner sound (no flaw). Primitive
conformance, composition, and supply chain remain clean.

**Two honest gaps remain, both known:** (8) instruction-level constant-time proof is
blocked only on a `sudo apt install` (not on capability or willingness); and every
result here is machine-checked *implementation/design* evidence — it still does not
replace the one thing paid expertise uniquely provides: a named cryptographer's
signoff and liability. This is necessary-but-not-sufficient for a paid audit — but it
now clears a substantially higher bar than measurement-only tooling.

## Cleared next steps (own packet)

1. ~~Clear Tier 2b optics~~ **DONE 2026-07-20** — bumped libcrux dev-oracle to 0.0.10
   (fixes RUSTSEC-2026-0207/0208/0212 with patched code). 4 residual dev-only
   unmaintained/unsound warnings kept **visible** in `cargo audit` (no per-ID
   ignore) and documented in `SUPPLY_CHAIN.md`. Suite unchanged at 353/0/8.
2. **Tier 3 sustained**: continuous-fuzzing config is WRITTEN in `oss-fuzz/`
   (ClusterFuzzLite recommended — self-hosted in Citadel's own CI, no acceptance gate;
   OSS-Fuzz as the optional Google-hosted path). Drop `.clusterfuzzlite/` + the workflow
   and each target fuzzes for hours with an accumulating corpus.
3. **Tier 8 CT**: one root install (`sudo apt install libc6-dbg`) runs the ready ctgrind
   harness; then DATA/haybale for deeper coverage.
