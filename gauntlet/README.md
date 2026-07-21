# Citadel Adversarial Gauntlet

A free/open-source validation battery that mirrors what an independent
cryptographic auditor (Trail of Bits, NCC Group, …) runs *before* you pay one.

**Purpose:** decide whether Citadel is worth a paid audit. Every tier is a cheap,
decisive signal. A red at any tier is a "don't send the check yet." Passing the
whole gauntlet is *necessary but not sufficient* for a paid engagement — it does
not replace one, it earns the right to book one.

This encodes the project's founding lesson (`les_001`): self-grading is not
validation. Nothing here is a self-assessment; every tier is an external tool or
an independent oracle run against Citadel's real code, with machine-checked
pass/fail.

## Canonical environment

Ubuntu WSL2, same as the production suite. Run `bash preflight.sh` first to see
what tooling is present and get an install hint per missing tool.

## Tiers

| Tier | What it attacks | Tooling (all free/OSS) | Pass criterion |
|---|---|---|---|
| **1**  | Primitive conformance to known attacks | Google **Wycheproof** vectors through Citadel's *exact pinned* aes-gcm/x25519/hkdf | 0 failures on Valid+Invalid vectors |
| **1b** | Citadel's own envelope *composition* (KDF/AAD binding, wire format, v1/v2 dispatch) | **proptest** against the real `Citadel::seal/open` SDK | every security-guarantee property holds; 0 counterexamples |
| **2**  | Memory safety / undefined behavior | **cargo miri** (UB), ASan/UBSan on the FFI boundary | 0 UB reports, 0 sanitizer hits |
| **2b** | Supply chain | **cargo-deny**, **cargo-audit**, **cargo-vet**, osv-scanner on SBOM | 0 *shipped* advisories; every finding explained (shipped vs test-only) |
| **3**  | Parser / decoder robustness, sustained | **cargo-fuzz** (libFuzzer) + **AFL++** second engine, ASan-instrumented | 0 crashes over a sustained run; coverage tracked |
| **4**  | Constant-time / side-channel | **dudect** (have) + **DATA**/**MicroWalk** binary trace analysis | attacker-controlled-input classes pass; key-material effect localized or bounded |
| **5**  | *Proof* of parser panic/UB-freedom | **Kani** bounded model checking on the wire parsers | VERIFICATION SUCCESSFUL for all inputs ≤ bound |
| **6**  | *Exhaustive* concurrency correctness | **Loom** — every thread interleaving of the one-shot nonce | invariants hold under all schedules; no deadlock |
| **7**  | Runtime memory safety | **AddressSanitizer** (+leak) on the FFI | 0 sanitizer errors |
| **8**  | Constant-time as a *proof* | **ctgrind** / **DATA** / **haybale-pitchfork** on ML-KEM decap | CT proven, or leak located (needs valgrind/LLVM install) |
| **9**  | Cryptographic *design* soundness | hand review vs the KEM-combiner literature | combiner is IND-CCA2-robust or a flaw is named |

**Depth ladder.** Tiers 1–4 are the sampling/measurement layer (vectors, property
tests, fuzz smoke, statistical timing). Tiers 5–9 are the *proof/exhaustive/design*
layer that a serious audit reaches for: Kani **proves** (not samples), Loom is
**exhaustive** (not probabilistic), Tier 9 is human **design** reasoning no tool
produces. Passing 1–9 is still necessary-but-not-sufficient for a paid audit — Tier 9
is analytical, not a machine-checked crypto proof, and no free tool supplies a named
cryptographer's liability-bearing signoff.

Tier 1/1b, 5 (`tier5_kani/`), and 6 (`tier6_loom/`) live as **standalone-workspace**
crates — own `Cargo.lock`, excluded from the production workspace, so
`cargo test --workspace --locked --offline` stays pristine. Tier 1's primitive deps
are pinned to the exact versions in `citadel_v3/Cargo.lock`.

Tiers 2/2b/3/4/7 operate on the production workspace directly (invoked by `run.sh`).
Tier 8 is specified in [`tier8_ct/CONSTANT_TIME_PLAN.md`](tier8_ct/CONSTANT_TIME_PLAN.md);
Tier 9 is [`tier9_design/HYBRID_COMBINER_ANALYSIS.md`](tier9_design/HYBRID_COMBINER_ANALYSIS.md).

## Running

```bash
bash preflight.sh          # what's installed
bash run.sh                # all available tiers -> receipts/ + one summary
bash run.sh tier1 tier2b   # a subset
```

Receipts land in `receipts/`. `run.sh` prints one PASS/FAIL summary and exits
non-zero if any executed tier fails.

## Status log

See `receipts/` for the latest machine output. Headline as of the last run is
kept in `receipts/SUMMARY.md`.
