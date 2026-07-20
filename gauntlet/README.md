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

Tier 1/1b live in [`tier1_vectors/`](tier1_vectors/) as a **standalone-workspace**
crate — its own `Cargo.lock`, excluded from the production workspace, so
`cargo test --workspace --locked --offline` in the parent stays pristine. Its
primitive deps are pinned to the exact versions in `citadel_v3/Cargo.lock`, so
Tier 1 validates the versions Citadel actually ships.

Tiers 2/2b/3/4 operate on the production workspace directly and are invoked by
`run.sh` — no new crate.

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
