# Citadel timing validation model

Citadel's timing rule is secret independence, not equal time for every input.

Constant-time discipline means control flow, memory access patterns, and timing must not depend on secrets. It does not mean attacker-chosen malformed public inputs must cost the same as valid ciphertexts. Public-format differences are allowed to differ in timing when the attacker can classify the input without knowing any secret.

## Secret and public inventories

Secrets:

- decapsulation/private keys;
- decapsulated shared secrets;
- KDF output and AEAD keys;
- tag-comparison intermediates;
- unauthenticated plaintext before authentication succeeds.

Public inputs / public outcomes:

- envelope length and structural parse validity;
- public suite/version/header bytes;
- attacker-provided AAD and context;
- the success/failure bit returned by the API;
- library-level public-format class, such as truncated vs parse-valid ciphertext.

## Enforced invariants

- Secret comparisons must use constant-time primitives such as `subtle`.
- KEM decapsulation must not leak secret-key-dependent information through distinguishable failure behavior.
- Unauthenticated plaintext must never be released on failure.
- API errors for decrypt failures must stay opaque.
- Remote `/api/decrypt` responses use a deadline-style response floor so obvious traffic-analysis cliffs do not expose key existence or lifecycle state.

## Known limitation: key-value-dependent decapsulation timing (platform-level)

### Finding

Source inspection of the ML-KEM-768 implementations found no ordinary
constant-time violations:

- no secret-dependent branches;
- no secret-dependent table lookups;
- fixed-size loops;
- constant-time verify/cmov patterns;
- arithmetic-only Montgomery reduction and NTT operations.

However, bare-metal dudect testing on dedicated x86-64 Linux hardware shows
reproducible key-material-dependent timing signals in ML-KEM-768 decapsulation.
Same-key and same-key/two-ciphertext-pool controls pass, so the harness is not
simply distinguishing ciphertext pools or class layout.

### Observed results

Tested on DigitalOcean Premium Intel vCPU (x86-64), Ubuntu 24.04,
Rust 1.96/1.97, release profile, 2026-07-09.

| Provider | Control (same-key) | key-A-vs-key-B |
|---|---|---|
| PQClean (pqcrypto-mlkem 0.1.1) | PASS, \|t\| = 2.18 | FAIL: 41, 17, 136 |
| libcrux (libcrux-ml-kem 0.0.9) | PASS, \|t\| = 1.92 | FAIL: \|t\| = 61 |
| AWS-LC (aws-lc-rs 1.17.1) | PASS, \|t\| = 2.20 | FAIL: 3.5, 36, 61, 1106, 47 |

No tested ML-KEM-768 provider consistently passed key-A-vs-key-B dudect on
tested x86-64 hardware. The cross-provider reproduction (three independently
developed implementations, two languages, one C-with-assembly) rules out an
implementation-specific code defect with high confidence.

### Interpretation

This is **not** evidence of a cryptographic break of ML-KEM.

This is **not** evidence that the source code branches on secrets.

It **is** evidence that current ML-KEM-768 decapsulation, on this tested
hardware and build environment, has not been locally validated as
key-material-timing-independent.

### Likely cause

Below-source-level microarchitectural effects. ML-KEM polynomial arithmetic
necessarily performs many multiplications involving secret coefficients
(`fqmul` → `(int32_t)a * b` where `a` is a secret key coefficient). Even when
source code is branchless and memory access is fixed, modern x86-64 CPUs can
expose value-dependent timing through:

- data-operand-dependent instruction timing in integer multipliers;
- power/frequency response to operand values (Hertzbleed-class);
- cache/prefetch effects on large key objects (2400-byte secret keys);
- other microarchitectural mechanisms.

This is consistent with published Hertzbleed-class concerns, where
constant-time source discipline is not sufficient to guarantee timing
independence on real CPUs.

### Attacker-controlled-input classes

All attacker-controlled-input timing classes pass dudect:

- ciphertext variation (different valid ciphertexts, same key): PASS
- tag/AAD corruption (two failure modes): PASS
- KEM-byte corruption (two corruption positions): PASS

The dependence is on **static key material**, which an attacker cannot vary
per query. The service layer additionally applies opaque errors and a
deadline-scheduled response floor. An attacker querying `/api/decrypt` varies
the ciphertext, and the ciphertext-variation classes pass.

### What this blocks

- "Constant-time validated" — **cannot claim.**
- "Side-channel proof" or "side-channel hardened" — **cannot claim.**
- Certification-style timing claims — **blocked until resolved.**

### What this does not block

- Ordinary networked production use with opaque errors, response floors,
  and rate limits — **not automatically blocked.**
- FIPS 203 compliance (the algorithm is correct) — **not affected.**
- Post-quantum security claims (the cryptographic construction is sound) —
  **not affected.**

### Required wording for grant and security materials

> Citadel uses standardized FIPS 203 ML-KEM-768 in a hybrid construction with
> X25519 and AES-256-GCM. The production ML-KEM provider is RustCrypto `ml-kem`
> 0.3.2 (pure Rust). It largely follows constant-time discipline; a ctgrind
> (valgrind) analysis localized one secret-indexed table lookup (`Eta::ONES[val]`)
> in the crate's CBD noise sampling. For the ML-KEM-768 parameter set that table
> is 32 bytes — a single cache line, with an always-in-range index — so it is not
> practically exploitable, though it remains a constant-time anti-pattern in the
> dependency (see `gauntlet/tier8_ct/`). Our dudect-based timing
> validation suite passes all attacker-controlled-input classes (ciphertext
> variation, tag corruption, AAD corruption, KEM-byte corruption).
>
> Key-value-dependent decapsulation timing is detectable at the microbenchmark
> level on tested x86-64 hardware, reproduced across three independently
> developed ML-KEM implementations (PQClean, libcrux, AWS-LC). Source
> inspection found no code-level constant-time violations; the effect is
> consistent with hardware-level data-dependent execution
> (Hertzbleed-class). This is documented as a known platform-level
> limitation. We do not claim constant-time validation or side-channel
> hardening for ML-KEM decapsulation on this platform.
>
> The service boundary applies opaque error responses, response-time floors,
> and three-tier rate limiting. No remotely exploitable timing oracle has been
> demonstrated.

### Production risk assessment

The observed dependence is on static key material, not on attacker-supplied
input. A remote attacker querying `/api/decrypt` varies the ciphertext; the
per-key timing offset is constant across every query against a given key, so
it does not give a query-adaptive oracle. What it could leak, in the worst
case, is a small amount of information about the static key
(Hertzbleed-style attacks need exactly this shape, and they require
co-residency, enormous query volumes, and no frequency pinning).

Deployments where caution is warranted:

- hostile-multitenant hosts sharing cores with untrusted code;
- long-lived high-value static keys serving unbounded decapsulation queries.

For those deployments, key rotation and dedicated tenancy reduce exposure.

### Recommended mitigations

1. Keep remote API response floors and opaque errors.
2. Rate-limit decrypt attempts (already implemented: three-tier rate limiting).
3. Avoid exposing raw decapsulation as an attacker-queryable oracle.
4. Document that local co-resident attackers are out of scope unless hardware
   isolation is provided.
5. Prefer hardware isolation (TEE, dedicated tenancy) for high-assurance
   deployments.
6. Track provider and CPU behavior over time.
7. Re-run dudect on multiple CPU families (AMD, ARM) to characterize the
   effect across microarchitectures.
8. Consider adding an alternate KEM or fallback once additional NIST standards
   are available.

### Do not fix by adding delays

Do not add dummy work, artificial delays, or timing equalization inside the
ML-KEM decapsulation path. Such fixes are optimizer-fragile, drift from the
real execution path over time, add complexity to security-critical code, and
do not address the root cause (hardware data-dependent execution).

If remote equalization is required, enforce it at the service boundary with
opaque errors and a response floor — not inside the crypto primitive.

### Follow-up work (priority order)

1. **Effect size (Δ):** Measure the median per-call timing difference between
   key A and key B in nanoseconds with confidence intervals. Sub-nanosecond
   Δ materially strengthens the "not practically exploitable" argument.
2. **CPU frequency pinning:** Re-run with turbo boost disabled and CPU
   governor set to fixed frequency. If the signal collapses, it localizes
   to power/frequency response (cleanest possible explanation).
3. **Multiple key pairs:** Test 20+ random A/B pairs to show the effect is
   generic, not a quirk of two particular keys.
4. **Second microarchitecture:** Test on AMD and/or ARM to determine if the
   effect is Intel-specific.
5. **Instrumentation-level analysis:** Run one provider through
   Microwalk/ctgrind/valgrind secret tainting to formally separate "code is
   CT" from "hardware isn't."
6. **Gate criterion refinement:** For key-value classes, adopt a compound
   gate: fail on |t| > 4.5 **and** Δ above a stated floor (a few cycles).
   Retain |t|-only gating for attacker-controlled-input classes where zero
   tolerance is correct.

## P-384 ECDH arm (suite `0xA4`) — harness + preliminary screen

Suite `0xA4` adds one new secret-dependent primitive over `0xA3`: **P-384 ECDH** via the
pure-Rust `p384` crate (the ML-KEM-1024 arm is the same family as the already-characterized
ML-KEM-768). The classical arm is isolated for dudect by
`kem_p384::diagnostic_p384_ecdh_only` (feature `timing-diagnostics`), which runs exactly the
ECDH `decapsulate` performs — parse the ephemeral point, `diffie_hellman` with the static
scalar, return the 48-byte x-coordinate. Two benches in `benches/timing_sidechannel.rs`:

| Bench | Tier | Leak it catches |
|---|---|---|
| `bench_stage_p384_ecdh_key_a_vs_key_b_success` | Diagnostic | Static-key-material-dependent timing in P-384 ECDH. Not attacker-varyable per query. |
| `bench_stage_p384_ecdh_same_key_pool_a_vs_pool_b_control` | Harness control / attacker-controlled screen | Two pools of *varying* valid ciphertexts, same key — same public class. This is both the null control AND the remote-relevant ciphertext-variation screen. |
| `bench_info_p384_ecdh_fixed_vs_random_ciphertext` | Informational | One *identical* ciphertext repeated vs varying — deliberately NOT same-public-class; demonstrates the fixed-input cache artifact. Not a gate. |

### Preliminary screen — 2026-07-26 (NOT authoritative)

Run on a **noisy WSL2-on-Windows dev box** (release, `--features timing-diagnostics`), which
is explicitly *not* the quiet dedicated Linux the ML-KEM results above used. Sub-threshold
values drift run-to-run on this box (e.g. key-A-vs-key-B read 1.51 then 2.15) but stay `< 4.5`:

| Bench | max \|t\| | n (post-crop) | verdict |
|---|---|---|---|
| `..._key_a_vs_key_b_success` | ~1.5–2.2 | ~13K (est. ~70–142K needed) | no signal, but **underpowered** |
| `..._same_key_pool_a_vs_pool_b_control` | ~1.4–2.5 | ~43–100K | no signal (same-public-class) |
| `bench_info_..._fixed_vs_random_ciphertext` | **~106** | 46K | **artifact, not a leak** (see below) |

**The `~106` is not a leak — and reading it correctly is the whole point.** That bench compares
one *identical* ciphertext repeated against varying ciphertexts, which is not a same-public-class
comparison: the fixed input stays cache/branch-predictor-hot and runs systematically faster,
regardless of any secret. The decisive disambiguator is the same-public-class control immediately
above it — *varying-vs-varying valid ciphertexts, same key* — which stays `< 4.5`. If the ECDH
leaked on ciphertext value or key material, that control would move; it does not. So the huge `t`
localizes to the fixed-input measurement artifact and confirms this file's "same-public-class
only" rule, rather than indicating a timing oracle.

### Box-capability baseline — this box DOES detect a real key-material leak (2026-07-26)

The "noisy box, can't conclude" caveat is largely answered by a control experiment: run the
**ML-KEM** key-material benches under the *identical harness on the identical box*. If the box
can surface ML-KEM's documented Hertzbleed-class signal, then a P-384 null result is meaningful,
not just insensitivity.

| Bench (same box, same harness) | max \|t\| | n | (5/tau)^2 | verdict |
|---|---|---|---|---|
| `rustcrypto_mlkem_key_a_vs_key_b` | **38.5** | 38K | 647 | **signal — well-powered** |
| `stage_mlkem_key_a_vs_key_b` | **27.8** | 59K | 1923 | **signal — well-powered** |
| `rustcrypto_mlkem_same_key` controls (×2) | ≤ 1.7 | 65–100K | — | clean |
| `stage_mlkem_same_key` controls (×2) | ≤ 1.4 | 77–99K | — | clean |
| **`p384_ecdh_key_a_vs_key_b`** | **1.8** | 13K | — | **no signal** |

So on this exact hardware the harness catches ML-KEM's key-material dependence decisively
(`|t|` 38.5 / 27.8, controls clean) — yet **P-384 ECDH shows no such signal (`|t|` 1.8)**. That
makes the P-384 result a **meaningful comparative negative**: the P-384 arm does *not* exhibit
the ML-KEM-magnitude key-material timing dependence. A signal as strong as ML-KEM's would have
shown even at 13K samples.

It is still **not** a full constant-time validation:
- A *subtler* sub-threshold leak (weaker than ML-KEM's) below the box's sensitivity floor at
  ~13K cropped samples is not excluded — that needs the quiet dedicated-Linux run at full
  samples with frequency pinning.
- But this is far stronger than "inconclusive": the box is demonstrably capable, and P-384 came
  back clean where ML-KEM came back loud.

**What the attacker-controlled screen shows:** the remote threat model (attacker varies the
ciphertext, not the key) maps to the same-public-class pool control, which is **clean** (`|t|`
≤ 2.9) — consistent with the ML-KEM attacker-controlled classes that pass on quiet hardware.

**Claim-matrix status:** row 1 stays *not established* (dudect never *proves* constant-time),
but the evidence is now "no signal detected, on a box that provably detects ML-KEM's signal" —
materially stronger than the first screen.

**Claim status unchanged:** *"The P-384 ECDH implementation is constant-time on the shipped
path"* remains **NOT established** (spec 033 §7 claim-matrix row 1). This screen adds a built,
reproducible harness and a preliminary no-detection, nothing stronger.

**Authoritative next step (Andre / dedicated hardware):** run both benches — plus the
attacker-controlled ciphertext-variation class, which is the one that matters for the remote
API — on a quiet Intel/AMD/ARM Linux box with frequency pinning, per the "Quiet-machine
validation run procedure" below, at full 100K+ samples. Only then can the P-384 arm be
characterized the way ML-KEM-768 was.

## Dudect bench policy

Hard-gated dudect benches compare only same-public-class inputs: same public wire shape, same parse outcome, and same observable success/failure class. A gated pair must name the leak it would catch.

| Bench | Tier | Leak it catches |
|---|---|---|
| `bench_tag_first_byte_vs_last_byte_failure` | Gate | Early-exit AEAD tag comparison. |
| `bench_wrong_aad_vs_wrong_tag_failure` | Gate | Secret-dependent divergence in the authentication failure path. |
| `bench_kem_corruption_a_vs_b_failure` | Gate | KEM/KDF behavior that differs by corrupted KEM value rather than following an implicit-rejection style pipeline. |
| `bench_key_material_fixed_vs_random_success` | Diagnostic gate | Timing dependence on key material during successful decrypt. This only blocks release if the matching null-control bench passes. |
| `bench_null_fixed_vs_random_harness_control` | Harness control | Same fixed-vs-random class construction as the key-material diagnostic, but with key-independent dummy work. If this exceeds threshold, the fixed-vs-random harness is confounded by layout/cache/input-selection effects. |
| `bench_stage_*` | Diagnostic | Localizes a failing key-material diagnostic to hybrid KEM, X25519-only, ML-KEM-only, KDF, AEAD, or key-A-vs-key-B controls. Stage diagnostics are logged for root-cause analysis; the top-level release decision remains the primary key-material diagnostic plus its null control. |
| `bench_stage_mlkem_same_key_shared_buffer_control` | Harness control | Confirms the ML-KEM shared-buffer harness does not distinguish arbitrary dudect classes when key material is fixed. |
| `bench_stage_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success` | Harness control | Confirms two independent valid ciphertext pools for the same ML-KEM key do not explain a key-A-vs-key-B signal. |
| `bench_stage_mlkem_key_a_vs_key_b_shared_buffer_success` | Provider diagnostic | Detects secret-key-material-dependent timing in the active ML-KEM provider after address/layout and ciphertext-pool controls pass. |
| `bench_pqclean_mlkem_*` | Provider comparison | Dev-only PQClean-backed comparison benches. |
| `bench_info_valid_vs_short_public_format` | Informational | Expected public-format timing gap from structural parse early return. |
| `bench_info_wrong_key_a_vs_b_failure` | Informational | Wrong-key failure behavior; useful drift signal, but not a clean gate because it mixes key variation with guaranteed authentication failure. |

Use the standard dudect threshold (`|t| < 4.5`) for gated benches. A persistent `|t|` above threshold, especially one that grows with sample count across independent runs, is a release blocker for gated classes.

The fixed-vs-random key-material bench has a paired null control. Interpret it as follows:

- key-material passes and null control passes: no timing signal detected in that diagnostic;
- key-material fails and null control passes: block release and localize the signal across ML-KEM decapsulation, KDF/AEAD, X25519, and envelope glue;
- key-material fails and null control also fails: mark REVIEW, because the measurement harness itself distinguishes classes before proving a primitive leak;
- key-material passes and null control fails: mark REVIEW and repair the harness before relying on that diagnostic.

When localization is needed, prefer interpreting key-A-vs-key-B stage controls before fixed-vs-random stage controls. A fixed-vs-random stage result can be contaminated by cache residency or key-object reuse patterns; key-A-vs-key-B keeps both classes hot and gives stronger evidence of key-material-dependent timing.

For large secret objects such as ML-KEM-768 decapsulation keys, key-A-vs-key-B
diagnostics must use a matching shared-buffer null control before they are
treated as evidence. The control copies selected key/ciphertext bytes into the
same preallocated buffers before the timed closure and assigns classes
independently of the selected sample. If that control passes, a key-A-vs-key-B
shared-buffer failure is stronger evidence that the provider/platform remains
timing-distinguishable after address/layout effects have been removed.

Informational benches are logged but ignored by the release gate. They are drift detectors: if a public-format timing gap changes shape after a refactor, investigate whether secret-dependent work moved across a public parse boundary.

## HTTP timing policy

HTTP timing is evaluated separately from library dudect.

- Public-class differences may use practical thresholds. Statistical significance alone is expected with enough samples.
- Secret-dependent HTTP pairs must not get a magnitude escape hatch. If a same-secret-class signal reproduces across independent runs and grows with sample count, the response floor failed and the release should block.
- Low-sample p99/max values are not hard gates. At small `n`, one scheduler spike can dominate the maximum. A suspicious tail should trigger a larger-sample run, not an immediate fix-by-guessing.

## Quiet-machine validation run procedure

All timing validation runs in WSL Ubuntu or bare-metal Linux. Never run cargo
on Windows directly (SAC blocks unsigned build scripts).

### Standalone ML-KEM repro (no Citadel envelope)

The `mlkem_standalone` bench calls PQClean, libcrux, and AWS-LC ML-KEM-768
directly — no Citadel types, no hybrid wrapper, no KDF, no AEAD.

```bash
cd /path/to/citadel-v3
source ~/.cargo/env 2>/dev/null || true

# Controls — must stay |t| < 4.5
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter pqclean_same_key_control
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter pqclean_same_key_two_pool_control

# Key-A-vs-key-B — all three providers
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter pqclean_key_a_vs_key_b
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter libcrux_key_a_vs_key_b
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter awslc_key_a_vs_key_b
```

### Full Citadel timing suite

```bash
# Controls
cargo bench --bench timing_sidechannel -p citadel-envelope -- --filter bench_stage_mlkem_same_key_shared_buffer_control
cargo bench --bench timing_sidechannel -p citadel-envelope -- --filter bench_stage_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success

# Key-A-vs-key-B through Citadel wrapper
cargo bench --bench timing_sidechannel -p citadel-envelope -- --filter bench_stage_mlkem_key_a_vs_key_b_shared_buffer_success
```
