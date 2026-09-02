# CITADEL_AUDIT — consistency audit of citadel-v3

**Baseline:** upstream `master` @ `31deefe` (2026-09-02). **Produced on:** the fork `LuckyCody/citadel-v3`, 2026-09-02.

## What this is — and is not

This is a **consistency audit**: claims-vs-code, surface inventory, reproducibility of the documented paths, code quality, docs coherence, and structure. **It is not a security audit.** No cryptanalysis was performed, no penetration testing, no exploit development. Citadel's own README says "unaudited" — **that remains true after this document.** Nothing here is third-party security assurance. Where this audit found anything vulnerability-*shaped*, it is not in this document or anywhere on this fork; it went to the maintainer's private channel per SECURITY.md.

Method: seven sections, every finding carrying file:line on both sides (the claim and the code), so any row can be falsified in minutes. To reproduce the whole audit from scratch instead of trusting it: `audit/prompts/1-audit.md` against a clean clone.

## Executive summary

**The headline is positive and specific.** Of 51 checkable claims verified in §0: **38 VERIFIED** — including every headline crypto claim (CryptoVerif combiner proofs exist with "All queries proved" receipts for both 0xA4 arms; ACVP 60/60 vectors verified in JSON and test loops; the independent ML-KEM differential is real, against libcrux; the malleability-sweep counts reproduce *arithmetically exactly* from envelope sizes: 5,099 = 4×1,273+7). The project's own CI — fmt, clippy `-D warnings`, ~320 workspace tests, KAT/ACVP gates, stress, audit, live-server tests, Schemathesis — **passes fully green on a clean fork clone with zero secrets** (§2, public run links inside). The four ⏳ PENDING rows in VALIDATION_MATRIX are disclosed, not hidden. This maintainer documents more honestly than most funded teams.

**The 13 non-verified claims and the structural findings, by weight:**

1. **WIRE_SPEC.md is wrong, not just stale** (§4): the v1 spec marked "FINAL" mandates a two-stage HKDF with labels (`citadel-hybrid-*`) that never existed in shipped code. An implementer following it produces undecryptable ciphertexts. SPEC.md is the correct v1 record; the fix is a quarantine banner + canon declaration (exact texts in §4 §2.5).
2. **WIRE_SPEC_V2 vs encoder** (§0): the "frozen" v2 spec says KDF/AAD bind the full 98-byte header; code deliberately binds the 86-byte nonce-free prefix (FIPS GCM Scenario 2, the repo's own packet 056). Spec must catch up or interop breaks — decision question Q1.1.
3. **Three endpoint inventories, none complete** (§1): 27 routes in code, 18 in README, 24 in a buried openapi.yaml; the entire ML-DSA/assertion surface was undocumented.
4. **Four dashboards** (§1): the API serves a crate-internal file; the three root-level dashboard files are a stale twin and two fake-data simulations, referenced by nothing.
5. **Docs contradict each other** in 5 HIGH / 7 MEDIUM spots (§4): FIPS/CMVP status (one doc says "NOT validated" against five saying CMVP-validated, and cites a file that doesn't exist), replay durability overstated in two docs vs code's batched 5s/100-op window, a replay doc documenting env vars that don't exist, compliance totals 26/7/1 vs the matrix's own 27/6/1.
6. **Reproducibility catches** (§2): the documented example exits on an env-var mismatch (`CITADEL_KEY` vs `CITADEL_API_KEY`); `cargo deny check` fails on a yanked chacha20 while CI masks it with `|| true`; the judge's `--offline` default surprises judge-first users. Everything else — build, tests, judge, fuzz, his full CI — reproduces, on Ubuntu **and** (undocumented) Windows.
7. **Code quality** (§3): the 23 FFI `unsafe` sites are exemplary (safety docs + catch_unwind on every entry); the HTTP crate is the inversion — 7 request-path panic sites, no panic-catch layer, and a master-key entropy check that panics per-request instead of at boot; 10 `Mutex::lock().unwrap()` in non-test keystore paths. Three TODOs total in 30k LOC. One 311-line orphan module.
8. **Walk-test failures** (§5): a fresh reader cannot determine the authoritative wire spec, the canonical validation entry point, or which dashboard is live, from the files alone. The §5 migration map fixes exactly that; the preservation ledger (§6, separate file) numbers every capability so no fix can silently drop one.

**Counts:** §0: 51 claims — 38 verified / 7 mismatch / 4 stale-path / 2 unverifiable (10 of 13 are doc-fixes; 2 need maintainer intent). §1: 13-row duplication matrix; 27-route table; 15 CLI commands; 12 FFI exports fully bound. §4: 5 HIGH / 7 MEDIUM / ~10 MINOR contradictions + 4 explicit all-clears. Execution state: every no-ruling-needed fix is implemented on `audit/phase-a-doc-truth`; consolidation on `audit/phase-b-consolidation`; restructure demo on `audit/phase-c-icm`; recommendation-gated items on `audit/phase-d-rulings` — each with a committed `LEDGER_CHECK` and green CI. `DECISION_QUESTIONS.md` is the walkthrough that turns the rest into one-line rulings.

---
# §0 — Claims vs. Code

**Scope:** consistency audit (not a security audit) of the checkable claims in the ~33 root documents of `C:\Data\citadel-v3` against the code, tests, receipts, and git history in the same clone. **Method:** every significant claim was traced the hard way — the cited test/file was opened, the test body read to confirm it tests what the claim states (not something adjacent), loop counts and constants compared against quoted numbers, the wire encoders walked field-by-field against the spec tables, the axum router diffed against the README endpoint table, and CHANGELOG dates reconciled against `git log` (132 commits, 2026-07-09 → 2026-08-17, **no git tags**). Where a claim references an external run (GitHub CI, the recorded adversarial gate run), it is marked UNVERIFIABLE rather than assumed either way. Overall verdict up front: **this codebase is unusually honest** — the headline cryptographic claims (CryptoVerif proofs, ACVP 60/60, malleability sweep, sustained-fuzz receipt, constant-time comparison, hash-chained audit log, uniform errors) all check out, several to exact-arithmetic precision. The mismatches found are overwhelmingly stale documentation lagging a moving implementation, concentrated in three files (VALIDATION_MATRIX test names, TIMING.md's PQClean-era procedure, REPLAY_TRUST_BOUNDARIES' env vars/modes), plus one real spec-vs-code divergence in WIRE_SPEC_V2 §4.

## Verification table

| # | Claim | Claimed where (file:line) | Code reality (file:line) | Verdict | Severity |
|---|-------|---------------------------|--------------------------|---------|----------|
| 1 | Machine-checked CryptoVerif proof: `0xA4` combiner keeps derived key secret if either arm survives | README.md:244; CHANGELOG.md:27-29; VALIDATION_MATRIX.md:34-38 | `gauntlet/tier12_combiner_proof/citadel_combiner_ctd2_p384_arm.ocv` + `..._mlkem1024_arm.ocv`; receipts `receipt_ctd2_p384_arm.txt` / `receipt_ctd2_mlkem1024_arm.txt` end "RESULT Proved secrecy of K …" + "All queries proved." Statement matches the claim (each arm proof assumes the other arm fully broken). `0xA3` arms likewise receipted. | VERIFIED | — |
| 2 | ProVerif symbolic analysis: secrecy + no-downgrade proved | gauntlet/receipts/SUMMARY.md tier 11 row; README.md:245 (fuzzing/verification bullet set) | `gauntlet/tier11_proverif/citadel_envelope.pv` + `receipts/tier11_proverif.txt:11-13`: secrecy PROVED, no-downgrade PROVED, replay-injectivity honestly marked INCONCLUSIVE (tool limitation, cross-referenced to Loom tier 6) | VERIFIED | — |
| 3 | ML-KEM ACVP vectors pass 60/60 against production provider | VALIDATION_MATRIX.md:32; CHANGELOG.md:30-32 | `citadel-envelope/tests/production_mlkem_acvp.rs:58-90` (25 keygen + 25 encap + 10 decap = 60); `acvp_mlkem768_vectors.json` counts confirmed 25/25/10; ML-KEM-1024 mirror in `acvp_mlkem1024.rs:84-134` + `acvp_mlkem1024_vectors.json` 25/25/10 | VERIFIED | — |
| 4 | Byte-for-byte differential against a second, independent ML-KEM implementation | README.md:242 | libcrux: `production_mlkem_acvp.rs:147` `selected_provider_matches_independent_libcrux_on_all_60_vectors`; plus AWS-LC differential `citadel-envelope/tests/awslc_mlkem_differential.rs` | VERIFIED | — |
| 5 | Malleability sweep: every tampered input rejected, zero forgeries, zero panics, "thousands of mutations and truncations per backend" | README.md:243; CHANGELOG.md:50-52 | `citadel-envelope/tests/ringer.rs:36-137` (`malleability_sweep_a3`/`_a4`, catch_unwind, asserts accepted==0 && panicked==0). Whitepaper counts (5,099 a3 / 7,279 a4 per backend) are **arithmetically exact**: 4 muts/byte × 1,273-byte a3 envelope + 7 truncations = 5,099; 4 × 1,818-byte a4 envelope + 7 = 7,279 | VERIFIED | — |
| 6 | "200,000 seals produce distinct nonces" | README.md:243; CHANGELOG.md:52; whitepaper/CITADEL_WHITEPAPER.md:293 | In-repo tests: `security_stress.rs:199-226` runs **10,000**; `ringer.rs:234-241` defaults to **20,000** (`RINGER_NONCE_SEALS` env override exists). No checked-in receipt, script, or CI config sets 200,000; the figure traces only to the whitepaper's narrative of a separate recorded run | UNVERIFIABLE (mechanism verified; count not reproduced in-repo) | doc-fix |
| 7 | Cross-suite envelopes are rejected | README.md:243 | `ringer.rs:267` `cross_suite_reject_matrix` + dedicated `citadel-envelope/tests/suite_confusion_swarm.rs` | VERIFIED | — |
| 8 | Fuzzing of wire parser, full decryption path, seal/open round trip, FFI free path | README.md:245 | `fuzz/` targets confirmed via corpus table: decode_wire, fuzz_wire_parse, decode_envelope_v2, decrypt_full, fuzz_decrypt, decrypt_v2_mutation, fuzz_roundtrip, fuzz_ffi_free (gauntlet/receipts/tier3_sustained_campaign.txt:33-42) | VERIFIED | — |
| 9 | Sustained fuzz: 27 days, 24 completed runs, 884-file corpus, 0 crashes | gauntlet/receipts/SUMMARY.md tier 3 row (claim echoed in recent commits) | `gauntlet/receipts/tier3_sustained_campaign.txt:7-31`: window 2026-07-21→08-17 = 27 days ✓; 31 batch runs, **24 completed**, 7 non-starts explained ✓; corpus table sums 877+7 = **884** ✓; "Zero crashes" ✓ | VERIFIED | — |
| 10 | ctgrind localizes residual to `Eta::ONES[val]` 32-byte single-cache-line table in ml-kem CBD sampling; Citadel's own code has 0 secret-dependent branches | TIMING.md:124-132 ("see gauntlet/tier8_ct/"); SUMMARY.md tier 8 row | `gauntlet/receipts/tier8_ct.txt:14-50`: iteration-2 result, all residual branches in `ml_kem::algebra::sample_poly_cbd` (algebra.rs:114-125), ONES = 16 × u16 = 32 bytes, one cache line, index always in range; zero flags in envelope/kdf/aead/wire. Harness present at `gauntlet/tier8_ct/ctgrind_harness/` | VERIFIED | — |
| 11 | dudect bench suite exists as documented (gate/control/diagnostic benches incl. P-384 benches) | TIMING.md:216-222, 374-388 | `citadel-envelope/benches/timing_sidechannel.rs:86-1357` — every bench named in TIMING.md's policy table exists, including `bench_stage_p384_ecdh_key_a_vs_key_b_success:1283`, `..._pool_a_vs_pool_b_control:1316`, `bench_info_p384_ecdh_fixed_vs_random_ciphertext:1357`; `kem_p384.rs:294` `diagnostic_p384_ecdh_only` behind `timing-diagnostics` feature | VERIFIED | — |
| 12 | Quiet-machine repro procedure: "`mlkem_standalone` bench calls PQClean, libcrux, and AWS-LC"; filters `pqclean_same_key_control`, `pqclean_key_a_vs_key_b`; policy row `bench_pqclean_mlkem_*` "dev-only PQClean benches" | TIMING.md:423-439, 385 | **PQClean is absent from the tree.** `grep pqclean\|pqcrypto` over all .rs/.toml: zero hits. `benches/mlkem_standalone.rs:11-20` provides `libcrux_*`, `rustcrypto_*`, `awslc_*` only. Provider was switched PQClean→RustCrypto (CHANGELOG.md:41-44); the historical results table (TIMING.md:56-60, PQClean 0.1.1) is legitimately historical, but the *runnable* procedure and bench-policy row cite commands that cannot run | STALE-PATH | doc-fix |
| 13 | Compliance: "34 controls: 26 satisfied, 7 partial, 1 gap" | README.md:258 | COMPLIANCE_MATRIX.md:23 summary says **27 / 6 / 1**; manual row count of all six sections (6+8+5+6+5+4 = 34 rows) confirms 27 SATISFIED, 6 PARTIAL, 1 GAP — the matrix is internally consistent; README's split is stale (CHANGELOG.md:12-14 says the matrices were reconciled; README wasn't) | MISMATCH | doc-fix |
| 14 | Compliance spot-check: key states = Pending/Active/Rotated/Suspended/Revoked/Destroyed (2.6) | COMPLIANCE_MATRIX.md:49 | `citadel-keystore/src/types.rs:142-160` — exactly those six variants | VERIFIED | — |
| 15 | Compliance spot-check: explicit activation Pending→Active (2.2) | COMPLIANCE_MATRIX.md:45 | `types.rs:177` valid_transitions Pending→[Active, Destroyed]; route `/api/keys/:id/activate` (citadel-api/src/main.rs:3345) | VERIFIED | — |
| 16 | Compliance spot-check: OS CSPRNG keygen (2.1) | COMPLIANCE_MATRIX.md:44 | `citadel-envelope/src/kem.rs:38,379,391` `OsRng` (rand_core/getrandom); `getrandom` in Cargo.toml:58-59 | VERIFIED | — |
| 17 | Compliance spot-check: per-IP token-bucket rate limiting with burst + threat escalation (4.6) | COMPLIANCE_MATRIX.md:72 | `citadel-api/src/main.rs:342-348` `ip_buckets`/`key_buckets`/`global_bucket: Mutex<TokenBucket>` + burst; tests `it_rate_limit_activates_under_spam`, `it_wrong_key_spam_is_rate_limited` exist in main.rs | VERIFIED | — |
| 18 | Compliance spot-check: tamper-evident SHA-256 hash-chained JSONL audit log (5.3/6.3) | COMPLIANCE_MATRIX.md:80,90; README.md:233 | `citadel-keystore/src/audit.rs:343-399`: integrity-chain sink, monotonic `sequence`, `prev_hash` = SHA-256 of previous event JSON, genesis = SHA-256("citadel-audit-genesis"); tests `audit_chain_records_lifecycle_events`, `audit_chain_tamper_is_detectable` in same file | VERIFIED | — |
| 19 | Constant-time API-key comparison via `subtle` | README.md:230; SECURITY_GUARANTEES.md:89; VALIDATION_MATRIX.md:182-183 | `citadel-api/src/main.rs:45` `use subtle::ConstantTimeEq`; `:232-240` `authenticate()` compares hex(SHA-256(provided)) vs stored hash with `stored.ct_eq(provided)` after length check | VERIFIED | — |
| 20 | All shared secrets and AES keys wrapped in `Zeroizing<T>` | README.md:231; COMPLIANCE_MATRIX.md:48,68 | Backend trait returns `Zeroizing<Vec<u8>>` for encapsulate/decapsulate (`backend.rs:73-78`); combined SS `kem.rs:400-403`; derived AES keys wrapped at every use site: `wire_v2.rs:299,332,369`, `stream.rs:154,258`, `stream_v3.rs:101,179,378`; AWS-LC backend mirrors (`backend_awslc.rs:75-500`). `kdf.rs:36` documents the returned-bare/caller-wraps contract, and all callers comply | VERIFIED | — |
| 21 | Uniform decryption errors — identical opaque error for all decrypt failures (no oracle) | README.md:232; API_FREEZE.md:105; TIMING.md:30-31 | `citadel-api/src/main.rs:2047-2085`: authz-denied and crypto-failure both return 400 + `"operation failed"` + request_id; `timing_dummy.burn()` on the early path; absolute-deadline response floor `main.rs:1976,2002` (`sleep_until(response_deadline)`) — matches TIMING.md's "deadline-style response floor" | VERIFIED | — |
| 22 | Auth failures written to tamper-evident audit chain, not just rotating log | SECURITY_GUARANTEES.md:28-31 | `citadel-api/src/main.rs:1133-1135`: "P158: write auth failure to tamper-evident audit chain" → `AuditAction::AuthFailed`; `audit.rs:88` documents the same | VERIFIED | — |
| 23 | Key hierarchy tests p211_*/p184_*/p063_* exist and test what's claimed | VALIDATION_MATRIX.md:46-55 | All eight named fns present in `citadel-keystore/tests/vertical_slice.rs` (dek_under_domain, dek_under_root, kek_under_root, domain_under_kek, root_with_parent, correct_full_hierarchy, flat_dek_requires_parent, flat_dek_override) | VERIFIED | — |
| 24 | `CITADEL_ALLOW_FLAT_DEKS` requires `CITADEL_ENV=development` | VALIDATION_MATRIX.md:54-55 | `citadel-keystore/src/keystore.rs:842-861`: override honored only when `CITADEL_ALLOW_FLAT_DEKS=1` **and** `CITADEL_ENV=development` | VERIFIED | — |
| 25 | citadel-api integration tests (`it_*`) exist: roundtrip, concurrent, replay-spam, corrupted-blob, rate-limit ×2, api-key lifecycle, scope enforcement, health | VALIDATION_MATRIX.md:52,65,87-89,105-108,117-122 | All ten `it_*` fns present in `citadel-api/src/main.rs` (in-file test module) | VERIFIED | — |
| 26 | Backup/restore tests: roundtrip, wrong master key, corrupted, empty | VALIDATION_MATRIX.md:150-153 | All four fns in `citadel-keystore/src/backup.rs` | VERIFIED | — |
| 27 | Validation script steps: no-auth 401, wrong key 401, replay before/after restart, KEK-under-Root rejected (P213) | VALIDATION_MATRIX.md:53,63-64,98-104 | `citadel_full_validation.ps1:212-280`: `Must-Fail` steps for all named checks incl. "KEK under Root is rejected (P211/P213)" (:227) and replay before/after restart (:257,:274); `citadel_multiprocess_replay_harness.ps1` exists at root (honestly marked ⏳ PENDING in the matrix) | VERIFIED | — |
| 28 | Test names `primitive_kat_*`, `hkdf_kat_*` | VALIDATION_MATRIX.md:28,30 | `citadel-envelope/tests/primitive_kat.rs` exists and contains the claimed *coverage* (HKDF RFC-5869 cases :48-109, AES-GCM NIST :178-285, SHA3 :321-339, X25519 :360-422), but **no fn matches the cited globs** — actual names are `hkdf_sha256_rfc5869_test_case_*`, `aes256gcm_nist_*`, etc. | STALE-PATH (names) | doc-fix |
| 29 | Test names `p006_*`, `p007_*`, `p012_wrong_key_*` | VALIDATION_MATRIX.md:29,31 | Zero hits anywhere in the repo (`grep -r "p006_\|p007_\|p012_"`). Equivalent coverage exists under different names (`aes256gcm_*` in primitive_kat.rs; `wrong_key_rejected` nist_acvp_kat.rs:218; `wrong_key_fails` security_stress.rs:71) — the *claims* hold, the cited evidence names do not exist | STALE-PATH (names) | doc-fix |
| 30 | Corruption tests `file_store_truncated_json_fails_closed`, `file_store_invalid_json_fails_safely` | VALIDATION_MATRIX.md:76-77 | Actual fns: `file_store_truncated_json_returns_err` (replay_store.rs:1141) and `file_store_invalid_json_returns_err` (:1177). Both assert Err (fail-closed) — behavior matches the row's "Safe recovery or fail-closed"; names stale | STALE-PATH (names) | doc-fix |
| 31 | "Missing CITADEL_MASTER_KEY blocks startup" — evidence: `it_health_no_auth_required` | VALIDATION_MATRIX.md:132 | `citadel-api/src/main.rs:3747` — that test only asserts GET /health returns 200 **without auth**; it does not exercise the master-key startup gate. The gate itself exists (`keystore.rs:774,816-820` plaintext-key/production gate; `main.rs:2875` startup-order comment), but the cited test is the wrong evidence | MISMATCH (evidence≠claim) | doc-fix |
| 32 | VALIDATION_MATRIX current-CI header: run 31141328479, 435/0/9 + 44 KAT + 21 stress | VALIDATION_MATRIX.md:10-16 | External GitHub Actions run; cannot be verified offline from the clone. Local artifacts consistent (test corpus large; stress/volume tests exist, e.g. 10k roundtrips production_mlkem_acvp.rs:104) | UNVERIFIABLE (external CI) | doc-fix (none needed; reproducibility note) |
| 33 | WIRE_SPEC_V2 §2 wire layout (offsets 0-98: magic/ver/flags/suites/reserved/header_len/kem_ct_len/pt_len/recipient_hash/context_hash/nonce) + §1 constants | WIRE_SPEC_V2.md:22-59 | `citadel-envelope/src/wire_v2.rs:16-53` constants all match (HEADER_LEN 98, TAG 16, NONCE 12, MIN 1234, 64MiB/64KiB/4KiB); `encode_header` :104-131 writes fields at **exactly** the spec's offsets and widths, BE ints, reserved=0 | VERIFIED | — |
| 34 | WIRE_SPEC_V2 §4.1/§4.2: KDF transcript and AEAD AD bind `BE16(HEADER_LEN) || header` — i.e. the **full 98-byte header including the nonce** | WIRE_SPEC_V2.md:83-101 (with §2 defining header as bytes 0..98) | Code binds only the **nonce-free 86-byte prefix**: `wire_v2.rs:35` `HEADER_BOUND_LEN = HEADER_LEN - NONCE_LEN`; `kdf_transcript` :139-152 and `associated_data` :155-186 push `BE16(86) || header[..86]` (rationale: packet 056 — FIPS GCM Scenario 2 module-generated nonce cannot be a KDF/AAD input; nonce integrity still covered by GCM itself) | MISMATCH | **code-question** |
| 35 | v1 frozen wire format + constants (version 0x01, 0xA3, 0xB1, flags 0x00, header 6, kem_ct 1120, min 1154, pk 1216, sk 2432) | API_FREEZE.md:57-88; SPEC.md:43-55; README.md:221-226 | `citadel-envelope/src/wire.rs:17-96` — every constant matches; `decode_wire_raw` :221-260 parses version, suite_kem, suite_aead, flags, kem_ct_len(BE16), kem_ct[1120], nonce[12], aead_ct — field-for-field identical to README's block and SPEC.md | VERIFIED | — |
| 36 | v1 frozen KDF: `info = "citadel-env-v1" \|\| "\|aes\|" \|\| SHA3-256(kem_ct) \|\| context`, HKDF-SHA256 salt=None | API_FREEZE.md:90-96; SPEC.md:59-63 | `citadel-envelope/src/kdf.rs:49-71`: `PROTOCOL_ID` = b"citadel-env-v1" (wire.rs:17), `b"\|aes\|"`, `Sha3_256::digest(kem_ct)`, `Hkdf::<Sha256>::new(None, ss)` — exact | VERIFIED | — |
| 37 | New v1 sealing gated behind explicit `legacy-envelope-v1` feature with compat-named API | WIRE_SPEC_V2.md:160-163 | `citadel-envelope/Cargo.toml:123` feature; `sdk.rs:281-282` `seal_v1_compat` cfg-gated; `lib.rs:338` | VERIFIED | — |
| 38 | README API-endpoint table describes the live routes | README.md:136-157 | Router `citadel-api/src/main.rs:3339-3363`: all 18 documented endpoints exist ✓, **but 9 live routes are absent from the table**: `/` (dashboard), `/api/keys/:id/sign`, `/api/verify`, `/api/assertions/issue`, `/api/assertions/verify`, `/api/keys/:id/verifying-key`, `/api/threat/event`, `/api/threat/reset`, `/api/expire` (:3339, :3351-3360). (`/api/threat/event` is documented prose-side at README.md:195-200 but not in the table) | MISMATCH (table incomplete) | doc-fix |
| 39 | Replay backend selected via `CITADEL_REPLAY_BACKEND=memory\|file\|redis`; strict mode via `CITADEL_REPLAY_FLUSH_MODE=immediate` | REPLAY_TRUST_BOUNDARIES.md:17,37-39,72-74,127 | Real env var is **`CITADEL_REPLAY_STORE`** (`citadel-api/src/main.rs:2966-2970`; `root_key_provider.rs:334`; doctor.rs:654). `CITADEL_REPLAY_FLUSH_MODE` appears **nowhere in code**; there is no configurable immediate-flush mode — strict durability exists only as the `force_flush()` API (`replay_store.rs:493`) and the always-immediate flush on `release()` (:571-585) | MISMATCH | doc-fix + **code-question** |
| 40 | FileReplayStore batched crash window: 5 s or 100 ops | REPLAY_TRUST_BOUNDARIES.md:34,49-52 | `replay_store.rs:454-456`: `BATCH_SIZE = 100`, `BATCH_INTERVAL_SECS = 5` (+10k high-water) — exact match | VERIFIED | — |
| 41 | FileReplayStore is "APPEND-ONLY (NO EVICTION) — replay.json grows continuously" | REPLAY_STORE_GUARANTEES.md:36-42 | Code **does evict**: every `claim()` prunes expired entries (`replay_store.rs:537-540` `retain(ts >= cutoff)`) and flush atomically rewrites the whole file (:440-445), so expired entries do leave disk at the next flush. Claim is stale (conservative direction — warns of growth that no longer happens) | MISMATCH | doc-fix |
| 42 | Atomic `claim()` check-and-insert under one lock; `release()` only on decrypt failure, flushed immediately; Redis uses atomic `SET NX EX`; fail-closed on store error | REPLAY_STORE_GUARANTEES.md:3-9,19-21; SECURITY_GUARANTEES.md:55-67 | `replay_store.rs:531-560` single-lock check-and-insert with fail-closed flush + rollback (P161); `release()` :571-585 immediate flush; Redis `claim()` :677-701 `redis_set_nx_ex_atomic` (P319), fail_closed honored (:620,694); `file_store_large_entry_count_remains_consistent` (10k) and `memory_store_expired_entries_evicted` (:908) exist as cited | VERIFIED | — |
| 43 | Memory backend uses monotonic `std::time::Instant`; file backend TTL uses Unix wall clock | SECURITY_GUARANTEES.md:43,53 | Memory: `evict_expired` uses `Instant`-based `duration_since` (replay_store.rs:203-207); File: `unix_now()` wall-clock cutoff (:537-538) | VERIFIED | — |
| 44 | Primitive table: `aes-gcm 0.10` | SECURITY_GUARANTEES.md:126 | `citadel-envelope/Cargo.toml:45`: `aes-gcm = "0.11"` — deliberately bumped 0.10→0.11 for the polyval fix (comment :40-44). Table row stale | MISMATCH | doc-fix |
| 45 | Primitive table pins: ml-kem =0.3.2, p384 =0.14.0, x25519-dalek 2.x, hkdf/hmac 0.12, sha2/sha3 0.10 | SECURITY_GUARANTEES.md:122-129 | Cargo.toml:21 `ml-kem = "=0.3.2"` ✓ (exact pin); :33 `p384 = "0.14"` (caret, resolves 0.14.0 in Cargo.lock:1895-1896 — doc implies an exact `=` pin that isn't in the manifest, effectively true today); x25519-dalek "2" ✓; hkdf/hmac 0.12 ✓; sha2/sha3 0.10 ✓ | VERIFIED (minor pin-style nuance on p384) | — |
| 46 | `fips` feature executes inside the CMVP-validated AWS-LC-FIPS 3.1.0 build (certs #5298/#5314) | README.md:215,248; CHANGELOG.md:23-26 | `Cargo.toml:75` `aws-lc-fips-sys = "=0.13.11"` (exact pin); `tests/awslc_fips_mode.rs:54-62` asserts the **runtime** module version string contains "3.1.0" so a drifted pin fails the test. Certificate numbers themselves are an external-registry fact (not checkable offline) | VERIFIED (pin + runtime assertion; cert numbers external) | — |
| 47 | Threat system: 5 levels LOW→CRITICAL; policy tightening; expiry enforced by background task every 60 s; rotation requires operator (`check_rotation_due()`) | README.md:183-193; SECURITY_GUARANTEES.md:94-95,112 | `citadel-keystore/src/threat.rs:35-59` 5-level enum; `citadel-api/src/main.rs:3290` `interval(Duration::from_secs(60))`; `keystore.rs:1551` `check_rotation_due()` | VERIFIED | — |
| 48 | Scoped auth: read/encrypt/manage/admin, admin implies all | README.md:170-179 | `citadel-api/src/main.rs:56-85`: `enum Scope { Read, Encrypt, Manage, Admin }`, `:85` admin short-circuits `contains` | VERIFIED | — |
| 49 | `0xA4` suite evidence files: wycheproof_p384_ecdh.rs, proptest_a4.rs, v2_vector_a4.rs, awslc_ecdh_p384_differential.rs | VALIDATION_MATRIX.md:34-38 | All four files present in `citadel-envelope/tests/` | VERIFIED | — |
| 50 | CHANGELOG dates: 0.1.0 = 2026-07-09; 0.2.0 = 2026-08-06 | CHANGELOG.md:16,58 | git: initial commit `cff9649` 2026-07-09 ✓; commit `7a864d0` 2026-08-06 ("resolve alpha/beta and FIPS-version conflicts") ✓; `VERSION` file = "citadel-v3-beta-001 / 2026-08-06" ✓; all three crate manifests at 0.2.0 ✓. **No git tags exist** — "Tag: citadel-v3-beta-001" (VALIDATION_MATRIX.md:3) is a VERSION-file label, not a git tag | VERIFIED (with reproducibility caveat, see below) | — |
| 51 | ACVP row also cites `nist_acvp_kat` as vector evidence | VALIDATION_MATRIX.md:32 | `tests/nist_acvp_kat.rs:1-23` self-describes as "KAT-**adjacent** … structural and envelope behavior; full ACVP vectors now run … in production_mlkem_acvp.rs". Listing it alongside the two real vector files is loose but the row's substance (60/60 official vectors) is carried by the other two cited files | VERIFIED (citation looseness noted) | — |

**Counts:** 51 claims checked → **38 VERIFIED**, **7 MISMATCH**, **4 STALE-PATH**, **2 UNVERIFIABLE**.

## Code-question rows

These need the maintainer's intent, not a mechanical doc edit:

**Row 34 — WIRE_SPEC_V2 §4.1/§4.2 vs `wire_v2.rs` header binding.** This is the one substantive spec-vs-code divergence found. The spec (self-labeled "frozen implementation target", dated 2026-07-15) canonically encodes `BE16(HEADER_LEN) || header` — the full 98 bytes including the nonce at offset 86 — into both the KDF transcript and the AEAD associated data. The shipped encoder binds `BE16(86) || header[..86]` (nonce-free prefix, `wire_v2.rs:35,139-186`), changed by "packet 056" because the FIPS backend's GCM IV Scenario 2 generates the nonce *inside* seal, after the key and AAD must already exist. The code path is internally coherent (both seal and open use the same prefix; a flipped nonce still fails the GCM tag — see the code comment citing `p3d_open_rejects_*_nonce_tampered`), and the checked-in v2 vectors were regenerated against it. But an independent implementer coding from WIRE_SPEC_V2.md today would produce envelopes this decoder rejects. The maintainer must either (a) revise §4.1/§4.2 (and bump the spec draft number) to the 86-byte prefix with the Scenario-2 rationale, or (b) declare the spec authoritative and treat the code as divergent — (a) matches evident intent, but "frozen" specs shouldn't drift silently, so this is flagged as a code-question rather than a plain doc-fix.

**Row 39 — REPLAY_TRUST_BOUNDARIES strict mode.** The document specifies a whole deployment tier ("FileReplayStore (Strict Mode)", `CITADEL_REPLAY_FLUSH_MODE=immediate`, "every claim immediately fsynced, no crash window", with its own checklist and recommendation table) that does not exist in the code, and its env var `CITADEL_REPLAY_BACKEND` is not the one the server reads (`CITADEL_REPLAY_STORE`, main.rs:2970). Question for the maintainer: was per-claim immediate flush a designed-but-dropped feature (then the doc section should be removed or marked planned), or is it intended and missing (then it's a small code change — `should_flush()` already centralizes the policy at replay_store.rs:453)? Until resolved, an operator following this doc for a "compliance-critical" deployment would set two env vars that silently do nothing — the worst kind of doc error, even though the underlying batched implementation is honestly described elsewhere (REPLAY_STORE_GUARANTEES + SECURITY_GUARANTEES use the correct var and semantics).

**Row 6 — the 200,000-nonce figure.** Not an accusation: the test exists (`ringer.rs:234`), is env-parameterized, and the whitepaper describes a recorded high-volume run on both backends. But unlike every other headline number in this repo (which have checked-in receipts — tier3, tier8, tier12), no artifact in the clone records a 200k execution; defaults are 10k/20k. Either check in the run receipt like the gauntlet tiers, or restate the README/CHANGELOG figure as "N seals (20,000 in CI; 200,000 in the recorded validation run, receipt X)".

**Reproducibility caveat (squashed import — not a lie, worth stating).** The git history begins 2026-07-09 with a single "initial commit" containing the entire codebase; there are no git tags. Several documents carry authorship dates predating any commit — API_FREEZE.md ("Date: 2026-02-05, Signed: [Maintainer]"), the 20260501/02 baseline validation run throughout VALIDATION_MATRIX.md, REPLAY_STORE_GUARANTEES.md ("Last updated 2026-05-02"). Nothing before 2026-07-09 is reconstructable from this repository's history, so the Alpha-Freeze-era per-row "Last Run" records rest entirely on the documents' own testimony (mitigated by the fact that the current CI header re-asserts every row against a 2026-08-06 run). A one-line note in VALIDATION_MATRIX acknowledging the import boundary would close this.

**Minor editorial (no table row):** REPLAY_STORE_GUARANTEES.md:3 reads "now uses atomic `claim()+release()` instead of the old `claim()+release()` two-step" — the old and new mechanisms are named identically; presumably the old one was `check()+record()` or similar.
# §1 — Surface + Structure Inventory (citadel-v3 consistency audit)

Repo: `C:\Data\citadel-v3` (read-only audit, 2026-09-02). All file:line references are relative to that root.

---

## 1. Crate graph

7 workspace members (`Cargo.toml:1-10`, virtual workspace — root has no `[package]`).

| Crate | LOC (src) | One-line purpose | Intra-workspace deps (from Cargo.toml) |
|---|---|---|---|
| citadel-core | 1,604 | StateEnforcer — layer-1 runtime enforcement of identity/lifecycle/domain/operation-type (`citadel-core/src/lib.rs:1-7`) | (none) |
| citadel-envelope | 6,357 | Hybrid encryption core: suites 0xA3 (X25519+ML-KEM-768) and 0xA4 (P-384+ML-KEM-1024) + AES-256-GCM; optional AWS-LC `fips` backend | (none) |
| citadel-signer | 961 | ML-DSA-65 signing primitives + CitadelAssertion (CNA) format | (none) |
| citadel-keystore | 9,977 | Key lifecycle: 4-level hierarchy, replay stores, threat engine, audit chain, backup | citadel-envelope, citadel-core, citadel-signer (`citadel-keystore/Cargo.toml:36-37,66`) |
| citadel-api | 8,267 (8,172 in one file: `citadel-api/src/main.rs`) | Axum REST server, scoped API-key auth, rate limiting, embedded dashboard | citadel-envelope, citadel-keystore, citadel-core, citadel-signer (`citadel-api/Cargo.toml:33-39`) |
| citadel-ffi | 1,372 | C ABI (`cdylib`/`staticlib`, lib name `citadel`) over the envelope seal/open surface | citadel-envelope (`citadel-ffi/Cargo.toml:16`) |
| citadel-cli | 1,482 | `citadel` binary — doctor, key mgmt, migrate, audit, backup, replay | citadel-envelope, citadel-keystore (`citadel-cli/Cargo.toml:20-21`) |

Total ≈ **30,020 LOC** of Rust source across the workspace.

Dependency edges (arrows = depends-on):

```
citadel-api ──► citadel-keystore ──► citadel-envelope
    │  │  └───► citadel-core ◄─────────┘ (keystore also deps core)
    │  └─────► citadel-signer ◄── citadel-keystore
citadel-cli ──► citadel-keystore, citadel-envelope
citadel-ffi ──► citadel-envelope
```

**README "three crates" claim (`README.md:29-36`)** — *"The request path runs through three crates"* (envelope, keystore, api). Verdict: **acceptable simplification for encrypt/decrypt, but literally wrong for a third of the routes.**
- Sign/verify/assertion routes (`/api/keys/:id/sign`, `/api/verify`, `/api/assertions/*`) run through **citadel-signer** — citadel-api depends on it directly ("P373: CNA assertion API routes require citadel-signer", `citadel-api/Cargo.toml:38-39`).
- Every lifecycle/authorization decision goes through **citadel-core**'s StateEnforcer ("layer 1 of the two-layer enforcement boundary", `citadel-core/src/lib.rs:3-6`) — also a direct citadel-api dependency.
- The README does hedge ("see Project Structure for all seven"), and the Project Structure section (`README.md:262-279`) lists all 7 correctly. But `citadel-core`'s blurb there ("Shared types and primitives") **understates/mislabels** what it is — it is the runtime enforcement layer, not a types crate.

---

## 2. Endpoint table

Router: `citadel-api/src/main.rs:3339-3363`. Scope enforcement is centralized in `required_scope()` (`citadel-api/src/main.rs:91-117`), applied by the auth middleware at `main.rs:1028-1110`. `admin` implies all (`main.rs:84-89`).

| # | Method | Path | Scope | Handler (main.rs) |
|---|---|---|---|---|
| 1 | GET | `/` | none | `dashboard` :2631 |
| 2 | GET | `/health` | none | `health` :1502 |
| 3 | GET | `/api/status` | read | `get_status` :1537 |
| 4 | GET | `/api/metrics` | read | `get_metrics` :1562 |
| 5 | GET | `/api/keys` | read | `list_keys_handler` :1578 |
| 6 | POST | `/api/keys` | manage | `generate_key` :1640 |
| 7 | GET | `/api/keys/:id` | read | `get_key` :1621 |
| 8 | POST | `/api/keys/:id/activate` | manage | `activate_key` :1721 |
| 9 | POST | `/api/keys/:id/rotate` | manage | `rotate_key` :1763 |
| 10 | POST | `/api/keys/:id/revoke` | manage | `revoke_key` :1818 |
| 11 | POST | `/api/keys/:id/destroy` | manage | `destroy_key` :1863 |
| 12 | POST | `/api/keys/:id/encrypt` | encrypt | `encrypt_data` :1896 |
| 13 | POST | `/api/decrypt` | encrypt | `decrypt_data` :1960 |
| 14 | POST | `/api/keys/:id/sign` | encrypt | `sign_data` :2101 |
| 15 | POST | `/api/verify` | read | `verify_signature_handler` :2192 |
| 16 | GET | `/api/keys/:id/verifying-key` | read | `get_verifying_key` :2272 |
| 17 | POST | `/api/assertions/issue` | encrypt | `issue_assertion` :2339 |
| 18 | POST | `/api/assertions/verify` | read | `verify_assertion` :2459 |
| 19 | GET | `/api/threat` | read | `get_threat` :2508 |
| 20 | POST | `/api/threat/event` | manage | `post_threat_event` :2535 |
| 21 | POST | `/api/threat/reset` | manage | `reset_threat` :2563 |
| 22 | GET | `/api/policies` | read | `get_policies` :2579 |
| 23 | POST | `/api/expire` | manage | `expire_due` :2613 |
| 24 | GET | `/api/auth/keys` | admin | `list_api_keys` :2639 |
| 25 | POST | `/api/auth/keys` | admin | `create_api_key` :2682 |
| 26 | DELETE | `/api/auth/keys/:id` | admin | `revoke_api_key` :2783 |
| 27 | GET | `/api/auth/whoami` | read | `whoami` :2834 |

**27 method+path endpoints in code.**

### Diff vs README endpoint table (`README.md:136-157` — 18 rows)

Routes **in code but missing from the README table** (9):

| Route | Where README does/doesn't mention it |
|---|---|
| GET `/` (dashboard) | Mentioned prose-only (`README.md:55`), never in the table |
| POST `/api/keys/:id/sign` | Not documented anywhere in README |
| POST `/api/verify` | Not documented |
| GET `/api/keys/:id/verifying-key` | Not documented |
| POST `/api/assertions/issue` | Not documented |
| POST `/api/assertions/verify` | Not documented |
| POST `/api/threat/event` | **Only in the Adaptive Threat prose** (`README.md:195-200`), not in the endpoint table — confirmed as the task suspected; its `manage` scope requirement is stated nowhere |
| POST `/api/threat/reset` | Prose-only as a dashboard "Reset" button (`README.md:198-199`); not in the table |
| POST `/api/expire` | Not documented |

- Routes documented but absent from code: **none** — all 18 README rows exist.
- Scope mismatches on documented rows: **none** — all 18 rows match `required_scope()`.
- The whole ML-DSA/assertion surface (5 routes, P367/P373) is invisible in the README table — the largest doc gap.

### Diff vs API_FREEZE.md

`API_FREEZE.md` **does not document HTTP routes at all.** Despite the name, it freezes the **Rust SDK + FFI surface** (Tier 1: `Citadel::seal/open`, key byte sizes, wire v1; Tier 2 additive 0xA4 FFI symbols, `API_FREEZE.md:15-40`). So there is no route-level freeze contract anywhere; the closest thing to an HTTP contract is `scripts/security/openapi.yaml`, which documents **24 paths** (`openapi.yaml:229-860`) — everything except `GET /`, and it is buried in a test-scripts folder rather than linked from README's Documentation table. Consistency finding: three competing endpoint inventories (README table 18, openapi.yaml 24, code 27), none complete.

---

## 3. CLI (citadel-cli, clap)

Top-level: `citadel-cli/src/main.rs:60-94`. Globals: `--data-dir` (env `CITADEL_DATA_DIR`, default `./citadel-data`), `--output text|json` (`main.rs:42-58`). All commands operate **directly on the data dir / local keystore files** — the CLI does not call the HTTP API.

| Command | Defined at | What it calls / does |
|---|---|---|
| `citadel doctor` | main.rs:63 → `commands/doctor.rs` (104 LOC) | Deployment health checks via `citadel_keystore::doctor`; exit 0/1/2 |
| `citadel key graph` | `commands/key.rs:17` | ASCII hierarchy tree from keystore storage |
| `citadel key inspect <id>` | key.rs:20 | Key metadata dump (full-ID or prefix match) |
| `citadel key generate --name … --key-type … [--parent] [--policy] [--activate]` | key.rs:26 | Create root/domain/kek/dek/hybrid-id key |
| `citadel key rotate <id>` | key.rs:49 | New version, old kept for decrypt |
| `citadel key revoke <id> --reason …` | key.rs:55 | Emergency deactivation (reason required) |
| `citadel key destroy <id> --confirm` | key.rs:65 | Irreversible material purge |
| `citadel key rewrap <id> [--parent]` | key.rs:75 | Re-wrap under new parent KEK / external master key |
| `citadel migrate hierarchy [--dry-run] [--execute] …` | `commands/migrate.rs:15-38` | Upgrade flat keys to V3 Root→Domain→KEK→DEK |
| `citadel audit export [--output] [--format jsonl\|json] [--limit]` | `commands/audit.rs:13` | Export `citadel-audit.jsonl` |
| `citadel audit verify-chain` | audit.rs:28 | Verify SHA-256 audit hash chain |
| `citadel backup create <path>` | `commands/backup.rs:17` | Encrypted metadata backup (needs `CITADEL_MASTER_KEY`, backup.rs:54) |
| `citadel backup verify <path>` | backup.rs:22 | Decrypt+parse check |
| `citadel backup restore <path> [--dry-run] [--overwrite]` | backup.rs:27 | Restore, conflict-skip by default |
| `citadel replay status` | `commands/replay.rs:9-12` | Report `CITADEL_REPLAY_STORE` config (warns on deprecated `CITADEL_REPLAY_BACKEND`, replay.rs:21-37) |

Doc-comment command list at `citadel-cli/src/main.rs:7-22` is missing `key rewrap` (exists in code, key.rs:75) — minor doc drift inside the crate itself.

---

## 4. FFI exports vs bindings

12 `extern "C"` exports in `citadel-ffi/src/lib.rs`:

| Export (lib.rs line) | Python (`bindings/python/test_citadel.py`) | Java (`bindings/java/io/reposignal/citadel/Citadel.java`) | C (`bindings/c/test_citadel.c`) |
|---|---|---|---|
| `citadel_public_key_bytes` :160 | ✅ | — | — |
| `citadel_secret_key_bytes` :166 | ✅ | — | — |
| `citadel_public_key_bytes_for_suite` :172 | ✅ | — | ✅ |
| `citadel_secret_key_bytes_for_suite` :182 | ✅ | — | ✅ |
| `citadel_keygen` :198 | ✅ | ✅ | ✅ |
| `citadel_seal` :248 | ✅ | ✅ | ✅ |
| `citadel_open` :322 | ✅ | ✅ | ✅ |
| `citadel_p384_keygen` :396 | ✅ | ✅ | ✅ |
| `citadel_p384_seal` :436 | ✅ | ✅ | ✅ |
| `citadel_p384_open` :510 | ✅ | ✅ | ✅ |
| `citadel_free` :591 | ✅ | ✅ | ✅ |
| `citadel_error_string` :617 | — | ✅ | — |

- **Bindings referencing non-existent exports: none.** All symbols used by all three bindings exist.
- **Exports without full binding coverage:** `citadel_error_string` is used only by Java — Python and C bindings map error codes themselves; the Java binding hardcodes key/buffer sizes instead of calling the four `*_bytes*` size functions. No binding exercises the complete 12-symbol surface.
- All 6 Tier-2 frozen 0xA4 symbols promised in `API_FREEZE.md:40` (`citadel_p384_{keygen,seal,open}`, `citadel_{public,secret}_key_bytes_for_suite`) exist — freeze and code agree.
- `citadel-ffi/bindings/OWNERSHIP.md` and `bindings/java/README.md` exist as binding docs.

---

## 5. The dashboards — actually FOUR files, not three

**What the API serves:** `citadel-api/src/dashboard.html` via `include_str!` at `citadel-api/src/main.rs:2631-2632`, routed at `GET /` (`main.rs:3339`). None of the three root-level files is served.

| File | Size | Nature | API calls |
|---|---|---|---|
| `citadel-api/src/dashboard.html` | 44,689 B | **SERVED.** React-UMD single-file app, live API, auth gate (API-key sign-in, "CONTINUE WITHOUT AUTH" demo mode, localStorage key) | `/api/status,​metrics,​keys,​keys/:id…,​policies,​threat/event,​threat/reset,​auth/whoami,​auth/keys,​auth/keys/:id` |
| `dashboard.html` (root) | 42,620 B | **Stale older snapshot of the served file.** Same `<title>`, same API-call set; 94 diff lines behind | same set |
| `citadel-dashboard.html` (root) | 25,939 B | Static **simulation mockup**: React 18 + Babel from CDN (`citadel-dashboard.html:23-26`), simulated keystore state, **zero** API calls | none |
| `citadel-dashboard.jsx` (root) | 27,559 B | Same simulation as an importable JSX module ("Simulated Keystore State", `citadel-dashboard.jsx:3`), **zero** API calls | none |

Behavioral differences, root `dashboard.html` vs served copy (from diff):
- Served copy's `api()` helper surfaces HTTP errors (`!res.ok` → thrown with server `error` text); root copy silently `res.json()`s error bodies — failures render as blank data.
- Served copy adds **domain-scoped API-key creation**: `newDomains` field, "DOMAINS (comma-separated, required for non-admin keys)" input, client-side rule *non-admin keys must be scoped to ≥1 domain*, sends `allowed_domains` in POST `/api/auth/keys`. Root copy can only create unscoped keys — it predates the P222/P223 domain-scoping work visible in `main.rs:660,833+`.
- Served copy adds `opError` state so threat-injection failures display instead of vanishing.

The two `citadel-dashboard.*` mockups share the served UI's panels (DEFCON threat strip, INJECT THREAT EVENTS, ADAPTIVE POLICY ENGINE, KEY INVENTORY, EVENT FEED) but run on hardcoded simulated data and pull React from CDNs (violates the served file's self-contained model). No document references any of the four dashboard files by name (grep across `*.md` = zero hits).

**Recommendation:**
- **Survivor: `citadel-api/src/dashboard.html`** (the only one wired to the binary, and the most advanced).
- Delete root `dashboard.html` — strictly older duplicate; nothing to port.
- Archive `citadel-dashboard.html` + `citadel-dashboard.jsx` — nothing functional to port (they are demos of the same UI on fake data). The only arguable unique value is "runs without a server" demo/marketing capability; if wanted, keep exactly one (the .html, since the .jsx additionally needs a build toolchain) under `examples/` with a README note. Two copies of a simulation is pure residue.

---

## 6. test_vectors.json vs test_vectors_real.json

| | `test_vectors.json` | `test_vectors_real.json` |
|---|---|---|
| Size | 7,210 B | 43,090 B |
| Encoding | UTF-8, valid JSON | **UTF-16 LE with BOM — not parseable by any UTF-8 JSON consumer** (classic PowerShell `>` redirect artifact of `cargo run --example generate_vectors > test_vectors_real.json`, the exact command in `examples/generate_vectors.rs:5`) |
| Schema | top-level keys: `spec_version, generator, generated_at, note, constants, wire_format, domain_separation, test_vectors, constraint_tests, interop_notes` | same schema (visible through the UTF-16), `generated_at: 2026-01-28`, generator "citadel-envelope test vector generator" — i.e. the *populated* output of the same generator |
| Referenced by | `WIRE_SPEC.md:310` ("See `test_vectors.json` for canonical test vectors") — doc-only | `examples/generate_vectors.rs:5` (as intended output filename) — doc-comment only |
| Consumed by tests | **nothing** — repo-wide grep (tests/, gauntlet/, scripts/, `citadel_cross_verify.py`, CI yml) finds zero programmatic consumers of either file | **nothing** |

Verdict: **neither file is live.** `test_vectors.json` is at least the one a spec doc points to ("canonical"); `test_vectors_real.json` is residue *and broken* (UTF-16). Note the actually-live vectors are elsewhere: `citadel-envelope/tests/vectors/envelope_v2.json`, `envelope_v2_a4.json`, the ACVP/Wycheproof JSONs under `citadel-envelope/tests/`, and gauntlet tier1 — all consumed by compiled tests. Related inconsistency: `citadel_cross_verify.py:19-20,346` tells users to run `cargo run --example export_test_vector` — **no such example exists** (root `examples/` has only `generate_vectors.rs` and `timing_analysis.rs`, and root examples aren't attached to any crate — see §7/§8).

---

## 7. Root harnesses — live vs residue

CI (`.github/workflows/ci.yml`) runs: fmt/clippy/build/`cargo test --workspace`, `security_stress`, cargo-audit/deny, then `scripts/security/persistence_server_test.sh`, `concurrency_stress.sh`, `log_canary_test.sh` (ci.yml:108-145). **No root harness is in CI.**

| Script | What it does | Referenced from | Live/Residue | Duplicates coverage in tests/fuzz/gauntlet? |
|---|---|---|---|---|
| `citadel_full_validation.ps1` (15,105 B) | End-to-end Windows validation: builds, boots API, ~dozens of Must-Pass/Must-Fail HTTP steps, replay-across-restart, JSON receipt | `VALIDATION_MATRIX.md:63-64,98-104` (many PASS rows dated 20260501) | **LIVE** — it is the evidence source for a third of the matrix | Overlaps in-crate axum tests (`main.rs` has 77 `#[test]`/`#[tokio::test]`) and `scripts/security/*` CI scripts, but is the only *Windows* E2E record |
| `citadel_abuse_harness.ps1` (10,683 B) | P199: 100× replay, wrong-AAD/context, malformed JSON, wrong-auth storm against a local API on :47200 | `VALIDATION_MATRIX.md:109` — status **⏳ PENDING** | **LIVE (referenced), never run to green** | Partially duplicated by `citadel-envelope/tests/security_stress.rs` + fuzz corpus + in-crate auth tests, at HTTP level unique |
| `citadel_multiprocess_replay_harness.ps1` (9,020 B) | P197: two API instances sharing one data dir; documents FileReplayStore single-process limitation | `VALIDATION_MATRIX.md:67,90` — both rows **⏳ PENDING** | **LIVE (referenced), never run to green** | Unique — nothing under tests/ or gauntlet does multi-process |
| `citadel_long_run_load.ps1` (9,822 B) | P198: 10-min continuous encrypt/decrypt/rotation/invalid/replay load on :47220 | Not referenced **by name** anywhere; `VALIDATION_MATRIX.md:163` describes the "Long-run load (10 min)" row as PENDING without naming the script | **Semi-residue** — matrix wants the capability but the file is orphaned from it | CI's `security_stress` (~4.3 min) is the explicitly-noted partial substitute |
| `citadel_crash_harness.ps1` (12,395 B) | P204: force-kill under continuous load, verify crash durability of writes | Referenced nowhere; `SECURITY_MATURITY.md:166` lists "Chaos/crash consistency testing" as an unchecked TODO | **Residue** (orphaned evidence for an open TODO) | Unique — no crash-durability test exists under tests/ |
| `citadel_api_security_test.py` (18,396 B) | HTTP-level auth-rejection / scope / rate-limit / input-validation tests vs a running API | Referenced nowhere (no doc, no CI, no matrix row) | **Residue** | Yes — heavily duplicated by main.rs in-process tests + `scripts/security/hostile_config_test.sh`/`ci_server_tests.sh` |
| `citadel_cross_verify.py` (17,051 B) | Independent Python reimplementation of SHA3→HKDF→AES-GCM; primitive KATs + optional real-ciphertext decrypt | Referenced nowhere; its own usage text points at a **non-existent** example (`export_test_vector`, lines 19-20, 346) | **Residue (and broken workflow)** | Primitive KATs duplicated by `citadel-envelope/tests/primitive_kat.rs`, `nist_acvp_kat.rs`, gauntlet tier1 Wycheproof; the "independent second implementation" idea is unique but unreachable as documented |
| `citadel_example.py` (10,633 B) | Documented integration example (healthcare record encryption, AAD binding, rotation, threat-aware client) | `README.md:118`, `INTEGRATION_GUIDE.md` | **LIVE** (documentation artifact) | n/a — an example, not a test |
| `Backup-Citadel.ps1` (12,071 B) | Docker-volume backup/restore/list/verify for container `citadel-api` | Referenced nowhere | **Residue** | Duplicates `citadel backup create/verify/restore` (CLI, `commands/backup.rs`) at the Docker-volume level |
| `Sign-Citadel.ps1` (5,833 B) | Authenticode-signs built exes/test binaries with a machine-local self-signed cert for this device's WDAC policy; references an `ATTACK_PLAN.md` that is not in the repo | Referenced nowhere | **Residue** (single-machine dev tool; useless to any other clone) | n/a |
| `Validate-Citadel.ps1` (15,931 B) | Quick live-API validation sweep against `http://localhost:8443` (pass/fail/warn report) | Referenced nowhere; exists in **3 copies** (see §8) | **Residue** | Duplicates `citadel_full_validation.ps1` (superset) and `scripts/smoke-test.sh` |

Split: **4 live/referenced** (full_validation, abuse, multiprocess, example) — though abuse + multiprocess are referenced only as PENDING — vs **7 residue** (long_run_load*, crash, api_security_test, cross_verify, Backup-, Sign-, Validate-Citadel). (*long_run counted residue: capability wanted, file unlinked.)

Also residue in the same category, found while auditing: root `tests/hybrid_kat.rs` and root `examples/{generate_vectors,timing_analysis}.rs` — the workspace root is a **virtual manifest** (no `[package]`), so these are **never compiled by anything**; `tests/hybrid_kat.rs:13-23` additionally imports modules (`citadel_envelope::hybrid`, `hybrid_wire`) that no longer exist in citadel-envelope. Dead on two counts.

---

## 8. Duplication matrix

| # | Artifacts | Shared purpose | Behavioral differences | Recommended survivor | Port before deleting loser |
|---|---|---|---|---|---|
| 1 | `citadel-api/src/dashboard.html` · `dashboard.html` · `citadel-dashboard.html` · `citadel-dashboard.jsx` | Security-operations dashboard UI | Served copy: live API + error surfacing + domain-scoped key creation. Root copy: same minus those (older). `citadel-dashboard.*`: simulated data, CDN React, no API | `citadel-api/src/dashboard.html` | Nothing — losers are subsets/simulations. Optionally keep ONE mockup under `examples/` as an offline demo |
| 2 | `test_vectors.json` · `test_vectors_real.json` | Canonical wire-format test vectors | `_real` is populated but UTF-16-corrupt; neither is consumed by any test | `test_vectors.json` (only one a doc cites) — or better, regenerate `_real` as UTF-8 and wire a test to it | If `_real`'s populated vectors matter, re-emit UTF-8 and update `WIRE_SPEC.md:310`; else delete `_real` |
| 3 | `SPEC.md` · `WIRE_SPEC.md` · `WIRE_SPEC_V2.md` · `FORMAT.md` | Wire-format specification (content overlap is §4's job) | File-level: 4 docs cover v1 informal / v1 RFC-2119 / v2 / encoding overview; README's Project Structure calls SPEC.md "Authoritative wire specification" (`README.md:274`) while its Documentation table calls it "v1 wire format specification" (`README.md:287`) — two different claims about the same file | (§4 to decide; likely WIRE_SPEC_V2 + one v1 doc) | Cross-links + a single "authoritative" pointer |
| 4 | `docker-compose.yml` · `docker-compose-production.yml` · `deploy/docker/docker-compose.yml` | Compose deployment | Root dev: plaintext key, demo seed, 127.0.0.1 bind. Root `-production`: Caddy TLS + hashed key + rate-limit env. `deploy/docker/`: a *different* production compose (CITADEL_MASTER_KEY-centric, `version: 3.9`, builds `citadel:v3`). Root dev file's own comment (`docker-compose.yml:10`) says "For production, use: deploy/docker/docker-compose.yml" — pointing at the *third* file, not `-production.yml` | Keep root dev + ONE production compose (`deploy/docker/` is the one docs point to; it lacks Caddy) | Merge Caddy service + rate-limit envs from `-production.yml` into the survivor; fix the dev-file comment |
| 5 | `Dockerfile` · `Dockerfile.fips` | Container build | 80 diff lines: `.fips` builds `--features fips` (AWS-LC, needs cmake/go/perl toolchain) | **Both stay** — legitimately different build targets, not residue | n/a (document pairing with compose files) |
| 6 | `scripts/run-tests.sh` · `scripts/test-citadel-ubuntu.sh` · `citadel_full_validation.ps1` (· `gauntlet/run.sh`) | "Run the tests" entry point | run-tests.sh: local cargo suite w/ thread-order handling. test-citadel-ubuntu.sh: canonical 2-run reproducibility judge + JSON receipts (README.md:85-89 blesses it). full_validation.ps1: Windows E2E HTTP validation + receipt. gauntlet/run.sh: adversarial tier orchestrator | All four serve distinct roles; **canonical = test-citadel-ubuntu.sh** per README | Add a one-table "which runner when" note (VALIDATION_MATRIX or CONTRIBUTING) — currently nothing lists all four |
| 7 | `Validate-Citadel.ps1` (root) · `citadel-keystore/Validate-Citadel.ps1` · `citadel-keystore/src/Validate-Citadel.ps1` | Live-API quick validation sweep | Root ≡ keystore copy (identical md5 `57b837…`). `src/` copy is an **older** variant (matches `state -eq "Active"` vs the fixed `"ACTIVE"` — i.e. it silently finds no DEK against the current API) | Root copy — or delete all three in favor of `scripts/smoke-test.sh` + `citadel_full_validation.ps1` | Nothing; the two keystore copies are checked-in strays inside a crate tree (a `.ps1` inside `src/`!) |
| 8 | `Backup-Citadel.ps1` · `citadel backup` (CLI, `citadel-cli/src/commands/backup.rs`) | Backup/restore | PS1 tars the Docker volume from outside; CLI creates encrypted `.ctdlbak` from inside with verify/dry-run/conflict handling | CLI | If Docker-volume-level snapshots are wanted, one documented `docker run --rm -v … tar` line in DEPLOYMENT.md replaces the 12KB script |
| 9 | root `Cargo.toml` · `citadel-keystore/Cargo.workspace.toml` | Workspace manifest | Stray 2-member (envelope+keystore) workspace file — pre-monorepo residue; cargo ignores the name, humans won't | root `Cargo.toml` | Nothing — delete stray |
| 10 | root `tests/hybrid_kat.rs`, root `examples/*.rs` · per-crate tests/examples | Tests/examples | Root copies attached to NO package (virtual workspace → never compiled); `hybrid_kat.rs` imports modules that no longer exist; `generate_vectors.rs` is the never-run producer of `test_vectors_real.json`; `citadel_cross_verify.py` depends on a third, missing example (`export_test_vector`) | Per-crate `citadel-envelope/tests/*` (compiled, in CI) | If cross-language verify is wanted, resurrect ONE vector-export example inside citadel-envelope and point cross_verify at it; otherwise delete root tests/ + examples/ |
| 11 | `citadel_api_security_test.py` · `citadel-api/src/main.rs` `#[cfg(test)]` (77 tests, main.rs:3427+) · `scripts/security/*.sh` | API security boundary tests | py: external HTTP black-box, referenced nowhere; in-crate: in-process axum, in CI; scripts/security: server-level, in CI (ci.yml:122-145) | in-crate tests + scripts/security (both CI-wired) | Check py file for any case absent from the other two (rate-limit specifics), port, delete |
| 12 | README endpoint table (`README.md:136-157`) · `scripts/security/openapi.yaml` | HTTP API documentation | 18 vs 24 endpoints; openapi.yaml is unlisted in README's own Documentation table; neither covers `GET /`; code has 27 | openapi.yaml as machine-readable truth, README table regenerated/extended from it | Add the 9 missing routes (§2) to README; move/ link openapi.yaml somewhere discoverable |
| 13 | `COPYING` · `AGPL-3.0.txt` (both 34,519 B, identical) · `LICENSE` (2,039 B summary) | License text | Byte-identical AGPL full text twice, plus a summary file; README cites both (`README.md:318`) | `COPYING` (GNU convention) or keep both knowingly — cosmetic | Update README/NOTICE refs if one is dropped |

**13 duplication rows.**

---

### §1 headline inconsistencies (for the roll-up)

1. GET `/` serves `citadel-api/src/dashboard.html`; all three root-level dashboard files are non-served residue, one of them a stale near-copy of the served UI.
2. 27 endpoints in code vs 18 in README vs 24 in a hidden openapi.yaml; the entire signing/assertion route family and `POST /api/expire` are undocumented; `POST /api/threat/event` appears only in prose, with its `manage` scope stated nowhere.
3. API_FREEZE.md freezes the SDK/FFI, not the HTTP API — no HTTP stability contract exists despite the filename.
4. `test_vectors_real.json` is UTF-16-corrupt and consumed by nothing; `citadel_cross_verify.py`'s documented workflow depends on an example that doesn't exist; root `tests/` and `examples/` are attached to no crate and never compile.
5. `Validate-Citadel.ps1` exists in 3 copies (one inside `citadel-keystore/src/`, older and behaviorally wrong against the current API), plus a stray `Cargo.workspace.toml` — direct violations of one-source-of-truth hygiene.
# §2 Reproducibility — running his docs, as written

Environments used (both on a clean clone of `master` @ 31deefe):
- **Ubuntu**: GitHub Actions `ubuntu-latest`, run in the fork ([`audit-repro` workflow, run 33677391296](https://github.com/LuckyCody/citadel-v3/actions/runs/33677391296) — every claim below is re-checkable in that public log; the workflow file lives only on the fork's `ci/repro-run` branch). rustc: current stable.
- **Windows** (bonus, undocumented platform): Windows Server 2025, rustup stable-msvc (cargo 1.98.0), VS2019 Build Tools, Git Bash.

| Step | Verdict | Evidence |
|---|---|---|
| **A. From-source build** (`cargo build --release -p citadel-api`, README:70) | ✅ WORKED — both platforms | Ubuntu: clean. Windows: 2m03s, 4 default-level warnings in citadel-keystore (unused imports) |
| **B. `cargo test --workspace --locked`** | ✅ WORKED — both platforms | ~320 tests, 0 failed, 3 ignored (both platforms; Windows ~2.5 min). Windows is undocumented and just works — worth a README line |
| **C. Canonical judge** (`bash scripts/test-citadel-ubuntu.sh`, README:85-89) | ✅ WORKED as documented (Ubuntu) | Judge passed on the first as-documented invocation, produced its receipts. Nuance: the script defaults to `--offline`; it succeeds because README's order has you build first (populating the cargo cache). Judge-first on a bare clone would need `--online` or a prior `cargo fetch` — worth one sentence in the script's usage text. On Windows Git Bash it aborts at its `python3` check (MS-Store shim) — out of the script's documented scope (Ubuntu/WSL2), noted only for completeness |
| **D. AWS-LC comparison check** (`cargo check -p citadel-envelope --benches --features aws-lc-comparison`, README:82) | ➖ NOT RUN | Needs the AWS-LC C toolchain (cmake/clang/go); we did not provision it. No claim made either way |
| **E. Fuzz targets compile** (`cargo +nightly fuzz build`) | ✅ WORKED | nightly 1.100.0, finished 24.83s, all 4 targets in fuzz/fuzz_targets/ |
| **F. Clippy** | ✅ default level CLEAN / pedantic 1,522 | His own CI gate is `clippy --workspace --all-targets -- -D warnings` and it passes — default lint level is genuinely clean. Pedantic (advisory): 1,522 warnings, dominated by style (476 format-string inlining, 427 doc backticks, 135 `#[must_use]`, 98 missing `# Errors` docs); the substantive tail: 17 `u64`→`f64` precision-loss casts (metrics paths), 17 `async fn` with no await |
| **G. cargo audit + his deny gate** | ✅ audit clean (as configured) / ⚠️ deny FAILS, and CI masks it | `cargo audit` with his two documented `--ignore`s (RUSTSEC-2026-0042/0043, aws-lc-fips pin, rationale in deny.toml + SUPPLY_CHAIN.md): passes; 4 further *warnings* (ansi_term, atty ×2, proc-macro-error2 — unmaintained/unsound, dev-only) are disclosed in deny.toml comments, exactly as documented. **But plain `cargo deny check` fails**: `error[yanked]: detected yanked crate` — `chacha20 0.10.1` is yanked and his own policy is `yanked = "deny"`. His CI never sees this because ci.yml:87 runs `cargo deny check 2>&1 \|\| true` — the deny gate is decorative. Fix is one lockfile line (`cargo update -p chacha20`); whether the `\|\| true` stays is a decision question (Q6.5) |
| **H. `citadel_example.py` end-to-end** (README:118) | ⚠️ NEEDED-UNDOCUMENTED-STEP | Server boots per README env vars; `/health` green. The example then exits: *"Set CITADEL_KEY environment variable"* — the script reads **`CITADEL_KEY`**, while every README/QUICKSTART snippet exports **`CITADEL_API_KEY`**. One env-var rename (or a doc line) fixes the golden path. Also: actual `/health` returns `{"crypto_backend":{...},"status":"ok","version":"0.2.0"}` — README:52 shows two fields, QUICKSTART:72 shows one |
| **I. Docker quickstart** | ➖ NOT RUN | Neither environment could run Linux containers (CI runner: no compose test in our workflow; local Docker daemon is Windows-containers mode). No claim made either way |
| **J. FFI build** | ✅ WORKED (via workspace build) | cdylib/staticlib `citadel` produced; bindings not exercised end-to-end in this pass |
| **K. His own CI on a clean clone** | ✅ **PASSED, fully green** | The repo's own `ci` workflow ([run 33677391360](https://github.com/LuckyCody/citadel-v3/actions/runs/33677391360)) ran automatically on our fork push: fmt --check, clippy -D warnings, build, workspace tests, KAT/ACVP fixed-vector gates, stress suite, cargo-audit, live-server tests (persistence/concurrency/log-canary), Schemathesis (500 examples/operation). All jobs green with zero repo-owner secrets available — the gate is genuinely self-contained |


**Test-parallelism observation** (found while executing phases, reproduced twice): `citadel-api`'s `exploit_scoped_admin_*_partial_overlap_listing` unit test can fail under default parallel `cargo test` load and passes deterministically in isolation and with `--test-threads=1` — which is exactly how ci.yml runs the workspace suite, so upstream CI never sees it. Not a product bug; a shared-state test-hygiene item worth one look.

**Overall verdict:** this repo reproduces. A fresh Ubuntu user following only the README gets a building, testing, judge-passing system, and the project's own CI passes on a fork with no secrets — rarer than it should be. The three real catches: the example's `CITADEL_KEY`/`CITADEL_API_KEY` mismatch (breaks the documented first-run), the yanked-chacha20 deny failure hidden behind `|| true`, and the judge's `--offline` default (fine in README order, surprising judge-first). Windows works end-to-end (build+tests) despite being undocumented.
# §3 Code Quality — Static Half (Consistency Audit)

Repo: `C:\Data\citadel-v3` · 7 workspace crates · audited 2026-09-02 (read-only, grep/read; clippy/cargo-audit run separately on Linux).
Workspace profile note: `panic = "unwind"` in release (`Cargo.toml` root) — relevant to §3.2.

---

## 3.1 Unsafe inventory

**Totals:** 24 non-test `unsafe` sites in workspace crates — 23 in `citadel-ffi`, 1 in `citadel-envelope` (`backend_awslc.rs`). **Zero** unsafe in citadel-api, citadel-keystore, citadel-core, citadel-signer, citadel-cli. `citadel-envelope` carries crate-wide `#![deny(unsafe_code)]` (`lib.rs:49`); no other crate declares the lint (recommend adding `#![forbid(unsafe_code)]` to keystore/core/signer/api/cli to lock in the current zero).

### citadel-ffi (`citadel-ffi\src\lib.rs`) — non-test (everything below line 634; tests start at the `#[cfg(test)] mod safety_tests` on 634)

Design context: every fallible export runs inside `ffi_guard` (`catch_unwind` → `CITADEL_ERR_PANIC`, lines 100–107), and all 7 `pub unsafe extern "C"` fns carry a `# Safety` doc section. Internal `*_impl` fns inherit the exported contract; inner `slice::from_raw_parts` calls rely on that fn-level contract rather than per-block `// SAFETY:` comments.

| Location (lib.rs) | What it does | Justified? | Safety comment? | Note |
|---|---|---|---|---|
| 135 `unsafe { alloc(layout) }` in `alloc_buf` | Raw heap alloc for out-buffers | Yes (allocator API) | Partial | Layout via `Layout::array` (Err→null), null-checked; registered in allocation map. No literal `// SAFETY:` tag. |
| 150–154 block in `write_output` | `copy_nonoverlapping` + writes through out-pointers | Yes | No inline | Buffer freshly alloc'd at `len`; out-pointers null-checked by every caller before use. |
| 198 `pub unsafe extern "C" fn citadel_keygen` | C export: keygen | Yes (FFI boundary) | Yes (`# Safety` 195–196) | Guarded by `ffi_guard`. |
| 204 block (ffi_guard closure) | Calls `citadel_keygen_impl` | Yes | Inherited | — |
| 207 `unsafe fn citadel_keygen_impl` | Null-checks, zeroes outputs, writes results | Yes | Yes (216–217, 228–235 incl. Zeroizing-during-unwind rationale) | Exemplary. |
| 248 `citadel_seal` | C export: A3 seal | Yes | Yes (244–246) | — |
| 260 block | ffi_guard closure | Yes | Inherited | — |
| 268 `citadel_seal_impl` | `from_raw_parts` on pk/pt/aad/ctx, null-checks first | Yes | Fn-level only | Lengths are caller-supplied — contract documented at export. |
| 322 / 334 / 342 `citadel_open` (+block, +impl) | C export: A3 open | Yes | Yes (318–320) | Same pattern as seal. |
| 396 / 402 / 405 `citadel_p384_keygen` (+block, +impl) | C export: A4 keygen | Yes | Yes (393–394) | `Zeroizing` on sk bytes (424). |
| 436 / 448 / 456 `citadel_p384_seal` (+block, +impl) | C export: A4 seal | Yes | Yes (432–434) | — |
| 510 / 522 / 530 `citadel_p384_open` (+block, +impl) | C export: A4 open | Yes | Yes (506–508) | — |
| 591 / 592 / 595 `citadel_free` (+guard block, +impl; incl. `write_bytes` zeroize at 609) | Free + zero-before-dealloc | Yes | Yes (581–589, best of the file) | Allocation-registry lookup makes caller length untrusted; mutex-poison recovery at 121–125 documented. |

**Test-only unsafe (fine):** `allocation_probe` `unsafe impl GlobalAlloc` + 2 unsafe fns (lines 62–67, `#[cfg(test)]`), plus ~60 unsafe FFI call sites in the test modules (641–1360).

### Unsafe OUTSIDE citadel-ffi (the notable one)

| Location | What it does | Justified? | Safety comment? | Note |
|---|---|---|---|---|
| `citadel-envelope\src\backend_awslc.rs:649,651` | Reads AWS-LC's static C version string (`OpenSSL_version` → `CStr::from_ptr`) | Yes — FIPS module self-report requires the C call | Yes — scoped `#[allow(unsafe_code)]` at 638 with 634–637 doc justifying the exception against the crate's `deny(unsafe_code)` | Exemplary handling. This is the **only** unsafe in any crypto crate. |

**Out-of-workspace tooling (not members, listed for completeness):** `fuzz\fuzz_targets\fuzz_ffi_free.rs` (37–52, exercises the FFI by design), `gauntlet\tier8_ct\ctgrind_harness\src\main.rs:39` (ct-grind harness). No action.

---

## 3.2 Panic paths in the API request path (citadel-api)

`citadel-api\src\main.rs`: 466 total panic-macro/unwrap/expect hits; **30 non-test** (tests begin line 3427), of which **~15 in request-reachable code (7 distinct sites)** and ~15 in startup/init.

### No panic containment at the HTTP layer

- **No `CatchPanicLayer`, no `std::panic::set_hook`** anywhere in citadel-api (grep: zero hits). `tower-http` is compiled with `features = ["cors"]` only (`citadel-api\Cargo.toml:45`); the only layers are the two auth/security `middleware::from_fn_with_state` + cors (main.rs:3364–3372).
- Consequence under `panic = "unwind"`: a handler panic is swallowed by the tokio task → the client gets a **dropped connection**, not a 500; process survives but there is no uniform error response and no request-id in the log for it. Ironic contrast: the FFI crate guards every entry point with `catch_unwind`, the network-facing crate guards none.

### (a) Request-handling paths — complete list

| # | file:line | What it is | What input reaches it |
|---|---|---|---|
| 1 | `main.rs:492,502,515,527,540,546` — `panic!` ×6 in `validate_master_key()` | Master-key hex/length/entropy/pattern rejection | **Every authenticated request.** `auth_middleware` (1065) → `hash_api_key` (597) → `validate_master_key`. **Gap:** the startup gate `create_keystore` (2891–2907) validates only hex + 32 bytes, NOT the entropy/AP/period checks — a low-entropy but well-formed key **boots cleanly and then panics on every request that presents an API key**. Worst finding in this section. |
| 2 | `main.rs:580,582,585` — `unwrap_or_else(panic!)` ×3 in `hash_api_key()` local-pilot branch | Loads root-key file per call | Every authenticated request when `CITADEL_PROFILE=local-pilot`. Root-key file deleted/chmod'd **after** startup → per-request panic instead of 503. |
| 3 | `main.rs:474` — `.expect("HMAC-SHA256 accepts any key length")` in `hmac_sha256` | HMAC init | Every authenticated request. Genuinely infallible (HMAC accepts any key length) — acceptable invariant. |
| 4 | `main.rs:617` — `getrandom(...).expect(...)` in `generate_api_key()` | OS CSPRNG | `POST /api/apikeys` handler (called at 2747). Fails only on OS RNG failure — arguably correct to die, but it dies as a dropped connection, not a 500. |
| 5 | `main.rs:625` — same in `generate_key_id()` | OS CSPRNG | Same handler (2749). |
| 6 | `main.rs:1024` — `"127.0.0.1:0".parse().unwrap()` | Constant fallback addr in `auth_middleware` | Every request without `ConnectInfo`. Infallible constant — fine. |
| 7 | `main.rs:1033` — `.expect("required_scope returned None after is_none check — logic error")` | Post-`is_none` re-unwrap in `auth_middleware` | Every scoped request. Logic invariant; would be cleaner as `let Some(required) = ... else`. |

No `panic!/unreachable!/todo!/unimplemented!` and no unguarded `[index]`/range slicing in any handler body (the only non-test indexing is in `validate_master_key` helpers, length-guarded at 501/560–562). Handlers between lines 1035–2900 are otherwise fully `match`/`?`-disciplined — that discipline is genuinely good.

### (b) Startup/init — acceptable, count only

**16 hits**: `main.rs:311` (TimingDummy seal expect, built once in `build_app` at 3285), `2941–2942` (data dir + FileBackend), `3062–3122` (11 unwraps in `seed_demo_keys`, gated behind `CITADEL_SEED_DEMO=true`), `3413,3419` (bind/serve in `main`). Plus deliberate `std::process::exit(1)` preflight paths (not panics). `hash_apikey.rs` (operator CLI): 2 expects — CLI-tool acceptable.

### (c) Tests — count only

**436 hits** in `main.rs` `#[cfg(test)]` modules (lines 3427+). Fine.

---

## 3.3 Same sweep: citadel-envelope & citadel-keystore (non-test code)

### citadel-envelope — clean

Non-test unwrap/expect sites, all invariant-style, **none reachable from attacker-controlled `open()` input** (seal/open return `Result` with unit-struct errors — deliberate oracle discipline, `error.rs:31-36` even normalizes `EncodingError→DecryptionError`):

- `kem.rs:106` — `MlKemPublicKey::new(...).expect("validated at construction")` (re-parse of already-validated bytes).
- `backend_awslc.rs:437,449` (freshly generated material must parse), `509,512,515` (`public_key_of`: stored scalar validated at construction), `653` (AWS-LC version string UTF-8).
- `kem_p384.rs:201` — `#[doc(hidden)]` KAT-vector helper, fixed scalar.
- Slicing in `encapsulate`/`decapsulate` is length-guarded (`ct.len() != KEM_CIPHERTEXT_BYTES` check before `ct[..P384_POINT_BYTES]`).

### citadel-keystore — one pattern worth fixing

| Location | What | Risk |
|---|---|---|
| `keystore.rs:1922` — `self.replay_cache.lock().unwrap()` | **In the `decrypt()` hot path** (replay claim) | Mutex-poison panic: one panic while the lock is held permanently panics **every subsequent decrypt**. Note the FFI crate solved exactly this for its allocation registry (`lock_allocations`, poison-recovery via `into_inner()`, lib.rs:121–125) — inconsistent standards between crates. |
| `keystore.rs:2069,2095,2099,2106,2126,2130,2161,2166` — `self.threat.lock().unwrap()` ×8 | Threat-level read/record (reachable from status/metrics/decrypt paths) | Same poison pattern. |
| `audit.rs:411` — `self.state.lock().unwrap()` in `IntegrityChainSink` | Audit hash-chain state — touched on **every** audited op (generate/encrypt/decrypt/rotate) | Same. |
| `storage.rs:67,72,78,84,89,98` — `RwLock` `.unwrap()` ×6 in `MemoryBackend` | Dev-mode backend | Acceptable (dev), same pattern though. |
| `backup.rs:198,201` — `try_into().unwrap()` on `data[8..16]` / `data[16..28]` | Backup blob parse (restore op) | **Guarded** — `data.len() < HEADER_LEN + 16` rejected at 176. Fine, but the unwraps silently depend on `HEADER_LEN` staying ≥ 28. |
| `keystore.rs:1910` — `&ciphertext[len - AEAD_TAG_BYTES..]` | Tag slice for replay key | Preceded by `envelope_nonce()` full-decode (wire framing enforces min lengths incl. tag) — guarded, OK. |

Everything else in keystore (threat.rs, policy.rs, hierarchy.rs, graph.rs, migration.rs, replay.rs, doctor.rs, root_key_provider.rs, types.rs): **zero** hits. replay_store/sharded_replay_cache/audit_witness/lib.rs hits are all `#[cfg(test)]`.

**Recommendation (one-line fix, three files):** adopt the ffi `lock().unwrap_or_else(|p| p.into_inner())` poison-recovery idiom (or a shared helper in citadel-core) for `replay_cache`, `threat`, and the audit chain mutex.

---

## 3.4 Dead code

`#[allow(dead_code)]` census (12 sites; 2 are test files — fine):

| Location | Verdict |
|---|---|
| **`citadel-envelope\src\cli.rs` (311 lines)** — no attribute, but **orphaned**: not declared in `lib.rs`, not a `[[bin]]` target, and is a divergent near-duplicate of `src\bin\citadel-encrypt.rs` (different flag names: `--input/--output` vs `--in`, has `inspect`, other doesn't) | **Top finding — delete or make it the single CLI.** Two CLIs with incompatible flags is a doc/support hazard. |
| `citadel-api\src\main.rs:3217` on `build_app()` | **Stale** — used by `main()` (3410) and tests. Remove attribute. |
| `citadel-api\src\main.rs:670` on `enum Operation` | Blanket allow over the whole authz enum — masks genuinely unused variants. Narrow it. |
| `citadel-api\src\main.rs:1201` on `struct SignReq` | Struct IS used (`sign_data`, 2105); allow covers the never-read `context` field. Either wire `context` into the audit event or drop the field. |
| `citadel-core\src\state_enforcer.rs:180` `capability()` | pub(crate) accessor kept for P261 validation — has explanatory comment, OK. |
| `citadel-keystore\src\replay_store.rs:285` & `626` — `fail_closed` field in **both** FileReplayStore and RedisReplayStore | Config accepted but never read — either enforce fail-closed behavior or remove; carrying a dead safety knob is the worst kind of dead code in a KMS. |
| `citadel-keystore\src\replay_store.rs:756` `redis_get` stub | Feature-gated fallback (`#[cfg(not(feature = "redis-backend"))]`) — legit. |
| `citadel-envelope\src\backend.rs:155`, `aead.rs:19` — `#[cfg_attr(feature = "fips", allow(dead_code))]` | Deliberate "compile both backends so neither rots", documented in comments — exemplary. |
| `citadel-keystore\tests\vertical_slice.rs:37,1306` | Test helpers — fine. |

Module wiring: every `mod`/`pub mod` in all 7 crates maps to a live file; **no orphan modules except `citadel-envelope\src\cli.rs`** above. No zero-call-site pub functions found beyond that file (FFI exports and `#[doc(hidden)]` KAT helpers correctly excluded from "dead").

---

## 3.5 TODO/FIXME/HACK/XXX census

**3 TODOs, 0 FIXME/HACK/XXX** across all `.rs` in the repo — remarkably clean.

- **citadel-core** — `src\state_enforcer.rs:1058`: assertion message `"TODO: Should fail when replay store integrated"` (test documents a known future-tightening; the assertion currently passes the lenient way).
- **citadel-api** — `src\main.rs:5636`: `// TODO: implement domain-filtered listing to verify Domain A keys are excluded.` (test gap — the scoped-admin listing test doesn't assert exclusion).
- **citadel-api** — `src\main.rs:5859`: `// TODO: verify global bootstrap key is filtered from scoped admin view.` (same class of test gap).

Both api TODOs are missing *assertions in authz tests* — worth burning down since domain isolation is a headline guarantee.

---

## 3.6 Duplicated code across crates

1. **Master-key validation exists in 3 divergent copies** — and the divergence is the §3.2 bug: `main.rs:487 validate_master_key` (hex+len+entropy+AP+period), `main.rs:2891` `create_keystore` inline (hex+len only), `hash_apikey.rs:69` inline (hex+len only). Consolidate into one function (citadel-core or keystore) called by both startup and `hash_api_key`, so startup and request-path can never disagree again.
2. **HMAC-pepper API-key hashing duplicated**: `main.rs:470 hmac_sha256` vs `hash_apikey.rs:85–89` (same algorithm hand-rolled twice; the doc in hash_apikey even promises "matching the algorithm used by the API server" — a promise only convention enforces).
3. **Local-pilot root-key loading block appears 3×**: `main.rs:578–586` (per-request!), `main.rs:2881+` (startup), `hash_apikey.rs:47–62`.
4. **`citadel-envelope\src\cli.rs` vs `src\bin\citadel-encrypt.rs`** — two forks of the same CLI (see §3.4).
5. **Error-newtype boilerplate**: `citadel-keystore\src\error.rs` has 6 structurally identical `struct XError(pub KeystoreError)` + Display + From blocks (Generate/Lifecycle/Rotate/Expire/Rewrap/Cascade); `citadel-signer\src\error.rs` has 3 identical `struct XError(pub String)` blocks. A tiny macro (or shared derive in citadel-core) removes ~120 lines. Do **not** touch citadel-envelope's unit-struct errors — their information-free Display is deliberate oracle discipline.
6. Minor: demo key-hierarchy seeding duplicated between `citadel-api\src\main.rs:3058 seed_demo_keys` and keystore's test fixture (`lib.rs:130+`) — test-only, low priority.

citadel-core is nearly empty today (one module, `state_enforcer`) — items 1/2/5 are natural first tenants.

---

## 3.7 Error handling pattern (citadel-api)

- **No typed error with an `IntoResponse` impl.** Handlers return `impl IntoResponse` and build errors by hand through helpers `err()` (400, main.rs:1344) / `err500()` (main.rs:1430), both producing `Json(ApiError { error, request_id })`. So the *shape* is uniform (good: every error carries a request_id), but the *mapping* is per-handler and string-driven.
- **Status-by-substring anti-pattern**: `main.rs:1943,2158,2241` pick status codes via `msg.contains("StateEnforcer") || msg.contains("revoked") || msg.contains("Active")` on `e.to_string()` — brittle; a Display-wording change silently turns 403s into 500s. This is the strongest argument for a real `enum ApiFailure` + `IntoResponse`.
- **Internal error strings leaked into response bodies** — `e.to_string()` of `KeystoreError` flows to clients; `KeystoreError::StorageError(String)`/`EnvelopeError(String)` wrap raw IO/engine messages (can include file paths). 500-class leaks: `main.rs:1548`, `1574`, `1617`, `2627` (+ `1572` leaks a serde error). 400-class sites passing internal Display to clients: `1636,1717,1759,1814,1859,1892,2396,2402` (mostly `key not found: <id>` — tolerable, but same mechanism). Inconsistency: the keystore's own decrypt path deliberately collapses everything to `"operation failed"` (keystore.rs:1902) — the API layer then re-leaks other ops' internals. Fix: at the `err500` boundary, log `e` with the request_id and return a generic body.

---

## Actionable shortlist (ranked)

1. **Close the master-key validation gap** (§3.2 #1): call full `validate_master_key` at startup in `create_keystore`, and make `hash_api_key` return `Result` instead of panicking — today a well-formed low-entropy key boots, then panics on every authenticated request.
2. **Add `CatchPanicLayer`** (tower-http `catch-panic` feature) + optional panic hook so any residual panic becomes a uniform 500 with request_id (§3.2).
3. **Poison-safe mutexes in keystore** (`replay_cache`, `threat`, audit chain) using the idiom citadel-ffi already ships (§3.3).
4. **Delete or promote `citadel-envelope\src\cli.rs`** (311-line orphan fork of the shipped CLI) (§3.4/3.6).
5. **Stop leaking internal error strings in 500 bodies**; replace the `msg.contains(...)` status dispatch with a typed error + `IntoResponse` (§3.7).
6. Consolidate master-key/HMAC/local-pilot loading into citadel-core (§3.6) and wire or remove the dead `fail_closed` replay-store knobs (§3.4).
# §4 — Docs Coherence Audit (citadel-v3)

**Scope:** consistency audit of the documentation set at `C:\Data\citadel-v3` (read-only; repo untouched).
**Baseline:** git HEAD `31deefe` (2026-08-17); `VERSION` = `citadel-v3-beta-001` / 2026-08-06; workspace crates at 0.2.0.
**Fairness note:** this maintainer documents unusually well — self-superseding decision logs (PROVIDER_DECISION_LOG), self-flagged stale guides (INTEGRATION_GUIDE's own header note), scope-exact FIPS tables (whitepaper §5), and an explicit "this document must never state a stronger claim than X" rule (THREAT_MODEL). The findings below are real byte-level or claim-level conflicts, not stylistic variance. Every contradiction cites both sides.

---

## 1. Doc-authority map

All 29 root `.md` docs plus `whitepaper/*`, `fuzz/README.md`, `gauntlet/README.md`. (No `.md` files exist under `deploy/` — its docker/kubernetes/systemd dirs are config-only.) "Last git touch" from `git log -1` per file; repo history starts 2026-07-09.

| Doc | Topic | Claims to be authoritative for | Actually authoritative? | Overlaps with | Staleness signals |
|---|---|---|---|---|---|
| README.md | Front door | Nothing explicitly; but Project Structure comment (README.md:274) labels SPEC.md "Authoritative wire specification" | Mostly accurate; three overclaims (§3.9, §3.13, compliance count) | Everything | Wire diagram at :221-224 shows v1 layout under "Wire Format" heading while v2 is current |
| SPEC.md | v1 wire format | "describes the v1 structured wire format implemented in the Rust crate" (SPEC.md:3) | **YES for v1** — matches `wire.rs`/`kdf.rs` byte-for-byte | WIRE_SPEC.md, FORMAT.md, README:219-226, MIGRATION.md | Untouched since initial commit (2026-07-09); no pointer to v2 |
| WIRE_SPEC.md | v1 wire format, "formal" | "Formal Specification, Version 1.0.0, **Status: FINAL**" (WIRE_SPEC.md:3-5) | **NO — key schedule contradicts shipped code** (see §2.2) | SPEC.md, FORMAT.md | Header date 2026-01-28 predates the public repo; untouched since 2026-07-09; labels never matched code in public history |
| WIRE_SPEC_V2.md | v2 wire format | "frozen implementation target... New encryption emits v2" (WIRE_SPEC_V2.md:4,10) | **YES for current format** — matches `wire_v2.rs` | README:226,289 | Only defines suite `0xA3` in constants (:26); `0xA4` layout not specified here (code+README+API_FREEZE carry it) |
| FORMAT.md | Envelope semantics overview | "high-level encoding and binding semantics" (FORMAT.md:3) | Partially — binding rules still true, but titled "(v1)" | SPEC.md, WIRE_SPEC_V2.md | Untouched since 2026-07-09; no mention of v2/CTD2 |
| QUICKSTART.md | Getting started | "Golden Path — canonical verification path" (QUICKSTART.md:3-5) | YES | README Quick Start, DEPLOYMENT.md | Health output at :72 omits `version` field code returns |
| DEPLOYMENT.md | Production deployment | "Production Deployment Guide" | Mostly; two sections stale (§3.7), one durability overclaim (§3.4) | QUICKSTART, SECURITY_GUARANTEES, REPLAY_* | "What's Next (Tier 2)" (:341) lists shipped features as future; "single bootstrap admin key" (:353) contradicts code; log example says v0.1.0 (:286); config table markdown broken by mid-table blockquote (:250-257) |
| INTEGRATION_GUIDE.md | SDK integration | SDK integration guide | YES (self-corrected: header note :5-7 flags its own staleness) | README Usage, API_FREEZE | Structure diagram (:11-19) shows 5 crates + deploy; README:265-272 shows 7 (omits citadel-core, citadel-signer) |
| MIGRATION.md | Python→Rust migration | Relationship of Python prototype to Rust impl | YES for what it covers — but v1-era residue (§4) | SPEC.md | Untouched since 2026-07-09; presents "Rust Citadel Envelope v1" as the current protocol (:11), no v2 mention |
| THREAT_MODEL.md | Attacker model | Security goals/assumptions; declares SUPPLY_CHAIN + SECURITY_MATURITY controlling for FIPS wording (:131-132) | Largely yes; FIPS scope phrase overbroad (§3.9); aes-gcm version stale | SECURITY_GUARANTEES, SECURITY_MATURITY, TIMING | ":27 328+ passing" vs VALIDATION_MATRIX 435 / SECURITY.md 500 (different vintages) |
| SECURITY_GUARANTEES.md | What is/isn't protected | "design-level claims" (:3) | Mostly; replay-durability claim stronger than code (§3.4); primitive table stale (§3.12) | THREAT_MODEL, REPLAY_* | aes-gcm listed 0.10 (:126); Cargo.toml has 0.11 |
| SECURITY_MATURITY.md | Deployment readiness | README:296 assigns it "deployment-readiness scope and limits"; THREAT_MODEL:131 makes it controlling for FIPS wording | Structurally yes, but its FIPS paragraph contradicts every other doc **and cites a file that doesn't exist** (§3.3) | THREAT_MODEL, VALIDATION_MATRIX, CITADEL_OVERVIEW | "Last Updated: Round 4 Security Audit" (no date, :263); references `CLAIM_EVIDENCE_MATRIX.md` (absent from repo); replay §3 correctly summarizes batched-mode window |
| SIDE_CHANNEL_NOTES.md | Timing status (short) | "Allowed External Claim" wording (:8-11) | **NO on auth-comparison fact** — stale (§3.11) | TIMING.md, README, DEPLOYMENT | Claims API key comparison "uses `==`" (:27-28) — code uses `subtle::ct_eq` |
| TIMING.md | Timing validation record | "Citadel's timing rule" — full dudect record | YES (most detailed and carefully hedged doc in repo) | SIDE_CHANNEL_NOTES, THREAT_MODEL | — |
| REPLAY_STORE_GUARANTEES.md | Replay store behavior | Per-backend guarantees | Mostly; internal contradiction on corruption recovery (§3.6); one garbled sentence (:3) | REPLAY_TRUST_BOUNDARIES, SECURITY_GUARANTEES, DEPLOYMENT | Footer "Last updated 2026-05-02" (:95) predates the git repo; consistent w/ VERSION tag though |
| REPLAY_TRUST_BOUNDARIES.md | Replay durability boundaries | ":238 This document supersedes earlier replay-persistence claims" — the only doc that explicitly claims supersession | **YES on durability semantics** (matches `replay_store.rs` batching) — **NO on config surface** (env vars don't exist, §3.5); Redis mislabeled "Future" (:96) | REPLAY_STORE_GUARANTEES, DEPLOYMENT, SECURITY_GUARANTEES | `CITADEL_REPLAY_BACKEND`/`CITADEL_REPLAY_FLUSH_MODE` (:17,:38-39,:73-74) not read by API; "replay.db" (:154) vs replay.json |
| SECURITY.md | Vuln reporting + audit status | Security policy | YES | SECURITY_GUARANTEES, VALIDATION_MATRIX | Contact emails vary across docs (gmail :62 / outlook :203 / reposignal in README:325) |
| VALIDATION_MATRIX.md | Per-claim test evidence | "per-claim validation record" (README:7) | YES — explicitly re-verified against CI run 2026-08-06 | SECURITY.md, THREAT_MODEL | Baseline rows dated 20260501 (intentional, explained :20-22) |
| COMPLIANCE_MATRIX.md | NIST 800-57 mapping | Control mapping, self-assessed | YES — but README/OVERVIEW quote different totals than its own summary (§3.8) | README:258, CITADEL_OVERVIEW:112 | — |
| CITADEL_OVERVIEW.md | Commercial positioning | Marketing one-pager | Honest on audit status; **overclaims CNSA via ML-KEM-768** and mis-describes the envelope mechanism (§3.10) | README, SECURITY_MATURITY, DEPLOYMENT | No mention of suite `0xA4` anywhere despite 0.2.0 vintage commit; compose sample won't boot under DEPLOYMENT's own gates |
| CHANGELOG.md | Release history | Release record | YES; its "Unreleased" note (:8-14) documents the very accuracy pass whose stragglers this audit found | VERSION, Cargo.toml | — |
| API_FREEZE.md | API stability | "Stability Contract... FROZEN" | YES (0xA4 additions correctly logged as Tier-2 additive) | INTEGRATION_GUIDE, SPEC.md | Header "Version 0.1.0, 2026-02-05" predates public repo; never re-versioned for 0.2.0 |
| SUPPLY_CHAIN.md | Advisory status | "Authoritative tools: cargo audit / cargo deny" (:3-4); named controlling by THREAT_MODEL:131 | YES | SECURITY.md, THREAT_MODEL | "Last reviewed: 2026-07-20" (:3) yet contains packet-058 content dated 2026-08-04 (:29) — header not bumped |
| SUPPORT.md | Support tiers | Support tiers | YES | SECURITY.md contacts | Empty "## Overview" section (:3-5) |
| CONTRIBUTING.md | Contribution policy | No-external-PRs policy | YES | CODE_OF_CONDUCT | — |
| CODE_OF_CONDUCT.md | Community standards | Contributor Covenant | YES | — | — |
| COMMERCIAL_LICENSE.md | Commercial terms | License v1.1 | YES | README §License | — |
| PROVIDER_DECISION_LOG.md | ML-KEM provider history | Decision log; each entry explicitly supersedes the prior (:19-21) | YES — model example of supersession done right | PROVIDER_BAKEOFF_2026 | — |
| PROVIDER_BAKEOFF_2026.md | Provider scorecard | "Frozen Before Migration" | YES | PROVIDER_DECISION_LOG | — |
| whitepaper/CITADEL_WHITEPAPER.md | Technical paper | Design + measured results; most precise FIPS scope statement in repo (§5 table) | YES | README, THREAT_MODEL, WIRE_SPEC_V2 | Draft 2026-08-05 |
| whitepaper/REFERENCES.md | Citations | Reference list | YES | — | — |
| fuzz/README.md | Fuzz targets | 4 fuzz targets | YES (all 4 target files exist in `fuzz/fuzz_targets/`) | gauntlet/README | — |
| gauntlet/README.md | Validation battery | 9-tier gauntlet | YES (`gauntlet/receipts/SUMMARY.md` exists) | VALIDATION_MATRIX, SECURITY.md | — |

---

## 2. The wire-format canon question (centerpiece)

Four documents describe the wire format, plus README's own diagram. Verified against `citadel-envelope/src/wire.rs`, `kdf.rs`, `kem.rs`, `wire_v2.rs`.

### 2.1 Who says what governs

| Source | What it says |
|---|---|
| README.md:274 (Project Structure) | `SPEC.md # Authoritative wire specification` |
| README.md:287 (doc table) | SPEC.md = "v1 wire format specification" |
| README.md:288 | WIRE_SPEC.md = "v1 wire format, formal RFC-2119 notation" |
| README.md:289 | WIRE_SPEC_V2.md = "v2 wire format (**current** envelope format)" |
| README.md:226 | "SPEC.md specifies the v1 wire format; WIRE_SPEC_V2.md specifies the current envelope-v2 header" — WIRE_SPEC.md not even mentioned here |
| SPEC.md:1-3 | "v1 Structured Wire Specification... implemented in the Rust `citadel-envelope` crate" — implementation-descriptive, doesn't claim canon |
| WIRE_SPEC.md:3-5 | "Formal Specification, Version 1.0.0, **Status: FINAL**, Date: 2026-01-28" — the only v1 doc that self-declares FINAL |
| WIRE_SPEC_V2.md:3-11 | "2.0.0-draft1, Status: frozen implementation target... The existing v1 decrypt path remains a migration input. **New encryption emits v2.**" |
| FORMAT.md:1 | "Citadel Envelope Format (v1)" — high-level, claims nothing about canon |

So: **two documents self-present as strongest authority for v1** (README:274 crowns SPEC.md "authoritative"; WIRE_SPEC.md crowns itself "FINAL"), and they **contradict each other on the v1 key schedule** (below). Meanwhile the *current* format is v2 per WIRE_SPEC_V2.md:10 and README:289 — so README:274's "Authoritative wire specification" pointing at a v1-only doc is doubly misleading.

### 2.2 Do the four agree byte-for-byte on v1? — NO. One real cryptographic contradiction.

**Layout (header + framing): AGREE.** SPEC.md:45-55, WIRE_SPEC.md:54-68, FORMAT.md:6-9 (prose), README:221-224, and MIGRATION.md:55-58 all give the identical v1 layout — `version(0x01) || suite_kem(0xA3) || suite_aead(0xB1) || flags(0x00) || kem_ct_len(BE16=1120) || kem_ct[1120] || nonce[12] || aead_ct[≥16]`, min 1154 bytes. Code agrees: `wire.rs:17-90` (HEADER_BYTES=6, KEM_CIPHERTEXT_BYTES=1120, MIN_CIPHERTEXT_BYTES=1154, NONCE_OFFSET=1126). Key sizes 1216/2432 agree everywhere (SPEC.md:38-39, WIRE_SPEC.md:37-38, wire.rs:63-66).

**KDF / key schedule: CONTRADICT.** This is the finding.

- **SPEC.md:61-65** (single-stage):
  `combined_ss = x25519_dh[32] || mlkem_ss[32]` (64 bytes) → `aes_key = HKDF-SHA256(ikm=combined_ss, salt=None, info="citadel-env-v1" || "|aes|" || SHA3-256(kem_ct) || context, len=32)`
- **WIRE_SPEC.md** (two-stage, different labels):
  - Stage 1 (WIRE_SPEC.md:179-184, diagram :114-123): `shared_secret[32] = HKDF(ikm=combined_ikm, info="citadel-hybrid-v1")`
  - Stage 2 (WIRE_SPEC.md:187-193, table :161-162): `aes_key = HKDF(ikm=shared_secret, info="citadel-hybrid-env-v1|aes|" || ct_hash || context)`
- **Code** (ground truth): `wire.rs:17` `PROTOCOL_ID = b"citadel-env-v1"`; `kdf.rs:4-6` and `kdf.rs:63-72` implement exactly SPEC.md's single-stage derivation with the 64-byte concatenated ikm (`kem.rs:400-409` builds the 64-byte combined secret; there is no intermediate HKDF). `grep 'citadel-hybrid'` across all `.rs` files: **zero hits**. `git show cff9649:citadel-envelope/src/kdf.rs` confirms the label has been `citadel-env-v1` since the initial public commit (2026-07-09).

**Verdict:** an implementer following WIRE_SPEC.md — the doc marked FINAL with RFC-2119 language — produces ciphertexts that **cannot be decrypted** by the shipped code (different HKDF structure *and* different domain-separation strings). SPEC.md is the correct v1 record. WIRE_SPEC.md documents a pre-public design iteration that never matched the code in the repo's public history.

Secondary WIRE_SPEC.md-vs-code divergences (same root cause):
- WIRE_SPEC.md:43-45 mandates `MAX_AAD_BYTES=65536`, `MAX_CONTEXT_BYTES=256` as REQUIREs (:171-172, :203-204). No such limits exist on the v1 path (`grep MAX_CONTEXT` hits only `wire_v2.rs:51-52`, where the values are 64 KiB / **4096**, per WIRE_SPEC_V2.md:35-36). So WIRE_SPEC.md's v1 context cap (256) is both unimplemented and inconsistent with v2's 4096.
- WIRE_SPEC.md:293-310 promises a test-vector format with `"seed"` for deterministic keygen "See test_vectors.json" — vectors exist, but SPEC.md/MIGRATION.md:100-105 state v1 KATs deliberately don't require deterministic ciphertext bytes.

### 2.3 v2 spec vs README/code — one gap, no contradiction

WIRE_SPEC_V2.md constants (:22-37) define only `SUITE_KEM = A3`. Suite `0xA4` (P-384 + ML-KEM-1024) is live in code (`wire.rs:26-30` `SUITE_KEM_HYBRID_P384_MLKEM1024 = 0xA4`, provider in `kem_p384.rs`), on the README front page (README.md:5, :204-211), in THREAT_MODEL.md:14-21, and in API_FREEZE.md Tier-2. **No document specifies the 0xA4 wire lengths normatively** — README:226 says only "suite 0xA4 substitutes a P-384 ephemeral key and the ML-KEM-1024 ciphertext." The per-suite length table lives solely in code (`wire.rs` SUITE_TABLE). Gap, not contradiction — but it means the "current" spec is incomplete for half the advertised suites.

### 2.4 README's own layout diagram

README.md:221-224 presents the **v1 6-byte-header layout** under the heading "Wire Format", generalized to both suites — but new encryption emits **v2** (CTD2 magic, 98-byte header, `recipient_key_hash`, `context_hash`, `plaintext_len`; WIRE_SPEC_V2.md:41-59). The caveat sentence at README:226 does route readers correctly, yet the only layout a README reader ever *sees* is the legacy one. Ambiguity, not error.

### 2.5 What a supersede-banner pass looks like (exact text)

Canon ruling: **WIRE_SPEC_V2.md = canon for the current format; SPEC.md = canon for the v1 legacy-decrypt format; WIRE_SPEC.md = historical, wrong, must be banner-quarantined; FORMAT.md = semantics overview, demoted to non-normative.**

1. **WIRE_SPEC.md** — insert directly under the title (and change `Status: FINAL` to `Status: SUPERSEDED — HISTORICAL`):
   > **⚠️ SUPERSEDED / HISTORICAL — DO NOT IMPLEMENT FROM THIS DOCUMENT.** The key schedule in §4–§5 (two-stage HKDF, labels `citadel-hybrid-v1` / `citadel-hybrid-env-v1|aes|`) describes a pre-release design that was never shipped. The implemented v1 derivation is single-stage with label `citadel-env-v1|aes|` — see [SPEC.md](SPEC.md) (normative for v1) and `citadel-envelope/src/kdf.rs`. The current envelope format is v2: [WIRE_SPEC_V2.md](WIRE_SPEC_V2.md).
2. **SPEC.md** — insert under the title:
   > **Status: normative for the legacy v1 format (decrypt-only).** New encryption emits envelope v2 — see [WIRE_SPEC_V2.md](WIRE_SPEC_V2.md), the canonical wire specification. v1 sealing requires the `legacy-envelope-v1` feature. This document supersedes [WIRE_SPEC.md](WIRE_SPEC.md), whose v1 key schedule never matched the implementation.
3. **FORMAT.md** — retitle "Citadel Envelope Format — Binding Semantics (non-normative)" and insert:
   > **Non-normative overview.** Byte-level authority: [WIRE_SPEC_V2.md](WIRE_SPEC_V2.md) (current, v2) and [SPEC.md](SPEC.md) (legacy v1). The binding rules here apply to both versions.
4. **WIRE_SPEC_V2.md** — add one line under Status:
   > **Canonical wire specification.** Supersedes [SPEC.md](SPEC.md) (v1, retained for the legacy decrypt path) and [WIRE_SPEC.md](WIRE_SPEC.md) (historical, inaccurate). *(Optionally: add the 0xA4 per-suite length table so both shipped suites are normatively specified.)*
5. **README.md:274** — change the Project Structure comment from `# Authoritative wire specification` to `# Legacy v1 wire spec (current: WIRE_SPEC_V2.md)`; README.md:288 doc-table row for WIRE_SPEC.md gains "(historical — superseded)".

---

## 3. Contradictions between docs

Severity: **HIGH** = a reader acting on the wrong doc gets broken interop or a false security belief · **MEDIUM** = materially wrong/stale statement, low blast radius · **MINOR** = cosmetic/vintage drift.

### 3.1 HIGH — WIRE_SPEC.md v1 key schedule vs SPEC.md + code
Full detail in §2.2. WIRE_SPEC.md:114-123,161-162,179-193 vs SPEC.md:61-65 + `citadel-envelope/src/wire.rs:17` + `kdf.rs:63-72`.

### 3.2 HIGH — Which doc is the wire canon (README self-contradiction)
README.md:274 ("Authoritative wire specification" → SPEC.md) vs README.md:287-289 (SPEC=v1, WIRE_SPEC_V2="current") vs WIRE_SPEC.md:4 ("FINAL"). Three different authority signals; the one doc crowned "FINAL" is the wrong one. Detail + fix in §2.1/§2.5.

### 3.3 HIGH — FIPS/CMVP validation status of the AWS-LC pin
- **SECURITY_MATURITY.md:40-43:** "the optional `fips` build routes envelope operations through the AWS-LC FIPS module, but that module's CMVP status is **review-in-process at the current pin — NOT validated**; see the FIPS-backend section of the factory `CLAIM_EVIDENCE_MATRIX.md`, which controls all wording" — **`CLAIM_EVIDENCE_MATRIX.md` does not exist anywhere in the repo** (verified).
- Versus, in the same repo: README.md:215,248 ("the exact build that **CMVP validated** as AWS-LC-FIPS 3.1.0, certificates #5298/#5314"); THREAT_MODEL.md:120-122 (same, "CMVP-validated build"); CHANGELOG.md:9-13 (Unreleased: FIPS claim "aligned to the pinned, **CMVP-validated** 3.1.0 build **across all docs**"); SUPPLY_CHAIN.md:28-30 ("The CMVP-**validated** pin aws-lc-fips-sys 0.13.11... certs #5298/#5314"); whitepaper/CITADEL_WHITEPAPER.md status block ("the exact build that CMVP validated as AWS-LC-FIPS 3.1.0").
- Aggravator: THREAT_MODEL.md:131-132 designates SUPPLY_CHAIN.md and SECURITY_MATURITY.md as the controlling records — and those two now disagree with each other. The CHANGELOG documents an alignment pass that evidently missed SECURITY_MATURITY.md:40-43. (Everyone agrees Citadel itself is not FIPS-validated; the conflict is strictly about the module pin's CMVP status.)

### 3.4 HIGH — Replay durability: per-claim persistence vs batched flush
- **DEPLOYMENT.md:202:** "Nonces are claimed atomically and **written to `CITADEL_DATA_DIR/replay.json` on every successful claim()**. A restart reloads the file." **SECURITY_GUARANTEES.md:48-49:** "Replays are rejected across process restarts. Nonces written to replay.json survive restart" (unqualified).
- Versus **REPLAY_TRUST_BOUNDARIES.md:31-52** (default = batched, crash window up to 5 s / 100 ops) and code `citadel-keystore/src/replay_store.rs:262-272`: "Claims are durable **ONLY after flush()**. Unflushed claims... LOST on crash. Replay window... up to 5 seconds... or 100 operations." SECURITY_MATURITY.md:119-129 also states the 5-second window correctly.
- Verdict: the guarantee is stated **stronger** in SECURITY_GUARANTEES/DEPLOYMENT than in RTB/SECURITY_MATURITY/code. RTB + code are right.

### 3.5 HIGH — REPLAY_TRUST_BOUNDARIES documents config that doesn't exist
- RTB.md:17, :38-39, :73-74, :104 use `CITADEL_REPLAY_BACKEND=...` and `CITADEL_REPLAY_FLUSH_MODE=batched|immediate`.
- Code: the API reads **`CITADEL_REPLAY_STORE`** only (`citadel-api/src/main.rs:2970`); `CITADEL_REPLAY_BACKEND` survives solely as a **deprecated alias in the CLI** with a warning (`citadel-cli/src/commands/replay.rs:22-29`); `CITADEL_REPLAY_FLUSH_MODE` appears **nowhere** in the codebase — "strict mode" as a config switch does not exist (only the programmatic `force_flush()`, replay_store.rs:277-279). `env.example:26-29` and QUICKSTART.md:98 use the correct `CITADEL_REPLAY_STORE`.
- Also RTB.md:96-104 files Redis under "**Distributed Backends (Future)**", while QUICKSTART.md:131-144, DEPLOYMENT.md:188-205, deploy/docker/docker-compose.yml:38-40 and REPLAY_STORE_GUARANTEES.md:67-73 all treat Redis as shipped (`--features redis-backend`, `RedisReplayStore` exists in code). RTB is authoritative on durability *semantics* (§3.4) yet stale on the *operational surface* — worst possible combination for the one doc that declares itself the superseder (RTB.md:238).

### 3.6 MEDIUM — REPLAY_STORE_GUARANTEES internal contradictions
- RSG.md:3: "ReplayStore now uses atomic `claim()+release()` **instead of the old `claim()+release()` two-step**" — the sentence replaces a thing with itself; the old API name was evidently lost in editing.
- RSG.md:50-51 (corruption table): truncated/invalid `replay.json` → "Safe recovery (**starts fresh**) or fail-closed" vs RSG.md:56-57: "The server does **NOT silently recreate** an empty replay store after corruption unless the operator explicitly deletes the file." Both cannot be the default behavior; "or" hides the actual semantics.
- RSG.md:63: "MemoryReplayStore — Used in **tests only**" vs every other doc (DEPLOYMENT.md:196, SECURITY_GUARANTEES.md:39-45, RTB.md:10-23): memory backend is the **development-mode** default.

### 3.7 MEDIUM — DEPLOYMENT.md stale vs shipped auth features
- DEPLOYMENT.md:341-346 "What's Next (Tier 2): 1. **Multiple API keys with scopes** — per-client keys with permissions" listed as future; DEPLOYMENT.md:353-361: "Citadel V3 supports a **single bootstrap admin key** per deployment... Scoped permissions exist in the data model but are **not enforced at the route level**."
- Versus README.md:154-179 (scope table, `/api/auth/keys` CRUD endpoints) and code: `citadel-api/src/main.rs:91-105` (`required_scope()` per path/method), :3361-3363 (auth-key routes), :84-89 (scope check). Route-level scope enforcement and multi-key management are implemented; a git commit even fixed the dashboard's scoped-key creation form (95d96fa, 2026-08-07). DEPLOYMENT's "Operational Limitations" section describes an older build.

### 3.8 MEDIUM — Compliance summary numbers disagree with the matrix itself
- README.md:258 and CITADEL_OVERVIEW.md:112: "34 controls: **26 satisfied, 7 partial, 1 gap**."
- COMPLIANCE_MATRIX.md:16-23 (its own summary table): "**27 / 6 / 1**." CHANGELOG.md:13-14 says COMPLIANCE_MATRIX was reconciled with current status — README/OVERVIEW quote the pre-reconciliation totals.

### 3.9 MEDIUM — FIPS backend scope: "every envelope operation" vs 0xA4-only KEM routing
- README.md:5 & :215: "routes **all envelope operations**/**every envelope operation** through the AWS-LC cryptographic library" (hedged only for keygen/seed-expansion at :217). THREAT_MODEL.md:119-120: "routes the v2 envelope's cryptographic operations **for both suites** through the AWS-LC FIPS module."
- Versus whitepaper §5 (CITADEL_WHITEPAPER.md:173-183 + table :185-193): "The FIPS backend does **not** move every operation into AWS-LC... Suite `0xA3`'s key-encapsulation arm, which is X25519 and ML-KEM-768, **stays in pure Rust on both builds**." Code agrees: `citadel-envelope/src/backend.rs:218` "the FIPS path is `0xA4`-only (PRD NG2); `0xA3` stays byte-identical on both backends."
- The README/THREAT_MODEL phrasing is defensible only if "envelope operations" is read as the seam's symmetric primitives (AES-GCM/HKDF/hashes do route for both suites) — but a compliance-minded reader will conclude 0xA3's KEM runs in AWS-LC, which is false. The whitepaper's table is the precise formulation; README/THREAT_MODEL should adopt its one-sentence scope.

### 3.10 MEDIUM — CITADEL_OVERVIEW.md (commercial doc) vs README honesty and mechanics
Credit first: the overview's Current Status table (OVERVIEW.md:122-132) honestly carries "Independent audit: **Not yet completed**", "Production deployments: **None yet**", and the correct FIPS disclaimer — it does *not* overclaim on audit posture relative to README:7. The real problems are technical:
- **CNSA overclaim:** OVERVIEW.md:118 "CNSA 2.0 | **ML-KEM-768 meets 2025 software requirement**." Everywhere else CNSA alignment attaches to `0xA4`/ML-KEM-1024 (README.md:5,:211; THREAT_MODEL.md:18) — and whitepaper (CITADEL_WHITEPAPER.md:99-104) states CNSA 2.0 targets category 5 and that even the 0xA4 pairing "is Citadel's design choice and not a CNSA-specified suite." ML-KEM-768 (category 3) does not meet CNSA 2.0.
- **Mechanism mis-description:** OVERVIEW.md:17-30 diagram: "generate AES-256 key → encrypt → **wrap key with hybrid KEM**." The envelope never wraps a generated AES key; the AES key is **derived** via HKDF from the KEM shared secrets (SPEC.md:61-65; WIRE_SPEC_V2.md §5; README.md:18-19 "derive AES-256 key (HKDF)"). A reader comparing the two diagrams sees two different cryptosystems.
- **Non-bootable sample:** OVERVIEW.md:76-87 compose fragment (`image: citadel:latest`, only `CITADEL_API_KEY_HASH` + `CITADEL_SEED_DEMO`) lacks `CITADEL_MASTER_KEY`, `CITADEL_ENV`, `CITADEL_REPLAY_STORE` — DEPLOYMENT.md:100-109 says the service "will not start without all four." Also no published image exists (QUICKSTART.md:58 "there is no published citadel:v3 image to pull").
- **Vintage:** no mention of suite `0xA4` anywhere in the doc despite being committed 2026-08-06 (post-0.2.0); audit cost "$75K–$150K+ / $20–40K scoped" (OVERVIEW.md:136-141) vs SECURITY_MATURITY.md:159-160 "$20K–$50K typical" — different framing, arguably different scopes, but the two ranges are presented as the same purchase.

### 3.11 MEDIUM — SIDE_CHANNEL_NOTES contradicts code and three other docs on auth comparison
- SCN.md:27-28: "**Constant-time key comparison:** API key hash comparison **uses `==` on byte arrays**. This may be vulnerable to timing attacks on the authentication path."
- Versus README.md:230, DEPLOYMENT.md:74, SECURITY_GUARANTEES.md:89 ("constant-time comparison via `subtle::ConstantTimeEq`") and code `citadel-api/src/main.rs:45` (`use subtle::ConstantTimeEq`), :238 (`stored.ct_eq(provided)`). SCN understates (safe direction) but is factually wrong and was last touched 2026-08-06 — the accuracy pass missed it.

### 3.12 MEDIUM — aes-gcm dependency version stale in both security docs
SECURITY_GUARANTEES.md:126 and THREAT_MODEL.md:165 list "AEAD | AES-256-GCM | ... | aes-gcm **0.10**". Cargo.toml: `aes-gcm = "0.11"` (`citadel-envelope/Cargo.toml:45`). Not cosmetic: `kdf.rs:20-27` documents that the 0.10→0.11 bump *closed a GCM tag-forgery-under-memory-disclosure residual* (polyval `H` zeroization) — the security docs still advertise the vulnerable-generation pin.

### 3.13 MINOR — Rate limiting: one-tier vs three-tier
README.md:234 "Per-IP token bucket" and DEPLOYMENT.md:267-277 (per-IP only, "runs in-memory") vs THREAT_MODEL.md:184 "Three-tier (per-key, per-domain, global)" and SECURITY_MATURITY.md:63 "Rate limiting (3-tier)". Code has three tiers (per-IP, per-key, global — `citadel-api/src/main.rs:340-363`, :1069-1075), so README/DEPLOYMENT *understate*; THREAT_MODEL's tier naming ("per-domain") doesn't match the code's ("per-key... global") either.

### 3.14 MINOR — Quickstart surface drift
- Health output: README.md:52 `{"status":"ok","version":"0.2.0"}` (matches code, main.rs:1504-1505 includes `CARGO_PKG_VERSION`) vs QUICKSTART.md:72 `{"status":"ok"}` (field omitted).
- DEPLOYMENT.md:286 JSON-log example: "starting Citadel API Server **v0.1.0**" — current version 0.2.0.
- Production compose duality: DEPLOYMENT.md:335 tells migrating users "Switch to `docker-compose-production.yml`" (root file: Caddy-based, **no Redis service, no `CITADEL_ENV`, no `CITADEL_MASTER_KEY`, no `CITADEL_REPLAY_STORE`, `CITADEL_SEED_DEMO` defaults to *true*, 8443 published on all interfaces**) while QUICKSTART.md:26,116 and DEPLOYMENT.md:180-185 use `deploy/docker/docker-compose.yml` (full gates, Redis, loopback-only). Two files both titled "Production Docker Compose" with materially different security posture; the root one appears to predate the required-vars gate (DEPLOYMENT.md:102) and likely fails startup.
- Env vars otherwise consistent across README/QUICKSTART/DEPLOYMENT: `CITADEL_API_KEY` = dev-only plaintext (root docker-compose.yml sets `dev-secret`, matching README:55/QUICKSTART:56), `CITADEL_API_KEY_HASH` = production HMAC — the dev/hashed split is told the same way in all three. Port 8443 is consistent repo-wide (commit 3ba4c52 unified it). ✔ genuinely coherent.

### 3.15 MINOR — Small cross-doc variances
- SUPPLY_CHAIN.md:3 "Last reviewed: 2026-07-20" vs its own packet-058 section dated 2026-08-04 (:29).
- RTB.md:154 "replay.db" vs `replay.json` everywhere else.
- Contact fragmentation: security = gmail (SECURITY.md:62), commercial support = outlook (SECURITY.md:203), license contact = commit@reposignal.io (README.md:325); SUPPORT.md says "GitHub Issues", SECURITY.md:202 says "GitHub Discussions".
- THREAT_MODEL.md:27 "328+ passing" vs VALIDATION_MATRIX.md:11 "435 passed" vs SECURITY.md:11 "500 tests... combined" — three snapshots of the same growing suite, only the latter two are mutually consistent (435+44+21=500).
- API_FREEZE.md:3-4 "Version 0.1.0, Date 2026-02-05, FROZEN" — never re-stamped for 0.2.0 even though its own Tier-2 table already logs the 0xA4 additions.
- INTEGRATION_GUIDE.md:11-19 five-crate diagram vs README.md:265-272 seven crates (guide's header note :5-7 already confesses its vintage — model behavior, just incomplete).
- DEPLOYMENT.md:250-257: blockquote inserted mid-markdown-table splits the Configuration Reference table; rows from `CITADEL_API_KEY_HASH` down won't render as a table.
- SUPPORT.md:3-5 empty "## Overview" heading.

### 3.16 Explicit all-clears (checked, found consistent)
- **VERSION ↔ CHANGELOG ↔ Cargo.toml ↔ README curl output:** VERSION `citadel-v3-beta-001`/2026-08-06 = CHANGELOG [0.2.0] — 2026-08-06 = all workspace crates 0.2.0 = README:52 `"version":"0.2.0"` = code `env!("CARGO_PKG_VERSION")`. ✔ All agree. (THREAT_MODEL:3 "citadel-v3-0.2.0" and VALIDATION_MATRIX "citadel-v3-beta-001" are two names for the same release — cosmetic.)
- **INTEGRATION_GUIDE code sample vs API:** `Citadel`, `Aad::for_database`, `Context::for_application`, `seal/open` all exist (`citadel-envelope/src/sdk.rs:39,70,112,134,201`); README endpoint table — all 18 rows exist verbatim in the router (`citadel-api/src/main.rs:3339-3363`; code additionally has sign/verify/assertions/threat-event routes the README table omits — undocumented surplus, not error); README Python/curl samples hit real routes with real field names (`plaintext`/`aad`/`context`/`blob`); `citadel_example.py`, `scripts/smoke-test.sh`, `scripts/test-citadel-ubuntu.sh`, `hash-apikey` bin (citadel-api/Cargo.toml:17), fuzz targets, `gauntlet/receipts/SUMMARY.md` all exist. ✔ 5/5 spot-checks pass.
- **Security-claims trio, audit posture:** README:252-254, SECURITY_GUARANTEES:3+147-150, THREAT_MODEL:94-96, SECURITY_MATURITY:236-242, SECURITY.md:11, OVERVIEW:130, whitepaper status block — "unaudited, no third-party assurance" is stated with identical strength in all seven places. ✔ Remarkably disciplined.
- **Replay trio on multi-instance:** "file store single-node only, Redis for multi-node" identical in SECURITY_GUARANTEES:50-52+99-104, THREAT_MODEL:104-108, RSG:25-34, DEPLOYMENT:194-205. ✔

---

## 4. Staleness pass

| Item | Evidence | Verdict |
|---|---|---|
| **v1-described-as-current prose** | SPEC.md, FORMAT.md, MIGRATION.md untouched since initial commit 2026-07-09 (git); none mention v2, which became the emitted format per WIRE_SPEC_V2.md (dated 2026-07-15, committed 2026-08-06). MIGRATION.md:11 table column "Rust Citadel Envelope v1" presents v1 as *the* Rust protocol. FORMAT.md:1 titled "(v1)". README:221-224 shows the v1 layout as "Wire Format". | v1-era docs post-date v2 without banners — the core of §2.5's fix |
| **References to files that don't exist** | SECURITY_MATURITY.md:43 → `CLAIM_EVIDENCE_MATRIX.md` (absent; described as "controls all wording" — a controlling record readers cannot read). RTB.md:154 → `replay.db` (actual: `replay.json`). RTB.md:38-39,73-74 → `CITADEL_REPLAY_FLUSH_MODE` (no such env var in code). Counter-check: INTEGRATION_GUIDE.md:5-7 handles its own dead reference (`citadel.rs`) correctly by declaring it gone. | 3 dead references, 1 self-healed |
| **Dates vs git history** | WIRE_SPEC.md "2026-01-28", API_FREEZE.md "2026-02-05", RSG footer "2026-05-02", RTB content — all predate the first public commit (2026-07-09); legitimate pre-public vintage, but WIRE_SPEC's "FINAL" + wrong schedule makes its stale date actively misleading. SUPPLY_CHAIN.md:3 review date (2026-07-20) older than content it contains (2026-08-04). SECURITY_MATURITY.md:262-263 has no date at all ("Last Updated: Round 4 Security Audit"). DEPLOYMENT.md:286 sample log v0.1.0. | Vintage-vs-content mismatches concentrated in the replay/maturity cluster |
| **Stale claims the 2026-08-06 accuracy pass missed** | CHANGELOG:9-14 documents a repo-wide accuracy pass (commits d33398e, 7a864d0, 1623033). Escapees found by this audit: SECURITY_MATURITY.md:40-43 (FIPS "review-in-process"), SIDE_CHANNEL_NOTES.md:27-28 ("=="), SECURITY_GUARANTEES.md:126 + THREAT_MODEL.md:165 (aes-gcm 0.10), DEPLOYMENT.md:341-366 (auth-scopes-as-future), README.md:258 + OVERVIEW.md:112 (26/7 compliance count), RTB env vars, WIRE_SPEC.md in its entirety. | The pass was real but incomplete; this list is its punch-list |

---

## 5. Supersede-banner recommendations (complete list)

Per topic, one canon; every overlapping doc gets a one-line banner. Wire-format banners (5 docs) are fully specified in §2.5 — not repeated here.

| # | Doc | Action / exact banner text | Canon for topic |
|---|---|---|---|
| 1–5 | WIRE_SPEC.md, SPEC.md, FORMAT.md, WIRE_SPEC_V2.md, README (2 lines) | See §2.5 verbatim | **Wire format → WIRE_SPEC_V2.md** (current); SPEC.md (legacy v1) |
| 6 | REPLAY_TRUST_BOUNDARIES.md | Top: "**Canonical for replay durability semantics.** Config names herein are historical: the API reads `CITADEL_REPLAY_STORE` (not `CITADEL_REPLAY_BACKEND`), and no `CITADEL_REPLAY_FLUSH_MODE` switch exists — batched flushing (5 s / 100 ops) is the only file-store mode; use `force_flush()` on shutdown. The Redis backend described under 'Future' is shipped (`--features redis-backend`)." | **Replay durability → REPLAY_TRUST_BOUNDARIES.md** (after env-var fix) |
| 7 | REPLAY_STORE_GUARANTEES.md | Top: "**Operational per-backend guarantees.** For durability boundaries and crash windows, [REPLAY_TRUST_BOUNDARIES.md](REPLAY_TRUST_BOUNDARIES.md) is canonical. Where the two disagree, RTB governs." (Also fix the self-referential sentence at :3 and the starts-fresh/never-recreates conflict at :50-57.) | ↑ |
| 8 | SECURITY_GUARANTEES.md (replay section, :47-49) | Inline: "File backend durability is **batched** — see [REPLAY_TRUST_BOUNDARIES.md](REPLAY_TRUST_BOUNDARIES.md) for the crash window; 'survives restart' assumes a flushed claim." | ↑ |
| 9 | DEPLOYMENT.md (:202 and :341-383) | Inline at :202: same batched-flush pointer as #8. Banner over "What's Next (Tier 2)" + "API Key Management (Operational Limitations)": "**Historical.** Scoped multi-key auth shipped in 0.2.0 and is enforced per route (`required_scope`); see README §API Key Scopes. Retained for the untested-rotation caveats only." | **Quickstart/prod ops → QUICKSTART.md (paths) + DEPLOYMENT.md (reference)**, after de-staling |
| 10 | docker-compose-production.yml (root) | Header comment: "**DEPRECATED — use `deploy/docker/docker-compose.yml`** (this file predates the required-vars startup gate: no MASTER_KEY / ENV / REPLAY_STORE, no Redis, demo seed on)." Update DEPLOYMENT.md:335 to point at `deploy/docker/docker-compose.yml`. | **Production compose → deploy/docker/docker-compose.yml** |
| 11 | SIDE_CHANNEL_NOTES.md | Top: "**Superseded by [TIMING.md](TIMING.md)**, the full timing validation record. Known-stale here: API-key comparison now uses `subtle::ConstantTimeEq` (citadel-api/src/main.rs), not `==`." | **Timing/side-channel → TIMING.md** |
| 12 | SECURITY_MATURITY.md (:40-43) | Replace the FIPS bullet with the wording every other doc converged on: "Requiring FIPS 140-2/3 validation (the optional `fips` build routes envelope operations through the CMVP-validated AWS-LC-FIPS 3.1.0 module, certs #5298/#5314 — Citadel itself remains unvalidated; controlling record: [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) §FIPS module advisory exceptions)." Kills the phantom `CLAIM_EVIDENCE_MATRIX.md` reference. | **FIPS wording → SUPPLY_CHAIN.md §AWS-LC** (already named controlling by THREAT_MODEL:131) |
| 13 | SECURITY_MATURITY.md (top) | "**Canonical for deployment-readiness posture.** Evidence per claim: [VALIDATION_MATRIX.md](VALIDATION_MATRIX.md). Attacker model: [THREAT_MODEL.md](THREAT_MODEL.md)." + add a real date to :262-263. | **Security posture → SECURITY_MATURITY.md** (posture), VALIDATION_MATRIX.md (evidence) |
| 14 | CITADEL_OVERVIEW.md | Top: "Commercial positioning summary — technical claims herein are simplified; [README.md](README.md) and [SECURITY_MATURITY.md](SECURITY_MATURITY.md) govern where they differ." Plus three spot-fixes: CNSA row → attach to `0xA4`/ML-KEM-1024 (:118); diagram → "derive AES-256 key (HKDF)" not "wrap key" (:22-23); compose sample → all four required vars (:76-87). | README governs |
| 15 | MIGRATION.md | Top: "**Historical (Python→Rust, v1 era).** Describes the v1 envelope; the current format is v2 ([WIRE_SPEC_V2.md](WIRE_SPEC_V2.md)). Retained for prototype-data migration only." | — |
| 16 | Mechanical one-liners (no banner needed) | README.md:258 + CITADEL_OVERVIEW.md:112 → "27 satisfied, 6 partial, 1 gap"; SECURITY_GUARANTEES.md:126 + THREAT_MODEL.md:165 → aes-gcm 0.11; README.md:215 + THREAT_MODEL.md:119 → adopt whitepaper §5 FIPS-scope sentence (0xA3 KEM arm stays pure Rust); QUICKSTART.md:72 → add `"version"` to health output; DEPLOYMENT.md:286 → v0.2.0; DEPLOYMENT.md:250-257 → un-break the config table; SUPPLY_CHAIN.md:3 → bump review date. | — |

---

*Audit method: full read of all 33 docs; every wire/config/API claim verified against `citadel-envelope/src/{wire,wire_v2,kdf,kem,backend}.rs`, `citadel-api/src/main.rs`, `citadel-keystore/src/replay_store.rs`, `citadel-cli/src/commands/replay.rs`, three compose files, `env.example`, Cargo manifests, and git history (initial commit `cff9649` 2026-07-09 → HEAD `31deefe`).*
# §5 ICM Analysis — citadel-v3 (Restructure mode, analysis output)

Method: ICM Architect skill (Interpretable Context Methodology, Van Clief & McDermott, arXiv:2603.16021), Restructure mode, run against the fork clone at commit `31deefe`. Analysis only — no file in the repo was moved. Execution happens later as fork Phase C so the maintainer can see the result instead of imagining it.

## 1. Inventory summary (Slice 0)

- 7 cargo workspace crates (~43.6k LOC Rust): citadel-core, -envelope (largest, 2.5 MB with vendored vectors), -keystore, -api, -cli, -ffi, -signer. Cargo owns this layout; no restructure proposal touches `src/` trees.
- ~42 root-level files that are not crate folders: 33 markdown docs, 7 `citadel_*` test harnesses (.ps1/.py) + `citadel_example.py`, 3 ops scripts (`Backup-/Sign-/Validate-Citadel.ps1`), 3 dashboards, 2 test-vector JSONs, build/deploy config.
- Structured evidence directories: `gauntlet/` (tiered validation: tier1_vectors … tier12_combiner_proof, plus `receipts/`), `fuzz/` (cargo-fuzz workspace), `tests/` (workspace integration test), `scripts/` (canonical judge + helpers), `supply-chain/` (cargo-vet), `whitepaper/`, `deploy/`, `.github/workflows/` (5 workflows incl. ClusterFuzzLite daily fuzzing with external corpus repo).

## 2. Form determination (from evidence, not preference)

**The repo already contains two latent ICM structures the maintainer invented independently:**

1. `gauntlet/` is a numbered **pipeline**: `tier1_vectors` … `tier12_combiner_proof` with a `receipts/` product folder. Sequencing by naming, evidence as artifacts — this is ICM-shaped already.
2. `VALIDATION_MATRIX.md` is a **claims catalog**: one row per claim, pointing at evidence. That is an `objects/_index.md` in all but name.

**The failure is not missing structure — it is missing declared authority.** 33 docs sit flat at root with no index stating which doc governs which topic; four documents describe the wire format; three dashboards sit at root with no marker for which one the API actually serves (`citadel-api/src/main.rs` embeds `dashboard.html`; the other two have zero referrers in the tree).

**Form call: System map (lightweight variant) composed over the existing latent pipeline.** Per the skill's own guardrail ("if the tree is small enough that one CONTEXT.md plus an index answers 'what is X' and 'what else moves', stop there"), a full `map/objects/processes/effects` scaffold is over-structure for a 7-crate workspace with a strong README. The right-sized deliverable is:

- `docs/INDEX.md` — the authority map: one row per topic (wire format, replay, timing, compliance, deployment, validation), naming the ONE canonical doc and listing the superseded/overview docs under it.
- A short crate map with change-impact ("if you change citadel-envelope's header encoder, these move: WIRE_SPEC_V2, test_vectors_real.json generator, fuzz targets X/Y, gauntlet tier1") — one file, not a card library.
- Supersede banners on the objectively superseded docs.

## 3. Classification table (catalog / contract / factory / product / dead)

Universe labels per system-map.md: live / leftover / ghost.

| File | Role | Universe | Evidence |
|---|---|---|---|
| README.md | Catalog (entry) | live | Good entry file; carries one internal canon conflict (calls SPEC.md "Authoritative wire specification" in Project Structure while its own doc table says SPEC=v1, WIRE_SPEC_V2=current) |
| VALIDATION_MATRIX.md | Catalog (claims index) | live | Cites harnesses + gauntlet; the repo's de-facto objects index |
| CHANGELOG.md, VERSION | Catalog | live | — |
| API_FREEZE.md | Contract | live | Frozen API promise; §0 checks it against routes |
| WIRE_SPEC_V2.md | Contract | live | Current envelope header spec |
| SPEC.md | Contract | leftover (v1) | README table says v1; needs banner + canon declaration |
| WIRE_SPEC.md | Contract | leftover (v1, formal) | References test_vectors.json (v1 vectors) |
| FORMAT.md | Contract (overview) | live-ish | 39-line overview; should point at canon, not restate |
| THREAT_MODEL, SECURITY_GUARANTEES, SECURITY_MATURITY, SIDE_CHANNEL_NOTES, REPLAY_STORE_GUARANTEES, REPLAY_TRUST_BOUNDARIES, COMPLIANCE_MATRIX, SUPPLY_CHAIN | Contract | live | Security-posture doc cluster (8 docs, one topic family) |
| TIMING.md | Product (evidence record) | live | dudect results record — a receipt, not a contract |
| QUICKSTART, DEPLOYMENT, INTEGRATION_GUIDE | Contract | live | Ops/user docs |
| MIGRATION.md | Contract | leftover | Python-prototype→Rust migration; historical once migration done |
| PROVIDER_DECISION_LOG, PROVIDER_BAKEOFF_2026 | Factory (decision records) | live (append-only) | Decision history |
| CITADEL_OVERVIEW.md | Factory (commercial) | live | Marketing positioning; §4 checks it against README honesty |
| SECURITY.md, SUPPORT, CONTRIBUTING, CODE_OF_CONDUCT, COMMERCIAL_LICENSE, LICENSE family, NOTICE, COPYING, AGPL-3.0.txt | Factory (governance) | live | GitHub-convention files; stay at root |
| Cargo.toml/.lock, deny.toml, rustfmt.toml, Dockerfile, Dockerfile.fips, docker-compose.yml, docker-compose-production.yml, Caddyfile, env.example | Factory (build/deploy) | live | — |
| dashboard.html (root) | Product | **leftover (stale copy)** | §1 correction: the API serves `citadel-api/src/dashboard.html` via include_str! (main.rs:2631); the root file is an older snapshot (94 diff lines behind — no error surfacing, no domain-scoped key creation) |
| citadel-dashboard.html | Product | **dead candidate** | Zero referrers; CDN-React simulation, zero API calls |
| citadel-dashboard.jsx | Product | **dead candidate** | Zero referrers; same simulation as importable JSX |
| test_vectors_real.json | Product (generated) | live | Generated by `examples/generate_vectors.rs` |
| test_vectors.json | Product | **leftover (v1)** | Referenced only by WIRE_SPEC.md (v1 doc) |
| citadel_abuse_harness.ps1, citadel_full_validation.ps1, citadel_multiprocess_replay_harness.ps1 | Factory (validation tools) | live | Cited by VALIDATION_MATRIX.md |
| citadel_long_run_load.ps1, citadel_multiprocess_replay_harness.ps1, citadel_abuse_harness.ps1 | Factory (validation tools) | **live-pending** | They are the evidence tools for VALIDATION_MATRIX's four ⏳ PENDING rows (long-run load, multi-process replay ×2, abuse storm) — promised gates not yet run, NOT residue. Their fate is a decision question ("run them and record receipts" vs "de-scope the pending rows"), never silent archive. |
| citadel_api_security_test.py, citadel_crash_harness.ps1 | Factory (validation tools) | **ghost candidates** | Zero doc/matrix referrers found (pending §1 deep referrer check) |
| citadel_cross_verify.py | Factory (validation tool) | live | Referenced from citadel-envelope/tests/primitive_kat.rs |
| citadel_example.py | Contract (doc example) | live | Cited by README + INTEGRATION_GUIDE |
| Backup-Citadel.ps1, Sign-Citadel.ps1, Validate-Citadel.ps1 | Factory (ops tools) | ghost candidates | Zero referrers; Windows ops era |
| gauntlet/ | Factory pipeline + Product receipts | live | Tiered; receipts/ carries run products |
| fuzz/, tests/, scripts/, examples/, supply-chain/, deploy/ | Factory | live | scripts/test-citadel-ubuntu.sh = declared canonical judge |
| whitepaper/ | Contract (design record) | live | — |

## 4. Walk test (honest transcript, cold agent)

1. **"Where am I?"** — Open README.md. Answered in one read: purpose, status (beta/unaudited), quickstart, structure, doc table. **PASS.** Entry ≈3.5k tokens — healthy.
2. **"How do I build and test?"** — README From Source + judge script command. **PASS on paper** (§2 verifies empirically; note the judge defaults to `--offline`, a clean-clone trap).
3. **"What is the current wire format, authoritatively?"** — README points two ways in one file (Project Structure: "SPEC.md — Authoritative wire specification"; doc table: SPEC=v1, WIRE_SPEC_V2=current). Four docs describe wire bytes (SPEC, WIRE_SPEC, WIRE_SPEC_V2, FORMAT) plus README's own diagram. No doc declares itself canon over the others. **FAIL — by definition** (the question has no authoritative answer from files alone).
4. **"How do I validate the whole system?"** — Five entry points: scripts/test-citadel-ubuntu.sh (README: "canonical judge"), scripts/run-tests.sh, citadel_full_validation.ps1 (VALIDATION_MATRIX), gauntlet/run.sh, CI workflows. No declared hierarchy among them. **FAIL.**
5. **"Which dashboard is the product?"** — Three dashboards at root, none labeled; the answer requires reading `citadel-api/src/main.rs`. **FAIL from files alone.**
6. **"Is claim X validated?"** — VALIDATION_MATRIX exists and points at evidence. **PASS structurally** (§0 verifies row accuracy).

Verdict: orientation and build walk PASS; authority walks FAIL on wire canon, validation hierarchy, and dashboard identity. The fix is an authority index + banners + quarantine of the zero-referrer files — not a deep restructure.

## 5. Migration map (proposal — executed on fork Phase C; upstream adoption is a DECISION_QUESTIONS item)

Reference-integrity constraints found before proposing (skill step 4): VALIDATION_MATRIX.md cites harness paths by name; WIRE_SPEC.md cites test_vectors.json; citadel-envelope/tests/primitive_kat.rs mentions citadel_cross_verify.py; README's doc table links every root doc; GitHub inbound URLs to root docs break on move (external referrers = owner question). Every move below updates its referrers in the same commit.

| Old path | New path | Role | Referrers to update |
|---|---|---|---|
| (new) | docs/INDEX.md | authority map: canon per topic | README doc table gains one pointer row |
| SPEC.md | docs/spec/SPEC.md + supersede banner ("v1 record; current format: WIRE_SPEC_V2.md") | contract/leftover | README ×2, FORMAT.md |
| WIRE_SPEC.md | docs/spec/WIRE_SPEC.md + same banner | contract/leftover | README, test_vectors.json note |
| WIRE_SPEC_V2.md | docs/spec/WIRE_SPEC_V2.md, declared CANON | contract | README |
| FORMAT.md | docs/spec/FORMAT.md (overview; pointer to canon) | contract | README |
| THREAT_MODEL, SECURITY_GUARANTEES, SECURITY_MATURITY, SIDE_CHANNEL_NOTES, TIMING, REPLAY_*, COMPLIANCE_MATRIX, SUPPLY_CHAIN | docs/security/ | contracts + records | README table, cross-refs among the 8 |
| DEPLOYMENT, INTEGRATION_GUIDE, MIGRATION (+historical banner), PROVIDER_* | docs/ops/ + docs/history/ | contracts/records | README table |
| citadel_abuse_harness.ps1, citadel_full_validation.ps1, citadel_multiprocess_replay_harness.ps1, citadel_cross_verify.py, citadel_api_security_test.py, citadel_long_run_load.ps1, citadel_crash_harness.ps1 | tools/validation/ | factory | VALIDATION_MATRIX paths, primitive_kat.rs comment |
| Backup-/Sign-/Validate-Citadel.ps1 | tools/ops/ | factory | none found |
| dashboard.html (root, stale), citadel-dashboard.html, citadel-dashboard.jsx | attic/ (quarantine, listed in attic/README.md — moved, never silently deleted) | leftover + dead | none found (§1 confirmed: no doc references any dashboard file by name) |
| citadel-keystore/Validate-Citadel.ps1, citadel-keystore/src/Validate-Citadel.ps1, citadel-keystore/Cargo.workspace.toml, root tests/hybrid_kat.rs, root examples/ (unattached to any crate) | attic/ | dead (§1: never compiled / stray copies, one behaviorally wrong) | none |
| test_vectors.json | attic/ or docs/spec/v1-vectors/ (owner ruling; it is v1 evidence) | leftover | WIRE_SPEC.md |
| Stays at root | README, QUICKSTART, CHANGELOG, VERSION, SECURITY.md, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, all license files, VALIDATION_MATRIX (centerpiece stays visible), API_FREEZE (frozen promise stays visible), all build/deploy config | — | — |

**Two-lane recommendation for upstream** (goes into DECISION_QUESTIONS): Lane 1 (minimal, zero URL breakage): banners + docs/INDEX.md only, no file moves. Lane 2 (full, what Phase C demonstrates): the map above. Our lean: Lane 2 on a repo this young is cheap and the fork shows the exact result; but inbound-link stability is the owner's call, not ours.


---

# §6 Preservation ledger

The numbered capability inventory lives in its own file: [PRESERVATION_LEDGER.md](PRESERVATION_LEDGER.md). Every phase branch carries a LEDGER_CHECK_*.md recording its walk against it.
