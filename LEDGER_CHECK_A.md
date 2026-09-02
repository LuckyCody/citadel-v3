# Ledger Check — Audit Phase A (doc-truth only)

**Branch:** `audit/phase-a-doc-truth` (base: `master` @ 31deefe)
**Scope:** documentation-truth fixes only — make docs match code reality, add supersede banners on the objectively superseded. Zero behavior changes, zero code changes (single exception: a comment-only doc-comment addition in `citadel-cli/src/main.rs`).

## Capability walk

Capabilities A1-A35/B/C/D/E/F/G/H: untouched (no code or config-behavior changes — verify: `git diff master --stat` lists only docs + comment block + a header comment in a deprecated compose file). Docs-as-promises I1-I7: I1 API_FREEZE strengthened (scope clarified, no guarantee weakened); I2-I7 intact. No capability removed or changed.

## Change table

| File | What changed | Why (audit item) |
|---|---|---|
| WIRE_SPEC.md | Superseded/historical banner; Status FINAL → SUPERSEDED — HISTORICAL | S4 §2.5 item 1 (key schedule never matched shipped code) |
| SPEC.md | Normative-for-legacy-v1 status banner | S4 §2.5 item 2 |
| FORMAT.md | Retitled "(non-normative)"; byte-level-authority banner | S4 §2.5 item 3 |
| WIRE_SPEC_V2.md | Canonical-wire-spec line under Status | S4 §2.5 item 4 (0xA4 length table skipped — ruling-gated) |
| README.md | Project Structure comment de-crowned SPEC.md; WIRE_SPEC.md doc row marked historical; endpoint table completed (+9 routes, real scopes); openapi.yaml pointer + doc row; citadel-core blurb → StateEnforcer; compliance count → 27/6/1 (recounted); FIPS scope → whitepaper §5 wording | S4 §2.5 item 5, §5 item 16; S1 §1/§2 |
| REPLAY_TRUST_BOUNDARIES.md | Canon-for-durability banner (real env var, no flush-mode switch, Redis shipped); replay.db → replay.json | S4 §5 item 6, §3.15 |
| REPLAY_STORE_GUARANTEES.md | RTB-governs banner; self-referential update sentence fixed; corruption table states fail-closed code truth (`file_store_truncated_json_returns_err` / `file_store_invalid_json_returns_err`, P393); memory backend = development-mode default | S4 §5 item 7, §3.6 |
| SECURITY_GUARANTEES.md | Batched-flush pointer on file-backend guarantee; aes-gcm 0.10 → 0.11 | S4 §5 item 8, §3.12 |
| DEPLOYMENT.md | Batched-flush pointer (:202); Historical banner over "What's Next (Tier 2)" + "API Key Management (Operational Limitations)"; log example v0.1.0 → v0.2.0; config table un-broken (blockquote moved below table); migration step → deploy/docker/docker-compose.yml | S4 §5 item 9, §3.4/§3.7/§3.14 |
| docker-compose-production.yml | DEPRECATED header comment (comment only, file predates required-vars gate) | S4 §5 item 10 |
| QUICKSTART.md | Health output example gains `version` field | S4 §5 item 16, §3.14 |
| SIDE_CHANNEL_NOTES.md | Superseded-by-TIMING banner; "==" claim corrected to `subtle::ConstantTimeEq` | S4 §5 item 11, §3.11 |
| SECURITY_MATURITY.md | Posture-canon banner; FIPS bullet rewritten (CMVP-validated 3.1.0 wording, phantom CLAIM_EVIDENCE_MATRIX.md ref removed, controlling record → SUPPLY_CHAIN.md); Last Updated dated 2026-08-06 | S4 §5 items 12-13, §3.3 |
| THREAT_MODEL.md | aes-gcm 0.10 → 0.11; FIPS scope adopts whitepaper §5 sentence (0xA3 KEM arm pure Rust on both builds); "328+" → pointer to VALIDATION_MATRIX current counts (435/44/21) | S4 §5 item 16, §3.9/§3.12/§3.15 |
| SUPPLY_CHAIN.md | 2026-08-04 addendum noted beside 2026-07-20 review date (no new review date fabricated) | S4 §5 item 16, §3.15 |
| CITADEL_OVERVIEW.md | README/SECURITY_MATURITY-govern banner; CNSA row → 0xA4/ML-KEM-1024; diagram → HKDF derivation (not key wrap); compose sample carries the four required vars; compliance count → 27/6/1 | S4 §5 item 14, §3.8/§3.10 |
| MIGRATION.md | Historical (Python→Rust, v1 era) banner | S4 §5 item 15 |
| SUPPORT.md | Empty "## Overview" filled with one sentence | S4 §5 item 16, §3.15 |
| API_FREEZE.md | Retitled "SDK / FFI Stability Contract"; Updated line (2026-08-06, 0.2.0; HTTP REST API not covered) | S1 §2 / worklist G |
| INTEGRATION_GUIDE.md | Crate diagram → 7 real workspace crates (self-flagging header note kept) | S4 §3.15; S1 §1; worklist G |
| citadel-cli/src/main.rs | Doc-comment gains missing `key rewrap` line (comment-only) | S1 §3; worklist G |

## Second wave (same phase-A scope)

| File | What changed | Why (audit item) |
|---|---|---|
| VALIDATION_MATRIX.md | Evidence names re-pointed to tests that exist: primitive-KAT globs → real fn names in tests/primitive_kat.rs; `p006_*`/`p007_*` → `aes256gcm_nist_*`; `p012_wrong_key_*` → `wrong_key_rejected` (nist_acvp_kat.rs) + `wrong_key_fails` (roundtrip.rs); corruption rows → `file_store_*_returns_err` (fail-closed behavior stated); master-key gate row now cites hostile_config_test.sh's "No CITADEL_MASTER_KEY" refuses-startup check instead of the unrelated `it_health_no_auth_required`. No PASS/PENDING status changed. | S0 rows 28-31 |
| TIMING.md | Repro procedure de-staled: PQClean bench filters → the real `rustcrypto_*` benches in benches/mlkem_standalone.rs; policy row `bench_pqclean_mlkem_*` → `bench_rustcrypto_mlkem_*`/`bench_libcrux_mlkem_*`; historical results tables untouched, heading labeled "(historical record)" | S0 row 12 |
| CHANGELOG.md | Note under [Unreleased]/Changed: public git history begins 2026-07-09 as a squashed import; earlier document dates refer to the private history | S0 reproducibility caveat |
| Cargo.lock | `cargo update -p chacha20` 0.10.1 → 0.10.2 (0.10.1 is yanked) — dependency version state: capability-neutral patch bump restoring the repo's own deny policy to green | wave-2 item 4 |
| README.md | citadel_example.py note: API key read from `CITADEL_KEY` env var; /health sample updated to the real three-field shape (`crypto_backend` + `status` + `version`) | wave-2 items 5-6 |
| INTEGRATION_GUIDE.md | Same `CITADEL_KEY` env-var note on the example reference | wave-2 item 5 |
| QUICKSTART.md | /health sample extended to the real three-field shape, consistent with README | wave-2 item 6 |
