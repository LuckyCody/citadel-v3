# LEDGER_CHECK_C — Phase C (structure migration) capability check

**Scope.** Phase C is moves only (branch `audit/phase-c-icm`, base
`audit/phase-b-consolidation`), applying Q4.1-as-recommended (Lane 2). Zero content
changes except: (a) link/path strings updated to the new locations in the same commit
as each move, (b) the new `docs/INDEX.md` authority map, (c) the new
`tools/validation/README.md` tool table. Every move is `git mv` — trivially revertable.

## Affected ledger areas

### A/B/C/D/E/F — Core capabilities
- Untouched. No crate source moved; the only `.rs` edits are comment-only path updates
  (`citadel-envelope/tests/primitive_kat.rs` → `tools/validation/citadel_cross_verify.py`
  mentions; `citadel-envelope/benches/timing_sidechannel.rs` and
  `gauntlet/tier8_ct/ctgrind_harness/src/main.rs` → `docs/security/TIMING.md` mentions;
  `citadel-envelope/src/kem.rs` → `docs/history/PROVIDER_BAKEOFF_2026.md` mention).
- Evidence: after all moves, `cargo build --workspace --locked` green;
  `cargo test --workspace --locked` green (all suites `0 failed` except the known
  citadel-api flake `integration::exploit_scoped_admin_can_view_multi_domain_api_key_via_partial_overlap_listing`,
  which failed once under full-parallel load and passed on immediate isolated rerun —
  same behavior recorded in LEDGER_CHECK_B). `cargo fmt --all -- --check` clean.

### G — Dashboard
- Untouched. `citadel-api/` unchanged apart from nothing at all — no file under
  `citadel-api/` was modified in Phase C.

### H-series — Deployment / validation harness capabilities
- **Judge script path unchanged:** `scripts/test-citadel-ubuntu.sh` stays in place and
  references no moved file (grep-verified: no hits for any moved doc or tool name).
- **openapi.yaml path unchanged:** `scripts/security/openapi.yaml` stays in place
  because the CI Schemathesis job invokes it by that exact path
  (`.github/workflows/ci.yml:198: schemathesis run scripts/security/openapi.yaml`) —
  CI-verified reason, deliberate non-move.
- **Harness capabilities intact at new `tools/` paths** (H5–H12 mapping old→new):
  - H5 full E2E validation: `citadel_full_validation.ps1` → `tools/validation/citadel_full_validation.ps1`
  - H6 abuse storm: `citadel_abuse_harness.ps1` → `tools/validation/citadel_abuse_harness.ps1`
  - H7 multi-process replay: `citadel_multiprocess_replay_harness.ps1` → `tools/validation/citadel_multiprocess_replay_harness.ps1`
  - H8 long-run load: `citadel_long_run_load.ps1` → `tools/validation/citadel_long_run_load.ps1`
  - H9 crash durability: `citadel_crash_harness.ps1` → `tools/validation/citadel_crash_harness.ps1`
  - H10 HTTP black-box security tests: `citadel_api_security_test.py` → `tools/validation/citadel_api_security_test.py`
  - H11 independent Python cross-verification: `citadel_cross_verify.py` → `tools/validation/citadel_cross_verify.py`
  - H12 operational smoke check: `Validate-Citadel.ps1` → `tools/ops/Validate-Citadel.ps1`
  - All harnesses resolve `target\debug\...` binaries relative to the **current working
    directory** (repo root), not the script directory (`citadel_full_validation.ps1`
    takes `$rootDir = (Get-Location).Path`), so the moves change no runtime behavior
    when invoked from the repo root as before. `citadel_example.py` stays at root
    (README-linked documentation example).

### I-series — Promise documents
- All promise docs intact, content unchanged except link paths: THREAT_MODEL,
  SECURITY_GUARANTEES, SECURITY_MATURITY, SIDE_CHANNEL_NOTES, TIMING,
  REPLAY_STORE_GUARANTEES, REPLAY_TRUST_BOUNDARIES, COMPLIANCE_MATRIX, SUPPLY_CHAIN
  now under `docs/security/`; specs under `docs/spec/`; DEPLOYMENT,
  INTEGRATION_GUIDE, CITADEL_OVERVIEW under `docs/ops/`; MIGRATION and the two
  PROVIDER_* records under `docs/history/`.
- **I4 intact:** `VALIDATION_MATRIX.md` stays at root; its evidence-tool citations
  updated to the `tools/validation/` paths in the same commit as the tool moves.
  Frozen dated gauntlet receipts (`gauntlet/receipts/tier2b_supplychain.txt`,
  `gauntlet/receipts/tier8_ct.txt`) deliberately keep their original bare doc-name
  mentions as historical evidence records; the live index `gauntlet/receipts/SUMMARY.md`
  was updated.

## Moves (all `git mv`, complete)

| old path | new path | commit |
|---|---|---|
| `SPEC.md` | `docs/spec/SPEC.md` | 1 |
| `WIRE_SPEC.md` | `docs/spec/WIRE_SPEC.md` | 1 |
| `WIRE_SPEC_V2.md` | `docs/spec/WIRE_SPEC_V2.md` | 1 |
| `FORMAT.md` | `docs/spec/FORMAT.md` | 1 |
| `THREAT_MODEL.md` | `docs/security/THREAT_MODEL.md` | 2 |
| `SECURITY_GUARANTEES.md` | `docs/security/SECURITY_GUARANTEES.md` | 2 |
| `SECURITY_MATURITY.md` | `docs/security/SECURITY_MATURITY.md` | 2 |
| `SIDE_CHANNEL_NOTES.md` | `docs/security/SIDE_CHANNEL_NOTES.md` | 2 |
| `TIMING.md` | `docs/security/TIMING.md` | 2 |
| `REPLAY_STORE_GUARANTEES.md` | `docs/security/REPLAY_STORE_GUARANTEES.md` | 2 |
| `REPLAY_TRUST_BOUNDARIES.md` | `docs/security/REPLAY_TRUST_BOUNDARIES.md` | 2 |
| `COMPLIANCE_MATRIX.md` | `docs/security/COMPLIANCE_MATRIX.md` | 2 |
| `SUPPLY_CHAIN.md` | `docs/security/SUPPLY_CHAIN.md` | 2 |
| `DEPLOYMENT.md` | `docs/ops/DEPLOYMENT.md` | 3 |
| `INTEGRATION_GUIDE.md` | `docs/ops/INTEGRATION_GUIDE.md` | 3 |
| `CITADEL_OVERVIEW.md` | `docs/ops/CITADEL_OVERVIEW.md` | 3 |
| `MIGRATION.md` | `docs/history/MIGRATION.md` | 3 |
| `PROVIDER_DECISION_LOG.md` | `docs/history/PROVIDER_DECISION_LOG.md` | 3 |
| `PROVIDER_BAKEOFF_2026.md` | `docs/history/PROVIDER_BAKEOFF_2026.md` | 3 |
| `citadel_full_validation.ps1` | `tools/validation/citadel_full_validation.ps1` | 4 |
| `citadel_abuse_harness.ps1` | `tools/validation/citadel_abuse_harness.ps1` | 4 |
| `citadel_multiprocess_replay_harness.ps1` | `tools/validation/citadel_multiprocess_replay_harness.ps1` | 4 |
| `citadel_long_run_load.ps1` | `tools/validation/citadel_long_run_load.ps1` | 4 |
| `citadel_crash_harness.ps1` | `tools/validation/citadel_crash_harness.ps1` | 4 |
| `citadel_api_security_test.py` | `tools/validation/citadel_api_security_test.py` | 4 |
| `citadel_cross_verify.py` | `tools/validation/citadel_cross_verify.py` | 4 |
| `Validate-Citadel.ps1` | `tools/ops/Validate-Citadel.ps1` | 4 |

New files: `tools/validation/README.md` (commit 4), `docs/INDEX.md` (commit 5).
Deliberately left in place: everything else at root (README, QUICKSTART, CHANGELOG,
VERSION, VALIDATION_MATRIX, API_FREEZE, SECURITY.md, licenses, configs,
`citadel_example.py`, `test_vectors.json`), `scripts/`, `gauntlet/`, `fuzz/`, `tests/`,
`examples/generate_vectors.rs` (Phase D relocates it), `deploy/`, `supply-chain/`,
`whitepaper/`, `.github/`.

## Statement

Iron rule held: every move updated its referrers in the same commit. Final
tree-wide grep for each old root filename hits only correct new paths, in-dir
relative links that resolve, historical records (attic/README.md, LEDGER_CHECK_*,
CHANGELOG.md, frozen gauntlet receipts), and self-references inside the moved docs'
own banners. All links from root docs into `docs/`/`tools/` (27) verified to resolve
on disk; every markdown link inside `docs/` and `tools/` verified to resolve.
