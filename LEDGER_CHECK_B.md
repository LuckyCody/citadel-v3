# LEDGER_CHECK_B — Phase B (duplication consolidation) capability check

**Scope.** Phase B quarantines duplicate, stale, and dead files into `attic/` per the
DECISION_QUESTIONS rulings Q3.1–Q3.10 (branch `audit/phase-b-consolidation`, base
`audit/phase-a-doc-truth`). No behavior change intended; two documentation additions
to DEPLOYMENT.md preserve patterns that lived only in quarantined files.

## Affected ledger areas

### G — Dashboard
- The **served** dashboard is `citadel-api/src/dashboard.html`, embedded via
  `include_str!` in `citadel-api/src/main.rs`. Untouched:
  `git diff audit/phase-a-doc-truth -- citadel-api/` is empty, and
  `grep -c include_str citadel-api/src/main.rs` = **1**, unchanged from base.
- Quarantined: root `dashboard.html` (stale snapshot, 94 diff lines behind the served
  file) and `citadel-dashboard.html` / `citadel-dashboard.jsx` (CDN-React simulations
  on hardcoded data, zero API calls, zero referrers). Q3.1.

### H1–H4 — Compose / deployment
- Dev compose `docker-compose.yml` (root) and the entire `deploy/` tree are intact
  (empty diff vs base).
- Production compose capability is now exactly **`deploy/docker/docker-compose.yml`**
  plus the two new DEPLOYMENT.md sections:
  - "### TLS termination with Caddy (optional)" — carries the caddy service block and
    full Caddyfile example out of the deprecated root compose (Q3.3);
  - "### Volume-level backup" — docker-volume tar snapshot for the `citadel_data`
    volume declared by the deploy compose (Q3.5).
- Quarantined: `docker-compose-production.yml` (DEPRECATED since Phase A: predates the
  required-vars startup gate, no Redis, demo seed on) and `Caddyfile` (referenced only
  by that deprecated compose). Q3.3.

### H12 + B12–B14 — Backup capability
- `citadel backup create` (CLI) remains the primary, encrypted backup mechanism —
  citadel-cli untouched, full workspace test suite green (see below).
- `Backup-Citadel.ps1` quarantined; its volume-snapshot role is preserved as a
  documented one-liner in DEPLOYMENT.md "### Volume-level backup". Q3.5.

### A/B/C/D/E/F — Core capabilities
- Untouched. Code moves were dead-only:
  - `tests/hybrid_kat.rs` imports modules that no longer exist and, with the root
    `Cargo.toml` being a **virtual workspace** (no `[package]`), was attached to no
    crate; same for `examples/timing_analysis.rs`. Q3.8.
    (`examples/generate_vectors.rs` deliberately left in place — Phase D relocates it.)
  - `citadel-envelope/src/cli.rs` has no `mod cli` declaration anywhere and no Cargo
    bin target pointing at it (bins auto-compile from `src/bin/` only). Q3.9.
- Evidence: after all moves, `cargo build --workspace --locked` and
  `cargo test --workspace --locked` are **green** (all suites `0 failed`; one
  citadel-api unit test flaked once under full-parallel load and passed on immediate
  rerun both in isolation, 77/77, and in the full workspace run).
  `cargo fmt --all -- --check` clean.

## Moves (all `git mv`, indexed in `attic/README.md`)

| attic file | original path | ruling |
|---|---|---|
| `attic/dashboard.html` | `dashboard.html` | Q3.1 |
| `attic/citadel-dashboard.html` | `citadel-dashboard.html` | Q3.1 |
| `attic/citadel-dashboard.jsx` | `citadel-dashboard.jsx` | Q3.1 |
| `attic/docker-compose-production.yml` | `docker-compose-production.yml` | Q3.3 |
| `attic/Caddyfile` | `Caddyfile` | Q3.3 |
| `attic/citadel-keystore-Validate-Citadel.ps1` | `citadel-keystore/Validate-Citadel.ps1` | Q3.4 |
| `attic/citadel-keystore-src-Validate-Citadel.ps1` | `citadel-keystore/src/Validate-Citadel.ps1` | Q3.4 |
| `attic/Backup-Citadel.ps1` | `Backup-Citadel.ps1` | Q3.5 |
| `attic/AGPL-3.0.txt` | `AGPL-3.0.txt` (byte-identical to `COPYING`; README/NOTICE/LICENSE-EXCEPTION repointed to COPYING) | Q3.6 |
| `attic/hybrid_kat.rs` | `tests/hybrid_kat.rs` | Q3.8 |
| `attic/timing_analysis.rs` | `examples/timing_analysis.rs` | Q3.8 |
| `attic/citadel-envelope-src-cli.rs` | `citadel-envelope/src/cli.rs` | Q3.9 |
| `attic/Cargo.workspace.toml` | `citadel-keystore/Cargo.workspace.toml` | Q3.10 |
| `attic/Sign-Citadel.ps1` | `Sign-Citadel.ps1` | Q3.10 |

Root `Validate-Citadel.ps1` stays (canonical copy).

## Statement

No capability removed without a ruling; every move is attic-quarantine, reversible
with `git mv`.
