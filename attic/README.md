# attic/ — quarantined files (consistency audit, Phase B)

Files moved here by the Phase B duplication-consolidation pass. Nothing is deleted:
every entry is reversible with `git mv attic/<name> <original path>`. Audit refs
(Qx.y) point at the rulings in the audit's DECISION_QUESTIONS.

| File | Original path | Why quarantined | Audit ref |
|---|---|---|---|
| `dashboard.html` | `dashboard.html` | Stale snapshot of the served `citadel-api/src/dashboard.html` (94 diff lines behind) | Q3.1 |
| `citadel-dashboard.html` | `citadel-dashboard.html` | CDN-React simulation on hardcoded data, zero API calls, zero referrers | Q3.1 |
| `citadel-dashboard.jsx` | `citadel-dashboard.jsx` | CDN-React simulation on hardcoded data, zero API calls, zero referrers | Q3.1 |
| `docker-compose-production.yml` | `docker-compose-production.yml` | Deprecated in Phase A; superseded by `deploy/docker/docker-compose.yml` (predates required-vars startup gate, no Redis, demo seed on) | Q3.3 |
| `Caddyfile` | `Caddyfile` | Only referenced by the deprecated root compose; TLS-with-Caddy pattern preserved in DEPLOYMENT.md | Q3.3 |
| `citadel-keystore-Validate-Citadel.ps1` | `citadel-keystore/Validate-Citadel.ps1` | Stray copy of root `Validate-Citadel.ps1` (root copy is canonical and stays) | Q3.4 |
| `citadel-keystore-src-Validate-Citadel.ps1` | `citadel-keystore/src/Validate-Citadel.ps1` | Stray copy of root `Validate-Citadel.ps1` (root copy is canonical and stays) | Q3.4 |
| `Backup-Citadel.ps1` | `Backup-Citadel.ps1` | Superseded: `citadel backup create` (CLI) is the primary encrypted mechanism; volume-level snapshot documented in DEPLOYMENT.md | Q3.5 |
| `AGPL-3.0.txt` | `AGPL-3.0.txt` | Byte-identical duplicate of `COPYING`; all references repointed to COPYING | Q3.6 |
| `hybrid_kat.rs` | `tests/hybrid_kat.rs` | Imports modules that no longer exist; root is a virtual workspace so the file was attached to no crate | Q3.8 |
| `timing_analysis.rs` | `examples/timing_analysis.rs` | Root is a virtual workspace — example attached to no crate, never compiled | Q3.8 |
| `citadel-envelope-src-cli.rs` | `citadel-envelope/src/cli.rs` | Orphan module: no `mod cli` declaration anywhere, no Cargo bin target points at it | Q3.9 |
| `Cargo.workspace.toml` | `citadel-keystore/Cargo.workspace.toml` | Stray workspace manifest inside a member crate; real workspace root is `/Cargo.toml` | Q3.10 |
| `Sign-Citadel.ps1` | `Sign-Citadel.ps1` | Stray script, referenced by nothing outside itself | Q3.10 |
