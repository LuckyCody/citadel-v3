# CITADEL_ICM_PROPOSAL — structure restructure, demonstrated

This is the §5 structure analysis as a standalone proposal. The FULL restructure (Lane 2) is **executed on this fork's `audit/phase-c-icm` branch** — diff it against master to see the exact result instead of imagining it. Adopting it upstream is ruling Q4.1 in [DECISION_QUESTIONS.md](DECISION_QUESTIONS.md); Lane 1 (banners + docs/INDEX.md only, zero moved files) is the low-commitment alternative already mostly delivered by phase A.

---

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
