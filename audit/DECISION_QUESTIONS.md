# DECISION_QUESTIONS — citadel-v3

Every audit finding that needs the **maintainer's intent**, in walkthrough form. Method: work block by block (blocks are ordered by unblocking power, not topic); for each item read the evidence, pick an option, write a one-line ruling next to it. Your Claude can walk you through this exactly as written — see `prompts/2-walkthrough-method.md`. Items marked **LEAN:** carry our recommendation — it is a recommendation, nothing more. Items marked **⏳ SLOW LANE** touch cryptographic composition or its specification: rule on them last, at your own pace, regardless of block order.

Scope reminder: this comes from a **consistency audit** (claims-vs-code, structure, reproducibility, quality) — not a security audit. Evidence references are to `audit/CITADEL_AUDIT.md` sections (§0–§6) and to file:line in your tree at `31deefe`.

Legend for what's already executed: **[done: branch]** = implemented on this fork on that branch, revertable; **[gated]** = not implemented anywhere, waits for your ruling.

---

## Block 1 — Wire-format truth (rules everything spec-shaped downstream)

**Q1.1 — WIRE_SPEC_V2 binding divergence. ⏳ SLOW LANE.** §0 found the v2 spec (§4.1/§4.2) states KDF/AAD bind the **full 98-byte header**, while the shipped encoder binds the **86-byte nonce-free prefix** (`citadel-envelope/src/wire_v2.rs:35`; your own packet 056 / FIPS GCM Scenario 2 note explains why: the nonce is generated inside the AEAD boundary on the FIPS path, so it cannot be in the transcript). An implementer coding from the frozen spec produces envelopes your code rejects.
Options: (a) fix the SPEC to document nonce-free-prefix binding, with the Scenario-2 rationale — code unchanged; (b) change the CODE to bind the full header — a cryptographic change that breaks every existing v2 envelope.
**LEAN: (a).** The code's behavior is deliberate and documented in your own packet notes; the spec drifted. **[gated — doc change, but it is a normative crypto spec: your slowest attention]**

**Q1.2 — 0xA4 has no normative wire lengths anywhere.** §4 §2.3: WIRE_SPEC_V2 constants define only 0xA3; the per-suite length table lives solely in code (`wire.rs` SUITE_TABLE). Half the advertised suites are unspecified.
Options: (a) add the 0xA4 length table to WIRE_SPEC_V2; (b) leave code-only.
**LEAN: (a). [done: audit/phase-d-rulings — applies a-as-recommended, one table, trivially revertable]** ⏳ SLOW LANE (normative spec text).

**Q1.3 — WIRE_SPEC.md's fate after the banner.** §4 §2.2: its "FINAL" v1 key schedule (two-stage HKDF, `citadel-hybrid-*` labels) never existed in shipped code — following it produces undecryptable ciphertexts. The banner (Phase A) already prevents harm.
Options: (a) keep at root with banner; (b) move to a history folder; (c) delete.
**LEAN: (b) — [done as part of Phase C's docs/history/; Phase A banner alone implements (a) if you reject C].**

**Q1.4 — The "200,000 seals, distinct nonces" README number.** §0: the test exists but its default runs are 10k/20k; no in-repo receipt records a 200k run — unlike every other receipted headline number.
Options: (a) run it at 200k once, commit the receipt, keep the claim; (b) soften README to the receipted numbers; (c) leave as-is.
**LEAN: (a).** [gated — we did not run it for you; a claim receipt should come from your machine or CI]

---

## Block 2 — Replay-protection truth

**Q2.1 — The phantom strict-flush mode.** §0/§4: REPLAY_TRUST_BOUNDARIES documents `CITADEL_REPLAY_FLUSH_MODE=immediate` and `CITADEL_REPLAY_BACKEND`; neither exists in code (real var: `CITADEL_REPLAY_STORE`; only programmatic `force_flush()` exists). Phase A already corrected the doc.
Options: (a) doc-fix only (done); (b) additionally implement the immediate-flush env switch so the documented mode becomes real.
**LEAN: (a) now, (b) as a roadmap item you size yourself.** [(a) done: audit/phase-a-doc-truth]

**Q2.2 — File-store durability wording.** §4 §3.4: SECURITY_GUARANTEES/DEPLOYMENT said "written on every claim"; reality is batched (5 s / 100 ops crash window; RTB + code agree). Phase A aligned the docs to reality.
Options: (a) doc-fix only (done); (b) make write-through the default (availability/perf tradeoff).
**LEAN: (a).** [(a) done: audit/phase-a-doc-truth]

---

## Block 3 — Duplication survivors (rules Phase B)

**Q3.1 — Dashboards (4 copies).** §1 item 5: the API serves `citadel-api/src/dashboard.html` (only that one); root `dashboard.html` is a stale snapshot (94 lines behind: no error surfacing, no domain-scoped keys); `citadel-dashboard.{html,jsx}` are CDN-React simulations on fake data, zero API calls, zero referrers.
Options: (a) attic all three root files, survivor = the served one; (b) keep one simulation under examples/ as an offline demo.
**LEAN: (a)** — a fake-data demo of a security dashboard misleads more than it markets. **[done: audit/phase-b-consolidation]**

**Q3.2 — Test-vector files.** §1 item 6: `test_vectors.json` is doc-cited but consumed by nothing; `test_vectors_real.json` is UTF-16LE-corrupt (PowerShell `>` artifact) and consumed by nothing; the generator (`examples/generate_vectors.rs`) is attached to no crate and never compiles; `citadel_cross_verify.py`'s documented workflow needs an example that doesn't exist. The live vectors are elsewhere (citadel-envelope/tests/vectors/, ACVP JSONs).
Options: (a) reattach the generator as a citadel-envelope example, regenerate ONE UTF-8 `test_vectors.json`, fix WIRE_SPEC.md's pointer and cross_verify's usage text; (b) attic all three artifacts and strike the doc references.
**LEAN: (a)** — the independent-Python-reimplementation check (cross_verify) is genuinely valuable and only needs its export path repaired. **[done: audit/phase-d-rulings — applies a-as-recommended]**

**Q3.3 — Production compose duality.** §4 §3.14: root `docker-compose-production.yml` lacks all four required env vars (fails the startup gate), publishes 8443 on all interfaces, defaults demo seed ON — while docs point at `deploy/docker/docker-compose.yml` (full gates, Redis, loopback). Phase A stamped the root file DEPRECATED.
Options: (a) attic the root file; document the Caddy/TLS pattern it carried as a section in DEPLOYMENT.md; (b) merge Caddy into deploy/docker/ compose.
**LEAN: (a). [done: audit/phase-b-consolidation]**

**Q3.4 — `Validate-Citadel.ps1` ×3** (root + citadel-keystore/ + citadel-keystore/src/ — the src copy is older and checks `"Active"` vs the API's `"ACTIVE"`, i.e. silently wrong). §1 item 7.
Options: (a) delete the two keystore strays, keep root; (b) delete all three (smoke-test.sh + full_validation cover it).
**LEAN: (a). [done: audit/phase-b-consolidation]**

**Q3.5 — `Backup-Citadel.ps1`** duplicates `citadel backup` CLI at docker-volume level, referenced nowhere.
Options: (a) attic + one documented docker-volume backup line in DEPLOYMENT.md; (b) keep.
**LEAN: (a). [done: audit/phase-b-consolidation]**

**Q3.6 — `COPYING` ≡ `AGPL-3.0.txt`** byte-identical (§1 item 13).
Options: (a) drop AGPL-3.0.txt, keep COPYING (GNU convention), update the README:318 reference; (b) keep both deliberately.
**LEAN: (a). [done: audit/phase-b-consolidation]**

**Q3.7 — Orphaned harnesses.** §1 item 7: `citadel_api_security_test.py` (duplicated by in-crate tests + scripts/security, referenced nowhere) and `citadel_crash_harness.ps1` (evidence tool for SECURITY_MATURITY's open chaos-testing TODO, referenced nowhere).
Options: (a) move both to tools/validation/ with a status README (crash harness = "pending evidence for maturity TODO"; py = "superseded by in-crate + scripts/security, kept for HTTP black-box reference"); (b) attic the py, keep the crash harness; (c) attic both.
**LEAN: (a)** — cheap, honest, keeps the pending-evidence chain visible. **[done: audit/phase-c-icm as part of tools/ move]**

**Q3.8 — Root `tests/hybrid_kat.rs` + `examples/timing_analysis.rs`.** §1 item 10: attached to no crate, never compiled; hybrid_kat imports modules that no longer exist.
Options: (a) attic both; (b) resurrect under citadel-envelope.
**LEAN: (a)** (generate_vectors.rs is separately resurrected under Q3.2). **[done: audit/phase-b-consolidation]**

**Q3.9 — `citadel-envelope/src/cli.rs`** — 311-line orphan module (not in lib.rs, not a bin target), divergent fork of `bin/citadel-encrypt.rs` (§3 item 7).
Options: (a) attic; (b) wire it back.
**LEAN: (a). [done: audit/phase-b-consolidation]**

**Q3.10 — Strays:** `citadel-keystore/Cargo.workspace.toml` (pre-monorepo residue), `Sign-Citadel.ps1` (signs binaries with a machine-local cert; references an ATTACK_PLAN.md not in the repo).
**LEAN: attic both. [done: audit/phase-b-consolidation]**

---

## Block 4 — Structure (rules Phase C)

**Q4.1 — Root-surface restructure: two lanes.** §5's walk test: orientation and build PASS; three authority walks FAIL (wire canon, validation entry points, which dashboard is live). The fix options:
- **Lane 1 (zero moved files):** supersede banners (Phase A, done) + a `docs/INDEX.md` authority map. No URL breaks.
- **Lane 2 (full):** Lane 1 + move second-tier docs into `docs/{spec,security,ops,history}/`, harnesses into `tools/validation/`, ops scripts into `tools/ops/`, quarantined files into `attic/` — every referrer updated in the same commit. Root keeps GitHub-convention files (README, QUICKSTART, CHANGELOG, SECURITY.md, CONTRIBUTING, licenses, VALIDATION_MATRIX, API_FREEZE, build/deploy config).
Cost of Lane 2: inbound deep links to moved docs break (GitHub serves 404s, no redirects); anything external pointing at them (your blog, issues, the whitepaper's own cross-refs) needs the new paths.
**LEAN: Lane 2** — the repo is young, 2 stars, pre-1.0; the walk-test failures cost every future reader more than the link breakage costs now. **[done: audit/phase-c-icm — diff it to SEE the result rather than imagine it; merging is a separate decision]**

---

## Block 5 — Code questions (rules Phase D; each on its own revertable branch)

**Q5.1 — Panic hygiene in the request path.** §3: master-key entropy/pattern checks `panic!` on the per-request auth path while startup validates only hex+length — a well-formed low-entropy key boots, then panics on every authenticated request (main.rs:492–546 via :1065). No CatchPanicLayer anywhere. 10 `Mutex::lock().unwrap()` in non-test keystore code, including the replay-cache lock inside `decrypt()` — one poisoned lock bricks all future decrypts (citadel-ffi already ships the poison-recovery idiom).
Options: (a) all three fixes: entropy validation moved to startup (fail-fast), `CatchPanicLayer` on the axum stack (uniform 500), poison-recovery (or parking_lot) on keystore locks; (b) a subset.
**LEAN: (a). [done: audit/phase-d-rulings — three separate commits so you can take any subset]**

**Q5.2 — Error responses leak internals.** §3 item 9: 500 bodies interpolate `KeystoreError::StorageError` strings (main.rs:1548/1574/1617/2627); three handlers pick status codes by `msg.contains("StateEnforcer")` string-matching.
Options: (a) minimal: stop interpolating internal error strings into bodies (uniform "internal error" + request_id, detail to logs) and replace the contains() checks with typed matches; (b) full typed-error refactor with IntoResponse.
**LEAN: (a)** — (b) is a real refactor you should shape yourself. **[done: audit/phase-d-rulings — minimal variant]**

**Q5.3 — Dead `fail_closed` config knobs** in both replay stores (§3 item 7): accepted, stored, never read.
Options: (a) remove the knobs; (b) wire them to behavior.
**LEAN: (a)** — dead security config is worse than no config (implies a switch that isn't there). **[gated — removing a public config field is API-shaped; your call]**

**Q5.4 — Helper duplication that already caused a bug.** §3 item 8: master-key validation exists in 3 divergent copies (the divergence IS the Q5.1 boot/request split), HMAC pepper hashing ×2, root-key loading ×3.
Options: (a) consolidate into citadel-core; (b) leave.
**LEAN: (a), sized as a normal refactor PR.** [gated — touches crypto-adjacent plumbing; wants your test-plan judgment]

**Q5.5 — VALIDATION_MATRIX evidence-name drift.** §0 item 8: several cited test names don't exist as named (`primitive_kat_*`, `p006_*`, `*_fails_closed`…) though equivalent coverage exists; one row cites a test that doesn't test the claim (`it_health_no_auth_required` for the master-key startup gate).
Options: (a) re-point every row at the real test names (our mapping is in §0's table); (b) leave.
**LEAN: (a). [done: audit/phase-a-doc-truth, second wave — pure evidence-pointer fixes]**

**Q5.6 — TIMING.md's repro procedure cites `pqclean_*` benches** that no longer exist post-provider-switch (§0 item 7).
Options: (a) update the procedure to the current bench names, keep historical results labeled historical; (b) leave.
**LEAN: (a). [done: audit/phase-a-doc-truth, second wave]**

---

## Block 6 — Promises, evidence, and identity

**Q6.1 — The four honest ⏳ PENDING rows in VALIDATION_MATRIX** (multi-process replay ×2, 100× abuse storm, 10-min long-run load). The harnesses exist; the receipts don't.
Options: (a) run them, attach receipts, flip the rows; (b) de-scope the rows explicitly ("covered by X instead"); (c) leave PENDING.
**LEAN: (a)** — they are your last self-declared gaps, and all three harnesses are runnable on a Windows box in under an hour. [gated — receipts should come from your environment]

**Q6.2 — History note.** Public git history starts 2026-07-09 (squashed import); several docs carry earlier dates (API_FREEZE 2026-02-05, baseline run 2026-05-01). Nothing dishonest — but §0 marked those "document testimony only."
Options: (a) one CHANGELOG line: "public history begins 2026-07-09 as a squashed import of the private development repo; in-doc dates before that refer to the private history"; (b) leave.
**LEAN: (a) — one line buys a lot of trust. [done: audit/phase-a-doc-truth]**

**Q6.3 — Contact fragmentation** (§4 §3.15): security=gmail, support=outlook, license=commit@reposignal.io; SUPPORT says Issues, SECURITY says Discussions.
Options: (a) one address per purpose, stated once; (b) leave.
**LEAN: (a) — owner-only choice of which addresses.** [gated]

**Q6.4 — HTTP API stability.** §1: API_FREEZE covers only the SDK/FFI; no HTTP freeze exists; three endpoint inventories disagree (README 18 → now 27 after Phase A; openapi.yaml 24; code 27).
Options: (a) declare openapi.yaml the machine-readable HTTP contract, extend it to 27 routes, link it from README (done in A), and state "HTTP surface: stable-additive, no freeze yet"; (b) write a real HTTP freeze tier into API_FREEZE.
**LEAN: (a) now, (b) at 1.0.** [openapi extension gated — it feeds your Schemathesis gate, so you should review each added schema]

**Q6.5 — The deny gate is decorative.** §2: `cargo deny check` currently FAILS (`error[yanked]: chacha20 0.10.1` — your own `yanked = "deny"` policy), and ci.yml:87 runs it with `|| true`, so CI never enforces it. The lockfile fix is `cargo update -p chacha20` (patch bump within 0.10.x).
Options: (a) apply the lockfile bump AND drop the `|| true` so the gate is real; (b) lockfile bump only, keep the soft gate; (c) keep `|| true` deliberately (deny as advisory) and say so in a comment.
**LEAN: (a).** [lockfile bump done: audit/phase-a-doc-truth (it restores YOUR declared policy to green — verify the diff is one lockfile entry); the `|| true` removal is gated — it changes what can break your CI]

**Q6.6 — Example env-var mismatch.** §2: `citadel_example.py` reads `CITADEL_KEY`; every README/QUICKSTART snippet exports `CITADEL_API_KEY` — the documented first-run exits with a usage message.
Options: (a) make the script also accept `CITADEL_API_KEY` (fallback order, two lines); (b) document `CITADEL_KEY` in README where the example is introduced.
**LEAN: (a) — the docs' variable should just work. [done: audit/phase-d-rulings — two-line fallback; (b) one-line doc note included in phase A]**

---

## Ruling sheet (fill in — one line each)

| Q | Ruling | Date |
|---|---|---|
| 1.1 | | |
| 1.2 | | |
| 1.3 | | |
| 1.4 | | |
| 2.1 | | |
| 2.2 | | |
| 3.1–3.10 (bulk OK) | | |
| 4.1 | | |
| 5.1 | | |
| 5.2 | | |
| 5.3 | | |
| 5.4 | | |
| 5.5 | | |
| 5.6 | | |
| 6.1 | | |
| 6.2 | | |
| 6.3 | | |
| 6.4 | | |
| 6.5 | | |
| 6.6 | | |
