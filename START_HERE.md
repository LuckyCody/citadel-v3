# START_HERE — the once-over you asked for

You said "maybe give it a once over... help point me towards making it better." This fork is that, done properly: a full consistency audit of citadel-v3, every finding executed as revertable branches, and the whole method included so you can reproduce it without trusting me. I'm Cody — I run this exact process on my own systems; your repo got the same treatment mine get. Read this file yourself, or paste it to your Claude/agent as a working prompt — it's written for both.

## The one honesty block, first

- **This is NOT a security audit.** It audits consistency, structure, reproducibility, claims-vs-code, and code quality. No cryptanalysis, no pentest, no exploit work. Your README's "unaudited" is still true, and every document here says so.
- **Anything vulnerability-shaped is NOT on this fork** — not in the report, not in branch history. If such material exists, it reaches you through your SECURITY.md private channel, nowhere else.
- **Branches that touch cryptographic composition or its specification deserve your slowest attention.** They are labeled. Nothing here pushes you to merge anything fast — your CONTRIBUTING.md says single-author review for crypto, and this fork is built to respect that: everything is a proposal you can diff, test, cherry-pick, or ignore.
- The good news is real and verified: 38 of 51 checkable claims VERIFIED — your CryptoVerif receipts, ACVP 60/60, the exact malleability-sweep arithmetic, and your full CI passing green on a clean fork clone with zero secrets. You built something unusually honest. The audit's job was finding the 13 that don't hold and the structure that hides your best evidence.

## The map — what lives where on this fork

**This branch (`audit/start-here`)** — all commentary, nothing else:
| File | What it is |
|---|---|
| `audit/CITADEL_AUDIT.md` | The full audit, §0–§6. Every row has file:line on both sides — falsifiable by design |
| `audit/DECISION_QUESTIONS.md` | Every finding that needs YOUR intent, as a walkthrough: evidence → options → our lean (marked as a lean). One-line rulings |
| `audit/PRESERVATION_LEDGER.md` | Every capability your system has, numbered (~100). The contract each phase branch was verified against |
| `audit/CITADEL_ICM_PROPOSAL.md` | The structure proposal (walk test + migration map), demonstrated on phase-c |
| `audit/prompts/1-audit.md … 4-playbook.md` | The full method as portable prompts — reproduce everything from scratch against a clean clone of YOUR repo |

**Phase branches** — code/doc changes only, the `audit/` directory is never on them, so merging any of them never imports my commentary into your tree:
| Branch | Contains | Merge posture |
|---|---|---|
| `audit/phase-a-doc-truth` | Doc-truth fixes needing no ruling: docs aligned to code reality, supersede banners (incl. the WIRE_SPEC.md DO-NOT-IMPLEMENT quarantine), README endpoint table completed to all 27 routes, the yanked-chacha20 lockfile bump. + `LEDGER_CHECK_A.md` | **Safe to merge** — every change is "make the doc match the code the repo itself ships" |
| `audit/phase-b-consolidation` | Duplicate-artifact consolidation per the survivor matrix: stale/simulated dashboards, 3× Validate-Citadel, strays, orphans → `attic/` (moved + listed, nothing silently deleted). Stacked on phase-a. + `LEDGER_CHECK_B.md` | Behavior-preserving; review the attic list |
| `audit/phase-c-icm` | The structure restructure executed (docs/ + tools/ + attic/, every referrer updated in the same commits) so you can SEE it, not imagine it. Stacked on phase-b. + `LEDGER_CHECK_C.md` | **Ruling-gated** (Q4.1) — diff it, then decide |
| `audit/phase-d-rulings` | Recommendation-gated items, one commit per ruling, each labeled "applies Qx.y-as-recommended — trivially revertable if you rule otherwise". Includes the panic-hygiene commits — **crypto-adjacent: slow lane** | **Ruling-gated** — take commits individually |
| `ci/repro-run` | The reproducibility harness: a workflow that runs YOUR documented paths (build, tests, your judge script, clippy, audit, deny, fuzz, your example) on clean ubuntu-latest. Its runs are public receipts | Never needs merging — it's evidence |

Every phase branch passes your own gates: `cargo test --workspace`, your `ci` workflow, and (where applicable) your judge script. Each carries its ledger walk as a committed file.

## Instructions for your Claude (verbatim-usable)

> Clone this fork and check out `audit/start-here`. Read `audit/CITADEL_AUDIT.md`. Pick any three findings and verify them against the code — every row carries file:line for both the claim and the reality; report whether they hold. Then read `audit/DECISION_QUESTIONS.md` and walk your owner through it block by block, exactly as `audit/prompts/2-walkthrough-method.md` specifies: one item at a time, evidence + options + the marked recommendation, one-line ruling per item, crypto-touching items last and slow. Then `git diff master..audit/phase-a-doc-truth` (and any other phase branch) and check its `LEDGER_CHECK_*.md`: confirm every numbered capability in `audit/PRESERVATION_LEDGER.md` is intact, changed-with-ruling, or removed-with-ruling. To reproduce the entire audit from scratch instead of trusting any of it: run `audit/prompts/` items 1–4 in order against a clean clone of the upstream repo.

## If you only have ten minutes

1. Read the executive summary at the top of `audit/CITADEL_AUDIT.md` (one page).
2. Look at finding #1 there (WIRE_SPEC.md's v1 KDF never matched your code — banner already written on phase-a) and finding #2 (WIRE_SPEC_V2's header-binding line vs `wire_v2.rs:35` — Q1.1, yours to rule).
3. Diff phase-a. It's all docs. If you like what you see, the rest of the fork works the same way.

— Cody (github.com/LuckyCody) · this fork never opens a PR at your repo; what merges, and when, stays entirely yours.
