# Prompt 3 — Phase execution with ledger verification

Use: paste this to your agent when rulings exist (from Prompt 2) and you want the changes executed. On this fork the phases are already executed on branches — this prompt is how to redo or continue that work in your own tree, with the same discipline.

---

You are executing audit findings as changes, one phase per branch. The discipline:

**Phase A — no ruling needed.** Everything where the repo's own claims define correctness: doc-contradiction fixes (make the doc match the code, or flag as code-question — never silently change behavior to match a doc), missing quickstart steps discovered in reproducibility testing, repairs of things broken-as-documented, supersede banners on the objectively superseded, lint-level pure wins, and dead-file quarantine — moved to an attic folder and listed in an attic README, never silently deleted. If the project's own test/CI gates are broken on the main branch, fixing the gate is Phase A and comes first, because every later phase is verified by that gate.

**Phase B — behavior-preserving consolidation.** Duplicate artifacts folded per the audit's survivor matrix, only where the audit named the behavioral differences and the survivor covers them (port the unique features first, then quarantine the loser). Never consolidate two things whose behavioral difference is still an open question — that's Phase D material.

**Phase C — structure migration.** The audit's migration map executed: files moved WITH their referrers updated in the same commit, reference integrity verified (grep for the old path afterward must return only historical documents like the audit itself).

**Phase D — ruling-gated changes.** One branch per ruling or ruling-cluster, named for the ruling it applies, containing nothing else. If executed on a recommendation the owner hasn't confirmed yet, the branch says so ("applies ruling X-as-recommended — trivially revertable if ruled otherwise").

**Every phase, before it's called done:**
1. Build passes.
2. The project's own test suite passes.
3. The project's own judge/CI script passes (the same gate the maintainer trusts, not a new one you invented).
4. **The ledger walk**: open the preservation ledger and check every numbered capability still exists and behaves — endpoint by endpoint, command by command, feature by feature. Record the walk as `LEDGER_CHECK_<phase>.md` committed on that branch: capability number → how verified (test name, curl, grep of survivor) → intact/changed/removed-with-ruling. A capability removed without a ruling number beside it fails the phase.

Order: A → B → C → D. Later phases rebase on earlier ones only if the owner wants them stacked; independent branches off main are the default so each can merge or die alone.
