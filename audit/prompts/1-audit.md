# Prompt 1 — The consistency audit

Use: paste this whole file as a prompt to a capable coding agent (Claude Code or similar) pointed at a clean clone of the repository you want audited. It reproduces the audit method that produced `audit/CITADEL_AUDIT.md` on this fork. Nothing here requires trusting the fork's results — this regenerates them from scratch.

---

You are running a **consistency audit** of the repository in the current working directory. This is explicitly NOT a security audit: you audit consistency, structure, reproducibility, claims-vs-code, and code quality. If the project calls itself unaudited, your report must state that it remains unaudited after this work. If while working you find anything that looks like an actual vulnerability, do NOT put it in the report — write it to a separate private file and tell your operator to use the project's SECURITY.md disclosure channel.

Work through seven sections. Every finding needs file:line on both sides (the claim and the code). Fairness rule: re-read the exact wording of a claim before marking a mismatch — a maintainer who documents precisely deserves precise reading. False mismatch accusations are the worst failure mode of this audit.

## §0 Claims vs. code (the centerpiece)
Inventory every document that makes checkable claims (validation matrices, security-guarantee docs, compliance matrices, README numbers, wire specs, API freeze contracts, CHANGELOG). For each claim: does the cited test exist at the cited path? Does it test what the claim says (open it and read the assertions — not just the name)? Do quoted numbers (loop counts, test counts, coverage counts) match the code constants? Does the CHANGELOG reconcile with git history? Output: a contradiction table — claim | claimed-where (file:line) | code reality (file:line) | verdict (VERIFIED / MISMATCH / STALE-PATH / UNVERIFIABLE) | severity (doc-fix vs code-question). Include VERIFIED rows for headline claims: the good news is part of the audit.

## §1 Surface + structure inventory
The real module/crate dependency graph vs. the README's story. Every actual API route/endpoint vs. the documented table. CLI commands. FFI exports vs. shipped bindings. Duplicated same-purpose artifacts (multiple dashboards, multiple test-vector files, multiple validation scripts): a duplication matrix with behavioral differences named and a recommended survivor per row, plus what unique features must be ported before the loser goes. Classify every root artifact live / leftover / ghost by finding its referrers (grep the whole tree; a file nothing references is a candidate, not a verdict).

## §2 Reproducibility — run their docs
Follow the README/quickstart exactly as written on a clean environment: container path, from-source build, the project's own canonical test/judge script, the full test suite, fuzz targets compile, documented examples end-to-end. Each step: WORKED / NEEDED-UNDOCUMENTED-STEP / FAILED, with the exact fix. Where the project's own CI defines the gate, run that gate.

## §3 Code quality (language-appropriate)
For Rust: clippy pedantic per crate (count + 5 worst), complete `unsafe` inventory (each justified? safety comment?), complete panic/unwrap/expect census in the request path (a server must not 500-by-panic — separate request-path from startup from tests), cargo audit + the project's own deny/vet gates, dead code, TODO census. Actionable handful per category, not a lint dump — but the unsafe table and request-path-panic list must be complete.

## §4 Docs coherence
Doc-authority map: for each topic, which document claims to govern and which actually should. Contradictions BETWEEN docs (same fact stated two ways), staleness (old-version prose surviving a new version), and the supersede-banner pass: exact banner text per superseded doc, one declared canon per topic.

## §5 Structure analysis (walk test)
Can a fresh agent, from the files alone: orient (what is this, where is everything)? build and test? find THE authoritative answer to any single question (wire format, validation entry point, which artifact is the live one)? Record the walk as a transcript — question, path taken, PASS/FAIL. Multiple docs answering one question with no declared canon is a walk-test failure by definition. Output a migration map (old path → new path → referrers to update) for the minimal restructure that makes the walk pass, honoring reference integrity: never propose a move without enumerating what points at the file.

## §6 Preservation ledger
Number every capability the system has: endpoints, CLI commands, FFI functions, UI features, wire suites, adaptive behaviors, docs-as-promises (stability contracts). This ledger is the contract every subsequent change is verified against — a consolidation that silently drops a numbered capability is vandalism with good intentions. Changes are verified by walking the ledger, not by "tests still pass."

Deliverable: one report file with sections §0–§6, a summary table of finding counts by severity, and an explicit scope statement (consistency audit, not a security audit, project remains unaudited).
