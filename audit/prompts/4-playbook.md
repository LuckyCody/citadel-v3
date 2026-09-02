# Prompt 4 — The full playbook (any repo, end to end)

Use: this is the whole method in one prompt, generalized. Point an agent at any repository you own — yours or one you're helping — and it runs audit → decision questions → executed phases → single-entrypoint delivery. Prompts 1–3 are this playbook's stages in detail; use them when you want one stage at a time and finer control.

---

You are giving the repository in the current working directory "the full treatment": a consistency audit, a decision walkthrough, executed consolidation, and a delivery the owner can verify. Ground rules first, then the sequence.

## Ground rules
- **Scope honesty.** This is a consistency/structure/reproducibility/claims-vs-code/quality audit. It is never a security audit, and every artifact you produce says so if the project is security-relevant. An unaudited project remains unaudited when you're done.
- **Vulnerability-shaped findings** go to a private file for the owner and the project's disclosure channel — never into public artifacts.
- **You don't need permission to work, only to merge.** On a fork or branch, execute everything; the owner's consent gates what lands on the mainline, item by item.
- **Preservation over improvement.** A numbered capability ledger is written before any change; every phase is verified against it. A rewrite without the ledger is vandalism with good intentions.
- **The owner's own gates are the gates.** Their test suite, their judge script, their CI. If those are broken, fixing them is the first change, because everything else is verified through them.

## Sequence

**1. Audit** (Prompt 1): seven sections — claims-vs-code contradiction table, surface + duplication inventory, reproducibility runs of their own docs, code quality (complete unsafe + request-path-panic census; lint/audit gates), docs coherence + authority map, structure walk test + migration map, preservation ledger. Everything file:line, both sides.

**2. Decision questions** (Prompt 2): every finding needing owner intent becomes a walkthrough item — evidence, options, recommended lean marked as recommendation — in blocks ordered by unblocking power. The owner rules one line per item. Rulings, not findings, authorize changes.

**3. Execution** (Prompt 3): four phases on separate branches — A: needs-no-ruling truth fixes; B: behavior-preserving consolidation per survivor matrix; C: structure migration with reference integrity; D: ruling-gated changes, one branch per ruling, labeled revertable. Each phase ends with build + their tests + their judge + a committed ledger-walk record.

**4. Delivery**: one entrypoint the owner points their agent at. A start-here branch whose root README-for-the-audit contains: three lines of orientation, the map of what lives where (which branches are safe-to-merge vs ruling-gated), verbatim instructions for the owner's agent (verify N findings against code, walk the owner through the decisions, diff any phase branch and check its ledger file, or regenerate everything from the prompt pack), and the honesty block (scope, what this is not, where vulnerability-shaped material went). The audit commentary lives ONLY on the start-here branch; phase branches carry code changes only, so merging one never imports the auditor's voice into the owner's tree.

## Why this shape works
- The audit is falsifiable: every row carries the refs to check it.
- The decisions are cheap: a minute per ruling, because the evidence and options are pre-chewed.
- The execution is safe: ledger-verified, phase-isolated, revertable, gated by the owner's own CI.
- The delivery is respectful: the owner merges nothing they didn't rule on, and can regenerate the whole thing from scratch instead of trusting a stranger's fork.
