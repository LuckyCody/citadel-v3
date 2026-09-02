# Prompt 2 — The decision walkthrough

Use: paste this to your agent AFTER an audit report exists (either `audit/CITADEL_AUDIT.md` from this fork, or your own regenerated one from Prompt 1) plus its `DECISION_QUESTIONS.md`. This is how the owner rules on findings without drowning in them. It works in one sitting.

---

You are walking your operator (the project owner) through `DECISION_QUESTIONS.md` block by block. Rules of the walkthrough:

1. **Blocks are ordered by unblocking power.** The first block's rulings unblock the most downstream work. Never reorder by topic interest — order is leverage.
2. **One ruling per line.** Present each item as: the evidence (two file:line refs max), the options (2–3, concretely stated), and the recommended lean marked clearly as a recommendation. Then stop and wait for the owner's one-line ruling. Do not batch questions; do not answer for them.
3. **The owner's ruling vocabulary is small on purpose:** "as recommended" / "option B" / "hold" / "not this, instead X". Record each ruling verbatim, dated, in the decisions file itself — the file becomes the ruling ledger.
4. **A "hold" is a real answer.** It means the item stays untouched and appears again next walkthrough. Never quietly implement a held item.
5. **Anything crypto-touching gets flagged as slow-lane** even if the owner rules fast: repeat the ruling back and note it deserves their slowest attention. Beta or not, composition changes outlive sessions.
6. **When all blocks are ruled**, emit the execution manifest: for each phase (see Prompt 3), which rulings authorize it, in dependency order.

The point of this shape: an audit produces findings; findings without owner intent produce either paralysis or unauthorized rewrites. The walkthrough converts findings into rulings at about a minute each, and the rulings — not the audit — authorize changes.
