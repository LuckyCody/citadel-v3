# Supply-Chain Advisory Status

Last reviewed: 2026-07-20. Authoritative tools: `cargo audit` (advisories) and
`cargo deny check` (advisories + bans + licenses + sources). Re-run any time.

## Policy

- **Vulnerabilities always fail the gate.** No vulnerability is ever ignored.
- **Unmaintained/unsound advisories are surfaced, not hidden.** `cargo audit`
  prints every one on every run. `cargo deny`'s gate scopes unmaintained/unsound
  to crates we *directly* depend on (`unmaintained = "workspace"`,
  `unsound = "workspace"`); transitively-pulled dev-tooling advisories do not fail
  the build but remain visible in `cargo audit` and are listed below.
- **We do not `ignore` specific advisory IDs.** There is no per-ID suppression.

## Vulnerabilities: 0

RUSTSEC-2026-0207, -0208 (libcrux-sha3) and -0212 (libcrux-secrets) were **fixed**
on 2026-07-20 by bumping the `libcrux-ml-kem` dev-dependency (differential-test
oracle / comparison benches only) from `=0.0.9` to `=0.0.10`, which pulls the
patched `libcrux-sha3 0.0.10` and `libcrux-secrets 0.0.6`. The vulnerable versions
are no longer in `Cargo.lock`; the patched code is compiled in. The full test
suite is unchanged at 353 passed / 0 failed / 8 ignored. This was a real code
swap, not a suppression — and libcrux was dev-only, so nothing vulnerable ever
shipped in the production binary regardless.

## Accepted (visible) warnings: 4 — all dev-only, no upstream fix

| Advisory | Crate | Type | Path (all dev-only) | Why accepted |
|---|---|---|---|---|
| RUSTSEC-2021-0139 | ansi_term 0.12.1 | unmaintained | dudect-bencher → clap 2.x (timing benches) | "No safe upgrade available"; not shipped |
| RUSTSEC-2024-0375 | atty 0.2.14 | unmaintained | dudect-bencher → clap 2.x | superseded by std::io::IsTerminal upstream; not shipped |
| RUSTSEC-2021-0145 | atty 0.2.14 | unsound | dudect-bencher → clap 2.x | potential unaligned read in a dev bench dep; not shipped |
| RUSTSEC-2026-0173 | proc-macro-error2 2.0.1 | unmaintained | hax-lib ← libcrux dev oracle | build-time proc-macro; not shipped |

These persist in every `cargo audit` run by design. The only way to remove them is
to drop the dev tooling that pulls them (replace `dudect-bencher`; drop the libcrux
differential oracle) — tracked as a possible future cleanup, deliberately not done
here because it would reduce test/CT-validation capability for zero shipped-risk
benefit.
