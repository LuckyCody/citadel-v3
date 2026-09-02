# Supply-Chain Advisory Status

Last reviewed: 2026-07-20 (FIPS-module advisory-exceptions addendum added 2026-08-04, packet 058). Authoritative tools: `cargo audit` (advisories) and
`cargo deny check` (advisories + bans + licenses + sources). Re-run any time.

## Policy

- **Vulnerabilities always fail the gate.** No vulnerability is ever ignored.
- **Unmaintained/unsound advisories are surfaced, not hidden.** `cargo audit`
  prints every one on every run. `cargo deny`'s gate scopes unmaintained/unsound
  to crates we *directly* depend on (`unmaintained = "workspace"`,
  `unsound = "workspace"`); transitively-pulled dev-tooling advisories do not fail
  the build but remain visible in `cargo audit` and are listed below.
- **We do not `ignore` specific advisory IDs.** There is no per-ID suppression.

## Vulnerabilities: 2 accepted exceptions (non-applicable, in the CMVP-validated FIPS pin)

RUSTSEC-2026-0207, -0208 (libcrux-sha3) and -0212 (libcrux-secrets) were **fixed**
on 2026-07-20 by bumping the `libcrux-ml-kem` dev-dependency (differential-test
oracle / comparison benches only) from `=0.0.9` to `=0.0.10`, which pulls the
patched `libcrux-sha3 0.0.10` and `libcrux-secrets 0.0.6`. The vulnerable versions
are no longer in `Cargo.lock`; the patched code is compiled in. The full test
suite is unchanged at 353 passed / 0 failed / 8 ignored. This was a real code
swap, not a suppression — and libcrux was dev-only, so nothing vulnerable ever
shipped in the production binary regardless.

### FIPS module advisory exceptions (packet 058, 2026-08-04)

The CMVP-**validated** pin `aws-lc-fips-sys 0.13.11` (AWS-LC FIPS 3.1.0, certs #5298 / #5314;
packet 051) carries two advisories that the newer **unvalidated** 3.4.0 build fixed:

| Advisory | Title | Applicability to Citadel | Status |
|---|---|---|---|
| RUSTSEC-2026-0042 | CRL distribution-point scope-check logic error in AWS-LC | **None** — Citadel does no X.509/CRL processing | Accepted, ID-scoped ignore |
| RUSTSEC-2026-0043 | AES-CCM tag-verification timing side-channel in AWS-LC | **None** — Citadel uses AES-256-GCM, never AES-CCM | Accepted, ID-scoped ignore |

Keeping the CMVP-validated build (packet 051) is a deliberate, owner-approved trade-off —
"validated ≠ latest." The vulnerable code is compiled into the fips build but **never reached by
Citadel's code paths** (grep-verified: zero AES-CCM, zero X.509/CRL). The fixes exist only in
3.4.0, which is **not** CMVP-validated; there is currently no build that is both validated and
patched (the v4.0 line is "in process"). These two IDs are the ONLY specific-ID ignores, in both
`deny.toml` and the `cargo audit` CI step; every other advisory still fails the build. **Re-evaluate**
when a validated build ≥ the fix lands, or if Citadel ever adds AES-CCM or X.509/CRL. This is honest
disclosure of present-but-non-applicable advisories, not suppression.

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

## AWS-LC subtree (packet 038 — Citadel-FIPS dependency gate, 2026-07-31)

The opt-in `fips` feature on `citadel-envelope` selects `aws-lc-rs` with its FIPS
module. Lock change was **additive-only**: one new package, initially `aws-lc-fips-sys
0.13.16`; no existing pin moved. **Superseded 2026-08-04 (packet 051):** re-pinned to
`aws-lc-fips-sys 0.13.11` to hold the CMVP-validated AWS-LC FIPS 3.1.0 build (certs
#5298/#5314) — see the AWS-LC FIPS module advisory-exceptions section above for the
"validated ≠ latest" rationale. Pins currently in force: `aws-lc-rs 1.17.1`,
`aws-lc-sys 0.42.0` (both pre-existing via the comparison feature), `aws-lc-fips-sys
0.13.11`. `cargo audit`: no findings on the subtree beyond the two ID-scoped ignores
documented above.

**License triage (deny.toml `[[licenses.exceptions]]`, scoped per-crate — the global
allowlist is unchanged):**

| Crate | Declared license | Exception granted | Why |
|---|---|---|---|
| aws-lc-rs 1.17.1 | `ISC AND (Apache-2.0 OR ISC)` | `ISC` | ISC is a permissive MIT-equivalent (OpenBSD's license); no obligations beyond notice |
| aws-lc-sys 0.42.0 | `ISC AND (…) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (…)` | `ISC` | Same; every other mandatory term already allowed globally |
| aws-lc-fips-sys 0.13.11 | `ISC AND (Apache-2.0 OR ISC) AND OpenSSL` | `ISC`, `OpenSSL` | See flag below |

**License note (`fips` feature only):** the `OpenSSL` license term carries the historic
advertising clause, which is commonly treated as incompatible with GPL/AGPL
redistribution of combined works absent an explicit exception. Citadel is
AGPL-3.0-or-later. [`LICENSE-EXCEPTION`](LICENSE-EXCEPTION) grants an additional
permission under AGPL section 7 covering exactly this combination, granted by the
copyright holder (RepoSignal LLC / Andre Cordero) on his own code. The `fips`
feature is opt-in and off by default; the default pure-Rust build links no
OpenSSL-licensed code.

**C-build note:** `aws-lc-fips-sys` compiles the AWS-LC FIPS module from C source and
requires CMake, a C compiler, **Go**, and Perl at build time. This box (WSL2 Ubuntu)
currently has cmake/gcc/perl but **no Go toolchain**, so `--features fips` does not
build here yet — installing Go is a prerequisite for packet 039. CI note: the GitHub
Actions build matrix `{default, fips}` (PRD §6.4) additionally needs those packages
in the runner image; Actions is billing-blocked until ~2026-08-04, so the matrix
lands with packet 043 validation running locally until then.
