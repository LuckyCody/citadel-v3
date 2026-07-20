# P028 — Cryptographic provider assurance remains open

**Status:** OPEN — production claim blocker

## Reproduced evidence

Packet 006 removed the production PQClean chain and its RUSTSEC-2026-0161,
-0162, and -0163 advisories. Exact-pinned RustCrypto `ml-kem 0.3.2` now passes
the direct FIPS 203, differential, negative, and randomized release-path gates.
Upstream nevertheless states that this implementation has never been
independently audited, so the evidence supports a self-validated audit candidate,
not an independently assured production claim.

The signing path exact-pins `ml-dsa 0.1.0-rc.9`. Packet 002 verified its
zeroization feature path, but it did not establish an independent implementation
audit, production validation, or direct official-vector evidence for the exact
release path. A clean advisory result would not provide that assurance by itself.

The whole-workspace `cargo audit --deny warnings` gate still reports unrelated
development/transitive warnings (`ansi_term`, `atty`, and `proc-macro-error2`).
None is in the selected ML-KEM release path, but the stronger zero-warning claim
is not met.

## Current containment

- Cryptographic versions are exact-pinned.
- The product is labeled unaudited and non-certified.
- Packet 006 records the completed ML-KEM migration gates.
- No independently audited, FIPS-validated, or unrestricted-production claim is permitted.

## Closure requirements

1. Create and pass an equivalent maintained-provider/direct FIPS 204 vector and
   negative-test gate for the exact ML-DSA release path.
2. Eliminate or explicitly govern the remaining non-provider dependency warnings
   without weakening product claims.
3. Preserve exact versions, source hashes, vector provenance, and rollback evidence.

Packet 006 closes the abandoned ML-KEM subfinding, not the broader provider-
assurance claim.
