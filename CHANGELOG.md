# Changelog

All notable changes to Citadel are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); dates are UTC.

## [Unreleased]

### Changed
- Documentation and metadata accuracy pass: corrected repository links, the
  Docker/source quick-start instructions, the AWS-LC FIPS module version
  claim (aligned to the pinned, CMVP-validated `3.1.0` build across all
  docs and one stale test assertion), and the AGPL commercial-license
  wording. Reconciled `VALIDATION_MATRIX.md` and `COMPLIANCE_MATRIX.md`,
  which had not been updated since the initial commit, with current status.

## [0.2.0] — 2026-08-06 (beta)

### Added
- Second envelope suite, `0xA4`: P-384 (FIPS 186-5) + ML-KEM-1024 (FIPS 203,
  NIST category 5), CNSA 2.0-aligned. `0xA3` (X25519 + ML-KEM-768, category 3)
  remains the default. Suite selection is self-describing on the wire —
  no negotiation, so no downgrade path.
- Optional `fips` build feature: routes envelope operations through the
  AWS-LC cryptographic library, pinned to a CMVP-validated FIPS module
  build (AWS-LC-FIPS 3.1.0, certificates #5298/#5314). Does not make
  Citadel itself a FIPS-validated product — see `SECURITY_MATURITY.md`.
- Machine-checked proof (CryptoVerif) that the hybrid combiner keeps the
  derived key secret as long as either component KEM remains secure, for
  both suites, independently adversarially reviewed.
- ML-KEM ACVP known-answer-test coverage now passing (60/60) against the
  production provider, cross-checked byte-for-byte against a second,
  independent ML-KEM implementation.
- Constant-time evaluation (dudect) of the shipped envelope paths; see
  `TIMING.md` for the full results and known limitations.
- Fuzzing coverage of the wire-format parser, the full decryption path,
  the seal/open round trip, and the FFI free path.
- `citadel-signer` crate: ML-DSA-65 signing service.
- `citadel-ffi` crate: C ABI plus Python/Java/C bindings.

### Changed
- ML-KEM provider switched from an abandoned PQClean-based chain to
  RustCrypto's `ml-kem` (currently pinned at `0.3.2`) after the former's
  upstream advisory. See `PROVIDER_DECISION_LOG.md` and
  `PROVIDER_BAKEOFF_2026.md` for the evaluation.
- Dual-licensed under AGPL-3.0-or-later plus a separate commercial license;
  added an AGPL section 7 additional permission covering the optional
  `fips` build's AWS-LC/OpenSSL-license linkage — see `LICENSE-EXCEPTION`.

### Security
- Adversarial testing of the envelope on both backends: the malleability
  sweep rejects every tampered input with zero accepted forgeries and zero
  panics; 200,000 seals produce distinct nonces; cross-suite envelopes are
  rejected. Independently re-run end to end by a separate automated review
  gate.
- No independent third-party security audit has been performed. See
  `SECURITY.md` for the current audit status and disclosure process.

## [0.1.0] — 2026-07-09

### Added
- Initial public release: hybrid post-quantum envelope encryption
  (X25519 + ML-KEM-768 + AES-256-GCM) behind a REST API.
- `citadel-envelope`: hybrid KEM + wire format core.
- `citadel-keystore`: four-level key hierarchy (Root → Domain → KEK → DEK),
  threat-adaptive rotation policies, replay protection, integrity-chained
  audit log.
- `citadel-api`: HTTP server, scoped API-key auth, rate limiting,
  real-time dashboard.
- `citadel-cli`: command-line interface.
- NIST ACVP known-answer vectors for ML-KEM-768.
