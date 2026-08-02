// SPDX-License-Identifier: AGPL-3.0-or-later
//! Packet 044: FIPS-mode runtime assertions on the fips build.
//!
//! `fips_module_status()` returning `Ok` proves the linked library is the AWS-LC
//! FIPS module AND that its constructor completed: the constructor performs the
//! module-integrity HMAC (fail-closed: on mismatch the module exits — upstream
//! FIPS.md, quoted in `citadel/fips-backend/FIPS_MODE_STATUS.md`) and the power-on
//! self-tests. A process that reaches these assertions alive with `Ok` has a
//! self-tested module underneath it. Empirically corrupting the module to
//! demonstrate the exit path requires building a modified binary and is a recorded
//! ceiling, not attempted here.
//!
//! Compiles empty without `--features fips`.

#![cfg(feature = "fips")]

use citadel_envelope::backend_awslc::{
    fips_entropy_status, fips_module_status, AwsLcHash, FIPS_MODULE_VERSION,
};

/// P1: the fips build links the real FIPS module and it is operational.
#[test]
fn fips_mode_is_active() {
    fips_module_status().expect("FIPS_mode() must be 1 on the fips build");
}

/// P1 (ordering variant): mode still asserted AFTER performing crypto — the module
/// remained operational through actual service use.
#[test]
fn fips_mode_still_active_after_crypto_use() {
    let digest = AwsLcHash::sha256(b"probe");
    assert_eq!(digest.len(), 32);
    fips_module_status().expect("FIPS mode must persist across service calls");
}

/// P2 (state probe, measured 2026-08-02): CPU jitter entropy is NOT enabled in
/// aws-lc-fips-sys 0.13.16's default build configuration — it is a cmake opt-in,
/// and the module uses its default approved seeding path instead. The SP 800-90B
/// jitter certificate (#E77) applies only to jitter-enabled builds, so no
/// jitter-entropy claim is supportable for this pin. This test PINS the measured
/// state: if a re-pin or build-flag change flips it, the failure forces the docs
/// and claim language to be revisited together (same pattern as the version anchor).
#[test]
fn fips_jitter_entropy_state_is_pinned() {
    assert!(
        fips_entropy_status().is_err(),
        "jitter entropy became ACTIVE — update FIPS_MODE_STATUS.md and claim language"
    );
}

/// P4 anchor: the pinned module version constant matches what the packet recorded.
/// (If aws-lc-fips-sys is ever re-pinned — e.g. to a certificate-validated v2.0
/// line per the Review-Pending finding — this test forces the constant, the docs,
/// and the claims to be revisited together.)
#[test]
fn pinned_module_version_is_recorded() {
    assert_eq!(FIPS_MODULE_VERSION, "AWS-LC-FIPS 3.4.0");
}
