// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
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
    fips_entropy_status, fips_module_status, fips_module_version_runtime, AwsLcHash,
    FIPS_MODULE_VERSION,
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

/// REAL guard (packet 054): the recorded `FIPS_MODULE_VERSION` constant must match the
/// version of the module **actually linked** into this process. `fips_module_version_runtime()`
/// reads that version from the module at runtime via `OpenSSL_version`, so a `cargo update`
/// that drifts `aws-lc-fips-sys` off the CMVP-validated 0.13.11 / AWS-LC FIPS 3.1.0 build
/// makes this test FAIL — the exact failure mode that was missing while the old assertion
/// compared a constant to a string literal (tautological; found in packet 051).
///
/// Negative controls proving this CAN fail (packet 054 RECEIPT): (A) flipping the constant to a
/// wrong version reddens this test with no rebuild; (B) repinning to 0.13.16 links module 3.4.0
/// and the runtime string then contains "3.4.0", not the recorded "3.1.0", so it fails.
///
/// 053 established why aws-lc-rs's own `fips_version()`/`awslc_version()` (new in 1.17.2) cannot
/// be used: every aws-lc-rs version exposing them requires `aws-lc-fips-sys >= 0.13.16`
/// (module 3.4.0), disjoint from the validated 3.1.0. The formats differ intentionally — the
/// constant reads `"AWS-LC-FIPS 3.1.0"` (hyphenated) and the module reports `"AWS-LC FIPS 3.1.0"`
/// (spaced) — so the guard matches on the version *token*, not the whole string.
#[test]
fn pinned_module_version_matches_linked_module() {
    // The version token of the recorded pin, e.g. "3.1.0" from "AWS-LC-FIPS 3.1.0".
    let recorded_token = FIPS_MODULE_VERSION
        .rsplit(' ')
        .next()
        .expect("FIPS_MODULE_VERSION carries a version token");
    let linked = fips_module_version_runtime();
    // Evidence line (visible with `--nocapture`): records the exact linked module string.
    println!("linked AWS-LC FIPS module version string: {linked:?}");
    assert!(
        linked.contains(recorded_token),
        "linked AWS-LC FIPS module reports {linked:?}, which does not contain the recorded \
         version token {recorded_token:?} (FIPS_MODULE_VERSION = {FIPS_MODULE_VERSION:?}). \
         The CMVP-validated 0.13.11 / 3.1.0 pin may have drifted — check Cargo.lock."
    );
    // Belt-and-suspenders: the module must self-identify as an AWS-LC FIPS build.
    assert!(
        linked.contains("AWS-LC"),
        "linked module version {linked:?} is not an AWS-LC build"
    );
}
