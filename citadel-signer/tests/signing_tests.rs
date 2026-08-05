// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Integration tests for citadel-signer.
//!
//! These tests verify the full sign → assert → verify pipeline using
//! real ML-DSA-65 keypairs. They complement the unit tests inline in
//! dsa.rs and assertion.rs.

use citadel_signer::{
    assertion::CitadelAssertionIssuer,
    dsa,
    wire::{MLDSA65_SEED_BYTES, MLDSA65_SIG_BYTES, MLDSA65_VK_BYTES},
};
use serde_json::json;

// ---------------------------------------------------------------------------
// ML-DSA-65 primitive integration tests
// ---------------------------------------------------------------------------

#[test]
fn mldsa65_key_sizes_match_fips204_spec() {
    // ML-DSA-65 sizes from NIST FIPS 204 §7 and confirmed from ml-dsa source:
    //   ML-DSA-65: sk=4032, vk=1952, sig=3309
    // We store the 32-byte seed (compact form), not the 4032-byte expanded sk.
    assert_eq!(MLDSA65_SEED_BYTES, 32, "seed must be 32 bytes");
    assert_eq!(MLDSA65_VK_BYTES, 1952, "verifying key must be 1952 bytes");
    assert_eq!(MLDSA65_SIG_BYTES, 3309, "signature must be 3309 bytes");
}

#[test]
fn mldsa65_generate_and_verify_roundtrip() {
    let (vk, seed) = dsa::generate_keypair().expect("keygen failed");
    assert_eq!(vk.len(), MLDSA65_VK_BYTES);
    assert_eq!(seed.len(), MLDSA65_SEED_BYTES);

    let message = b"hello from citadel-signer integration test";
    let sig = dsa::sign_message(seed.as_slice(), message).expect("sign failed");
    assert_eq!(sig.len(), MLDSA65_SIG_BYTES);

    let valid = dsa::verify_message(&vk, message, &sig).expect("verify failed");
    assert!(valid, "signature must verify against the correct key");
}

#[test]
fn mldsa65_tampered_message_does_not_verify() {
    let (vk, seed) = dsa::generate_keypair().expect("keygen failed");
    let sig = dsa::sign_message(seed.as_slice(), b"real message").expect("sign");
    let valid = dsa::verify_message(&vk, b"tampered message", &sig).expect("verify");
    assert!(!valid, "tampered message must not verify");
}

#[test]
fn mldsa65_different_keys_do_not_cross_verify() {
    let (_, seed1) = dsa::generate_keypair().expect("keygen1");
    let (vk2, _) = dsa::generate_keypair().expect("keygen2");
    let sig = dsa::sign_message(seed1.as_slice(), b"test").expect("sign");
    let valid = dsa::verify_message(&vk2, b"test", &sig).expect("verify");
    assert!(!valid, "signature must not verify with wrong key");
}

#[test]
fn mldsa65_verifying_key_deterministic_from_seed() {
    let (vk1, seed) = dsa::generate_keypair().expect("keygen");
    let vk2 = dsa::verifying_key_from_seed(seed.as_slice()).expect("reconstruct");
    assert_eq!(
        vk1, vk2,
        "verifying key must be deterministically derived from seed"
    );
}

#[test]
fn mldsa65_wrong_seed_size_is_rejected() {
    let result = dsa::sign_message(&[0u8; 16], b"test");
    assert!(result.is_err(), "wrong seed size must fail");
}

#[test]
fn mldsa65_wrong_vk_size_is_rejected() {
    let bad_sig = vec![0u8; MLDSA65_SIG_BYTES];
    let result = dsa::verify_message(&[0u8; 100], b"test", &bad_sig);
    assert!(result.is_err(), "wrong vk size must fail");
}

#[test]
fn mldsa65_wrong_sig_size_is_rejected() {
    let (vk, _) = dsa::generate_keypair().expect("keygen");
    let result = dsa::verify_message(&vk, b"test", &[0u8; 100]);
    assert!(result.is_err(), "wrong sig size must fail");
}

// ---------------------------------------------------------------------------
// Citadel Native Assertion integration tests
// ---------------------------------------------------------------------------

fn make_issuer() -> (CitadelAssertionIssuer, Vec<u8>) {
    let (vk, seed) = dsa::generate_keypair().expect("keygen");
    let issuer = CitadelAssertionIssuer::new("integration-test-key", 1, seed.to_vec());
    (issuer, vk)
}

#[test]
fn cna_issue_and_verify_roundtrip() {
    let (issuer, vk) = make_issuer();
    let claims = json!({ "sub": "user_123", "scope": ["dashboard:read"] });

    let assertion = issuer.issue(claims.clone(), 3600).expect("issue failed");

    assert_eq!(assertion.version, "cna-v1");
    assert_eq!(assertion.suite, "ml-dsa-65");
    assert!(!assertion.signature_hex.is_empty());
    assert!(!assertion.assertion_id.is_empty());

    let verified = assertion.verify(&vk).expect("verify failed");
    assert_eq!(verified.public_claims, claims);
    assert_eq!(verified.signing_key_id, "integration-test-key");
    assert_eq!(verified.signing_key_version, 1);
    assert!(!verified.has_sealed_claims);
}

#[test]
fn cna_expired_assertion_is_rejected() {
    let (issuer, vk) = make_issuer();
    let mut assertion = issuer.issue(json!({"sub": "u1"}), 60).expect("issue");
    assertion.expires_at = chrono::Utc::now().timestamp() - 1; // force expiry
    assert!(assertion.verify(&vk).is_err(), "expired must be rejected");
}

#[test]
fn cna_tampered_claims_are_rejected() {
    let (issuer, vk) = make_issuer();
    let mut assertion = issuer.issue(json!({"sub": "u1"}), 3600).expect("issue");
    assertion.public_claims = json!({"sub": "attacker", "scope": ["admin"]});
    assert!(
        assertion.verify(&vk).is_err(),
        "tampered claims must be rejected"
    );
}

#[test]
fn cna_wrong_verifying_key_is_rejected() {
    let (issuer, _) = make_issuer();
    let (vk2, _) = dsa::generate_keypair().expect("keygen2");
    let assertion = issuer.issue(json!({"sub": "u1"}), 3600).expect("issue");
    assert!(
        assertion.verify(&vk2).is_err(),
        "wrong key must be rejected"
    );
}

#[test]
fn cna_assertion_ids_are_unique() {
    let (issuer, _) = make_issuer();
    let a1 = issuer.issue(json!({}), 60).expect("issue1");
    let a2 = issuer.issue(json!({}), 60).expect("issue2");
    assert_ne!(
        a1.assertion_id, a2.assertion_id,
        "assertion_ids must be unique"
    );
}

#[test]
fn cna_canonical_form_does_not_include_signature() {
    let (issuer, _) = make_issuer();
    let assertion = issuer.issue(json!({"sub": "u1"}), 60).expect("issue");
    let canonical = assertion.canonical_signing_input().expect("canonical");
    let s = String::from_utf8(canonical).expect("utf8");
    assert!(
        !s.contains("signature_hex"),
        "canonical must exclude signature_hex"
    );
    assert!(
        s.contains("public_claims"),
        "canonical must include public_claims"
    );
    assert!(
        s.contains("assertion_id"),
        "canonical must include assertion_id"
    );
}

#[test]
fn cna_with_sealed_claims_issues_correctly() {
    let (issuer, vk) = make_issuer();
    let assertion = issuer
        .issue_with_sealed(
            json!({"sub": "u1"}),
            3600,
            "deadbeef".to_string(), // sealed_claims_hex (placeholder — real use: Citadel blob)
            "dek-id-123".to_string(),
            1,
        )
        .expect("issue_with_sealed");

    assert!(assertion.sealed_claims_hex.is_some());
    assert_eq!(assertion.sealed_claims_hex.as_deref(), Some("deadbeef"));

    let verified = assertion.verify(&vk).expect("verify");
    assert!(verified.has_sealed_claims);
}
