// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wycheproof AES-256-GCM vectors replayed on BOTH backends (packet 043b).
//!
//! Clears the packet-040 gate debt: an authoritative, checked-in vector FILE for the
//! AEAD (hand-transcribed spec case 16 was dropped there; these bytes were fetched
//! mechanically from C2SP/wycheproof at the same pinned commit as the P-384 file and
//! never passed through a human or a model). Valid cases must produce the exact
//! `ct || tag` on BOTH implementations and cross-open; invalid cases (mostly
//! modified tags/ct) must be rejected by BOTH. fips-gated so default-suite counts
//! stay frozen; the RustCrypto arm is exercised here alongside AWS-LC.

#![cfg(feature = "fips")]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as RcNonce,
};
use citadel_envelope::backend_awslc::AwsLcAes256Gcm;

#[derive(serde::Deserialize)]
struct Vectors {
    source_commit: String,
    tests: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rc_seal(key: &[u8; 32], nonce: &[u8; 12], msg: &[u8], aad: &[u8]) -> Vec<u8> {
    Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(&RcNonce::from(*nonce), Payload { msg, aad })
        .expect("rustcrypto seal")
}

fn rc_open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    Aes256Gcm::new_from_slice(key)
        .unwrap()
        .decrypt(&RcNonce::from(*nonce), Payload { msg: ct, aad })
        .ok()
}

#[test]
fn wycheproof_aes256gcm_replay_on_both_backends() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("wycheproof_aes256gcm_vectors.json")).unwrap();
    assert_eq!(
        vectors.source_commit, "b61843a9a5115bb758134b6a1f5d5e502d445342",
        "vector provenance changed"
    );

    let mut valid = 0u32;
    let mut invalid = 0u32;
    for case in &vectors.tests {
        let key: [u8; 32] = from_hex(&case.key).try_into().unwrap();
        let iv: [u8; 12] = from_hex(&case.iv).try_into().unwrap();
        let aad = from_hex(&case.aad);
        let msg = from_hex(&case.msg);
        let mut expected = from_hex(&case.ct);
        expected.extend_from_slice(&from_hex(&case.tag));

        match case.result.as_str() {
            "valid" => {
                valid += 1;
                let lc = AwsLcAes256Gcm::seal(&key, &iv, &msg, &aad).expect("awslc seal");
                let rc = rc_seal(&key, &iv, &msg, &aad);
                assert_eq!(lc, expected, "awslc tc{}: {}", case.tc_id, case.comment);
                assert_eq!(
                    rc, expected,
                    "rustcrypto tc{}: {}",
                    case.tc_id, case.comment
                );

                let lc_open = AwsLcAes256Gcm::open(&key, &iv, &expected, &aad).expect("awslc open");
                let rc_open = rc_open(&key, &iv, &expected, &aad).expect("rustcrypto open");
                assert_eq!(lc_open, msg, "awslc open tc{}", case.tc_id);
                assert_eq!(rc_open, msg, "rustcrypto open tc{}", case.tc_id);
            }
            "invalid" => {
                invalid += 1;
                assert!(
                    AwsLcAes256Gcm::open(&key, &iv, &expected, &aad).is_err(),
                    "awslc accepted invalid tc{}: {}",
                    case.tc_id,
                    case.comment
                );
                assert!(
                    rc_open(&key, &iv, &expected, &aad).is_none(),
                    "rustcrypto accepted invalid tc{}: {}",
                    case.tc_id,
                    case.comment
                );
            }
            other => panic!("unexpected result class {other} for tc{}", case.tc_id),
        }
    }
    assert_eq!(valid, 39, "valid case count drifted");
    assert_eq!(invalid, 27, "invalid case count drifted");
}
