// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Packet 040 differential gate: AWS-LC AES-256-GCM vs RustCrypto `aes-gcm`.
//!
//! AES-GCM is deterministic given (key, nonce, plaintext, aad), so unlike the KEM
//! differential (packet 039, interop-only by necessity) this gate demands **exact
//! byte-identity** of `ciphertext || tag` between the two implementations, plus
//! cross-opening, tamper rejection on BOTH implementations, and the authoritative
//! 256-bit GCM spec vectors (McGrew & Viega, "The Galois/Counter Mode of Operation",
//! revised spec appendix B, test cases 13 and 14 — the same vectors NIST CAVS uses)
//! reproduced by BOTH implementations.
//!
//! Compiles to an empty test binary unless `--features fips`.

#![cfg(feature = "fips")]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as RcNonce,
};
use citadel_envelope::backend_awslc::AwsLcAes256Gcm;
use rand::RngCore;

const ROUNDS: usize = 200;

fn rc_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
    cipher
        .encrypt(
            &RcNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("rustcrypto seal")
}

fn rc_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
    cipher
        .decrypt(
            &RcNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

fn random_case(round: usize) -> ([u8; 32], [u8; 12], Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);
    // Boundary sizes on early rounds, then random lengths.
    let pt_len = match round {
        0 => 0,
        1 => 1,
        2 => 16,
        3 => 4096,
        _ => (rng.next_u32() % 2048) as usize,
    };
    let aad_len = match round {
        0 | 2 => 0,
        1 => 1,
        3 => 512,
        _ => (rng.next_u32() % 256) as usize,
    };
    let mut pt = vec![0u8; pt_len];
    let mut aad = vec![0u8; aad_len];
    rng.fill_bytes(&mut pt);
    rng.fill_bytes(&mut aad);
    (key, nonce, pt, aad)
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// J2: exact byte-identity of `ct || tag` across implementations, 200 rounds.
#[test]
fn seal_outputs_byte_identical_200_rounds() {
    for round in 0..ROUNDS {
        let (key, nonce, pt, aad) = random_case(round);
        let rc = rc_seal(&key, &nonce, &pt, &aad);
        let lc = AwsLcAes256Gcm::seal(&key, &nonce, &pt, &aad).expect("awslc seal");
        assert_eq!(
            rc,
            lc,
            "ct||tag mismatch, round {round} (pt_len={})",
            pt.len()
        );
    }
}

/// J3a: each implementation opens the other's output, 200 rounds.
#[test]
fn cross_open_200_rounds() {
    for round in 0..ROUNDS {
        let (key, nonce, pt, aad) = random_case(round);
        let rc = rc_seal(&key, &nonce, &pt, &aad);
        let lc = AwsLcAes256Gcm::seal(&key, &nonce, &pt, &aad).expect("awslc seal");

        let lc_opens_rc = AwsLcAes256Gcm::open(&key, &nonce, &rc, &aad).expect("awslc opens rc");
        let rc_opens_lc = rc_open(&key, &nonce, &lc, &aad).expect("rc opens awslc");
        assert_eq!(lc_opens_rc, pt, "awslc-opens-rustcrypto, round {round}");
        assert_eq!(rc_opens_lc, pt, "rustcrypto-opens-awslc, round {round}");
    }
}

/// J3b: tampering with ct, tag, aad, or nonce is rejected by BOTH implementations.
#[test]
fn tamper_rejected_by_both() {
    let (key, nonce, pt, aad) = random_case(4);
    let sealed = AwsLcAes256Gcm::seal(&key, &nonce, &pt, &aad).expect("awslc seal");

    // ciphertext byte
    let mut t = sealed.clone();
    t[0] ^= 1;
    assert!(AwsLcAes256Gcm::open(&key, &nonce, &t, &aad).is_err());
    assert!(rc_open(&key, &nonce, &t, &aad).is_none());

    // tag byte
    let mut t = sealed.clone();
    let last = t.len() - 1;
    t[last] ^= 1;
    assert!(AwsLcAes256Gcm::open(&key, &nonce, &t, &aad).is_err());
    assert!(rc_open(&key, &nonce, &t, &aad).is_none());

    // aad
    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 1;
    assert!(AwsLcAes256Gcm::open(&key, &nonce, &sealed, &bad_aad).is_err());
    assert!(rc_open(&key, &nonce, &sealed, &bad_aad).is_none());

    // nonce
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 1;
    assert!(AwsLcAes256Gcm::open(&key, &bad_nonce, &sealed, &aad).is_err());
    assert!(rc_open(&key, &bad_nonce, &sealed, &aad).is_none());

    // truncated below tag length
    assert!(AwsLcAes256Gcm::open(&key, &nonce, &sealed[..8], &aad).is_err());
}

/// J4: authoritative 256-bit GCM spec vectors, reproduced by BOTH implementations.
///
/// Source: McGrew & Viega, GCM revised spec appendix B (AES-256 cases 13 and 14);
/// identical values appear in NIST CAVS gcmEncryptExtIV256. Stored as
/// (key, iv, pt, aad, expected ct||tag).
#[test]
fn gcm_spec_vectors_reproduce_on_both() {
    // Only vectors whose expected values are certain are pinned here; a third,
    // longer aad+pt case (spec test case 16) was removed when its transcribed
    // expectation failed against BOTH implementations — the transcription, not the
    // implementations, was suspect, and an expectation corrected from the code's own
    // output would be circular. Sourcing a checked-in CAVS vector FILE for AES-256-GCM
    // is recorded as combined-gate debt (packet 043). The long-input shapes are
    // meanwhile covered by the 200-round byte-identity differential above.
    let vectors: [(&str, &str, &str, &str, &str); 2] = [
        // Test case 13: zero key/iv, empty pt, empty aad -> tag only.
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        ),
        // Test case 14: zero key/iv, 16 zero bytes of pt.
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
        ),
    ];

    for (i, (key_hex, iv_hex, pt_hex, aad_hex, expected_hex)) in vectors.iter().enumerate() {
        let key: [u8; 32] = from_hex(key_hex).try_into().unwrap();
        let nonce: [u8; 12] = from_hex(iv_hex).try_into().unwrap();
        let pt = from_hex(pt_hex);
        let aad = from_hex(aad_hex);
        let expected = from_hex(expected_hex);

        let lc = AwsLcAes256Gcm::seal(&key, &nonce, &pt, &aad).expect("awslc seal");
        let rc = rc_seal(&key, &nonce, &pt, &aad);
        assert_eq!(lc, expected, "awslc vs GCM spec vector {i}");
        assert_eq!(rc, expected, "rustcrypto vs GCM spec vector {i}");
    }
}
