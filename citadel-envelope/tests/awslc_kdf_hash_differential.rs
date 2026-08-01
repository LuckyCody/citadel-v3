// SPDX-License-Identifier: AGPL-3.0-or-later
//! Packet 041 differential gate: AWS-LC SHA-256 / SHA3-256 / HKDF-SHA256 vs RustCrypto.
//!
//! All three primitives are deterministic, so every gate here is **exact byte
//! equality**: 200 random-input rounds per primitive, canonical published vectors on
//! BOTH implementations, and the exact `wire_v2::derive_key` construction (SHA-256
//! extract-salt label + HKDF transcript expand) reproduced identically through the
//! AWS-LC components. Compiles empty without `--features fips`.

#![cfg(feature = "fips")]

use citadel_envelope::backend_awslc::{AwsLcHash, AwsLcHkdfSha256};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

const ROUNDS: usize = 200;

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

fn len_for_round(round: usize) -> usize {
    match round {
        0 => 0,
        1 => 1,
        2 => 55,  // SHA-256 single-block padding boundary
        3 => 56,  // first two-block input
        4 => 64,  // exact block
        5 => 136, // SHA3-256 rate boundary
        _ => (rand::rngs::OsRng.next_u32() % 4096) as usize,
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// K2: SHA-256 byte-identity, 200 rounds including padding boundaries.
#[test]
fn sha256_byte_identical_200_rounds() {
    for round in 0..ROUNDS {
        let data = random_bytes(len_for_round(round));
        let rc: [u8; 32] = Sha256::digest(&data).into();
        let lc = AwsLcHash::sha256(&data);
        assert_eq!(rc, lc, "sha256 mismatch, round {round} len {}", data.len());
    }
}

/// K2: SHA3-256 byte-identity, 200 rounds including the Keccak rate boundary.
#[test]
fn sha3_256_byte_identical_200_rounds() {
    for round in 0..ROUNDS {
        let data = random_bytes(len_for_round(round));
        let rc: [u8; 32] = Sha3_256::digest(&data).into();
        let lc = AwsLcHash::sha3_256(&data);
        assert_eq!(
            rc,
            lc,
            "sha3-256 mismatch, round {round} len {}",
            data.len()
        );
    }
}

/// K2: canonical published hash vectors on BOTH implementations.
/// SHA-256 vectors are FIPS 180 appendix examples; SHA3-256("abc") is the FIPS 202
/// example value. (Per the packet-040 rule, only certain transcriptions are pinned.)
#[test]
fn canonical_hash_vectors_on_both() {
    let sha256_vectors = [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ];
    for (input, expected_hex) in sha256_vectors {
        let expected = from_hex(expected_hex);
        assert_eq!(
            AwsLcHash::sha256(input).as_slice(),
            expected,
            "awslc sha256"
        );
        let rc: [u8; 32] = Sha256::digest(input).into();
        assert_eq!(rc.as_slice(), expected, "rustcrypto sha256");
    }

    let sha3_expected =
        from_hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    assert_eq!(
        AwsLcHash::sha3_256(b"abc").as_slice(),
        sha3_expected,
        "awslc sha3-256(abc)"
    );
    let rc: [u8; 32] = Sha3_256::digest(b"abc").into();
    assert_eq!(rc.as_slice(), sha3_expected, "rustcrypto sha3-256(abc)");
}

/// K3: HKDF-SHA256 byte-identity, 200 rounds over Some/None salt and output lengths.
#[test]
fn hkdf_sha256_byte_identical_200_rounds() {
    for round in 0..ROUNDS {
        let salt_bytes = random_bytes((round % 48) + 1);
        let salt = if round % 3 == 0 {
            None
        } else {
            Some(salt_bytes.as_slice())
        };
        let ikm = random_bytes((round % 80) + 1);
        let info = random_bytes(round % 100);
        let okm_len = (round % 64) + 1;

        let mut lc_okm = vec![0u8; okm_len];
        AwsLcHkdfSha256::derive(salt, &ikm, &info, &mut lc_okm).expect("awslc hkdf");

        let rc = Hkdf::<Sha256>::new(salt, &ikm);
        let mut rc_okm = vec![0u8; okm_len];
        rc.expand(&info, &mut rc_okm).expect("rustcrypto hkdf");

        assert_eq!(
            rc_okm,
            lc_okm,
            "hkdf mismatch, round {round} (salt={}, okm_len={okm_len})",
            salt.is_some()
        );
    }
}

/// K3: RFC 5869 Test Case 1 on BOTH implementations.
/// IKM = 0x0b * 22, salt = 0x000102..0c, info = 0xf0f1..f9, L = 42.
#[test]
fn rfc5869_test_case_1_on_both() {
    let ikm = [0x0bu8; 22];
    let salt = from_hex("000102030405060708090a0b0c");
    let info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    let expected = from_hex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );

    let mut lc_okm = vec![0u8; 42];
    AwsLcHkdfSha256::derive(Some(&salt), &ikm, &info, &mut lc_okm).expect("awslc hkdf");
    assert_eq!(lc_okm, expected, "awslc vs RFC 5869 TC1");

    let rc = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut rc_okm = vec![0u8; 42];
    rc.expand(&info, &mut rc_okm).expect("rustcrypto hkdf");
    assert_eq!(rc_okm, expected, "rustcrypto vs RFC 5869 TC1");
}

/// K3: the exact `wire_v2::derive_key` construction through AWS-LC components.
///
/// `derive_key` computes `salt = SHA-256(EXTRACT_SALT_LABEL)` then
/// `HKDF-SHA256(salt, shared_secret).expand(transcript, 32)`. Reproducing it here
/// entirely from AWS-LC primitives and matching the RustCrypto pipeline byte-for-byte
/// is the direct evidence that the 043 backend swap cannot move the envelope key.
#[test]
fn wire_v2_derive_key_shape_identical() {
    const EXTRACT_SALT_LABEL: &[u8] = b"citadel-envelope-v2/extract-salt";
    for round in 0..50 {
        let shared_secret = random_bytes(64 + (round % 17));
        let transcript = random_bytes(200 + round);

        // AWS-LC pipeline.
        let lc_salt = AwsLcHash::sha256(EXTRACT_SALT_LABEL);
        let mut lc_key = [0u8; 32];
        AwsLcHkdfSha256::derive(Some(&lc_salt), &shared_secret, &transcript, &mut lc_key)
            .expect("awslc derive");

        // RustCrypto pipeline (the shipped derive_key body).
        let rc_salt = Sha256::digest(EXTRACT_SALT_LABEL);
        let rc = Hkdf::<Sha256>::new(Some(rc_salt.as_slice()), &shared_secret);
        let mut rc_key = [0u8; 32];
        rc.expand(&transcript, &mut rc_key)
            .expect("rustcrypto derive");

        assert_eq!(rc_key, lc_key, "derive_key shape mismatch, round {round}");
    }
}
