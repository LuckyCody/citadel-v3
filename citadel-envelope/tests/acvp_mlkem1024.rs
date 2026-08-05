// SPDX-License-Identifier: CC0-1.0
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! NIST ACVP FIPS 203 ML-KEM-1024 known-answer tests.
//!
//! Source: usnistgov/ACVP-Server commit
//! c924096a71e5d050742e31efa6846d1e2d6fb3bd.

#![cfg(feature = "kat")]
#![allow(deprecated)]

use ml_kem::{
    ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey, ExpandedDecapsulationKey},
    Decapsulate, ExpandedKeyEncoding, KeyExport, Seed,
};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(serde::Deserialize)]
struct Vectors {
    source_commit: String,
    source_urls: Vec<String>,
    algorithm: String,
    revision: String,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    keygen: Vec<KeygenVector>,
    encap: Vec<EncapVector>,
    decap: Vec<DecapVector>,
}

#[derive(serde::Deserialize)]
struct KeygenVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: String,
    z: String,
    ek: String,
    dk: String,
}

#[derive(serde::Deserialize)]
struct EncapVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    ek: String,
    m: String,
    c: String,
    k: String,
}

#[derive(serde::Deserialize)]
struct DecapVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    dk: String,
    c: String,
    k: String,
}

fn vectors() -> Vectors {
    let vectors: Vectors =
        serde_json::from_str(include_str!("acvp_mlkem1024_vectors.json")).unwrap();
    assert_eq!(
        vectors.source_commit,
        "c924096a71e5d050742e31efa6846d1e2d6fb3bd"
    );
    assert_eq!(vectors.source_urls.len(), 4);
    assert!(vectors
        .source_urls
        .iter()
        .all(|url| url.starts_with("https://raw.githubusercontent.com/usnistgov/ACVP-Server/")));
    assert_eq!(vectors.algorithm, "ML-KEM");
    assert_eq!(vectors.revision, "FIPS203");
    assert_eq!(vectors.parameter_set, "ML-KEM-1024");
    vectors
}

#[test]
fn mlkem1024_keygen_matches_all_25_nist_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.keygen.len(), 25);
    for vector in vectors.keygen {
        let d: [u8; 32] = from_hex(&vector.d).try_into().unwrap();
        let z: [u8; 32] = from_hex(&vector.z).try_into().unwrap();
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);
        let dk = DecapsulationKey::from_seed(Seed::from(seed));
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            from_hex(&vector.ek),
            "keygen ek tc{}",
            vector.tc_id
        );
        assert_eq!(
            dk.to_expanded_bytes().as_slice(),
            from_hex(&vector.dk),
            "keygen dk tc{}",
            vector.tc_id
        );
    }
}

#[test]
fn mlkem1024_encapsulation_matches_all_25_nist_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.encap.len(), 25);
    for vector in vectors.encap {
        let ek: [u8; 1568] = from_hex(&vector.ek).try_into().unwrap();
        let m: [u8; 32] = from_hex(&vector.m).try_into().unwrap();
        let ek = EncapsulationKey::new(&ek.into()).unwrap();
        let (ciphertext, shared) = ek.encapsulate_deterministic(&m.into());
        assert_eq!(
            ciphertext.as_ref(),
            from_hex(&vector.c),
            "encap ciphertext tc{}",
            vector.tc_id
        );
        assert_eq!(
            shared.as_ref(),
            from_hex(&vector.k),
            "encap shared secret tc{}",
            vector.tc_id
        );
    }
}

#[test]
fn mlkem1024_decapsulation_matches_all_10_nist_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.decap.len(), 10);
    for vector in vectors.decap {
        let dk: [u8; 3168] = from_hex(&vector.dk).try_into().unwrap();
        let ciphertext: [u8; 1568] = from_hex(&vector.c).try_into().unwrap();
        let dk =
            DecapsulationKey::from_expanded_bytes(&ExpandedDecapsulationKey::from(dk)).unwrap();
        let shared = dk.decapsulate(&Ciphertext::from(ciphertext));
        assert_eq!(
            shared.as_ref(),
            from_hex(&vector.k),
            "decap shared secret tc{}",
            vector.tc_id
        );
    }
}
