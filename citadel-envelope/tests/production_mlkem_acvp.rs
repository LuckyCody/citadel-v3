// SPDX-License-Identifier: AGPL-3.0-or-later
//! Final FIPS 203 ACVP vectors executed through Citadel's selected release provider.
//!
//! The deterministic entry points are compiled only with `kat`; normal production
//! key generation and encapsulation always obtain fresh system randomness.

use citadel_envelope::{HybridX25519MlKem768Provider, KemProvider, PublicKey, SecretKey};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(serde::Deserialize)]
struct Vectors {
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
    serde_json::from_str(include_str!("acvp_mlkem768_vectors.json")).unwrap()
}

#[test]
fn selected_provider_keygen_matches_all_25_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.keygen.len(), 25);

    for vector in vectors.keygen {
        let d: [u8; 32] = from_hex(&vector.d).try_into().unwrap();
        let z: [u8; 32] = from_hex(&vector.z).try_into().unwrap();
        let expected_ek = from_hex(&vector.ek);
        let expected_dk = from_hex(&vector.dk);
        let (ek, dk) = HybridX25519MlKem768Provider::kat_mlkem_keygen(d, z);
        assert_eq!(ek.as_slice(), expected_ek, "keygen ek tc{}", vector.tc_id);
        assert_eq!(dk.as_slice(), expected_dk, "keygen dk tc{}", vector.tc_id);
    }
}

#[test]
fn selected_provider_encapsulation_matches_all_25_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.encap.len(), 25);

    for vector in vectors.encap {
        let ek: [u8; 1184] = from_hex(&vector.ek).try_into().unwrap();
        let m: [u8; 32] = from_hex(&vector.m).try_into().unwrap();
        let expected_ct = from_hex(&vector.c);
        let expected_ss = from_hex(&vector.k);
        let (ct, ss) = HybridX25519MlKem768Provider::kat_mlkem_encapsulate(&ek, m).unwrap();
        assert_eq!(ct.as_slice(), expected_ct, "encap ct tc{}", vector.tc_id);
        assert_eq!(ss.as_slice(), expected_ss, "encap ss tc{}", vector.tc_id);
    }
}

#[test]
fn selected_provider_decapsulation_matches_all_10_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.decap.len(), 10);

    for vector in vectors.decap {
        let dk: [u8; 2400] = from_hex(&vector.dk).try_into().unwrap();
        let ct: [u8; 1088] = from_hex(&vector.c).try_into().unwrap();
        let expected_ss = from_hex(&vector.k);
        let ss = HybridX25519MlKem768Provider::kat_mlkem_decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss.as_slice(), expected_ss, "decap ss tc{}", vector.tc_id);
    }
}

#[test]
fn selected_provider_passes_10_000_randomized_round_trips() {
    for iteration in 0..10_000 {
        let (pk, sk) = HybridX25519MlKem768Provider::keygen();
        let (send, ct) = HybridX25519MlKem768Provider::encapsulate(&pk)
            .unwrap_or_else(|_| panic!("encapsulation failed at {iteration}"));
        let recv = HybridX25519MlKem768Provider::decapsulate(&sk, &ct)
            .unwrap_or_else(|_| panic!("decapsulation failed at {iteration}"));
        assert_eq!(send.as_slice(), recv.as_slice(), "round trip {iteration}");
    }
}

#[test]
fn selected_provider_rejects_malformed_lengths_and_wrong_keys() {
    let (pk, _sk) = HybridX25519MlKem768Provider::keygen();
    let (_other_pk, other_sk) = HybridX25519MlKem768Provider::keygen();
    let (send, ct) = HybridX25519MlKem768Provider::encapsulate(&pk).unwrap();
    let wrong = HybridX25519MlKem768Provider::decapsulate(&other_sk, &ct).unwrap();
    assert_ne!(send.as_slice(), wrong.as_slice());
    assert!(HybridX25519MlKem768Provider::decapsulate(&other_sk, &ct[..ct.len() - 1]).is_err());

    assert!(PublicKey::from_bytes(&[0u8; 1215]).is_err());
    assert!(SecretKey::from_bytes(&[0u8; 2431]).is_err());
}

#[test]
fn selected_provider_validates_public_and_expanded_secret_keys() {
    let (pk, sk) = HybridX25519MlKem768Provider::keygen();

    // FIPS 203 encapsulation-key modulus check: encode coefficient q=3329,
    // which lies outside the allowed [0, q-1] range.
    let mut bad_pk = pk.to_bytes();
    bad_pk[32] = 0x01;
    bad_pk[33] = (bad_pk[33] & 0xF0) | 0x0D;
    assert!(PublicKey::from_bytes(&bad_pk).is_err());

    // The expanded key contains H(ek). Corrupting that field must fail import.
    let mut bad_sk = sk.to_bytes();
    let hash_offset = 32 + 1152 + 1184;
    bad_sk[hash_offset] ^= 1;
    assert!(SecretKey::from_bytes(&bad_sk).is_err());
}

#[test]
fn selected_provider_matches_independent_libcrux_on_all_60_vectors() {
    use libcrux_ml_kem::mlkem768;

    let vectors = vectors();
    for vector in vectors.keygen {
        let d: [u8; 32] = from_hex(&vector.d).try_into().unwrap();
        let z: [u8; 32] = from_hex(&vector.z).try_into().unwrap();
        let (selected_ek, selected_dk) = HybridX25519MlKem768Provider::kat_mlkem_keygen(d, z);
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);
        let independent = mlkem768::generate_key_pair(seed);
        assert_eq!(selected_ek.as_slice(), independent.pk().as_slice());
        assert_eq!(selected_dk.as_slice(), independent.sk().as_slice());
    }

    for vector in vectors.encap {
        let ek: [u8; 1184] = from_hex(&vector.ek).try_into().unwrap();
        let m: [u8; 32] = from_hex(&vector.m).try_into().unwrap();
        let (selected_ct, selected_ss) =
            HybridX25519MlKem768Provider::kat_mlkem_encapsulate(&ek, m).unwrap();
        let independent_ek = mlkem768::MlKem768PublicKey::from(ek);
        let (independent_ct, independent_ss) = mlkem768::encapsulate(&independent_ek, m);
        assert_eq!(selected_ct.as_slice(), independent_ct.as_ref());
        assert_eq!(selected_ss.as_slice(), independent_ss.as_ref());
    }

    for vector in vectors.decap {
        let dk: [u8; 2400] = from_hex(&vector.dk).try_into().unwrap();
        let ct: [u8; 1088] = from_hex(&vector.c).try_into().unwrap();
        let selected = HybridX25519MlKem768Provider::kat_mlkem_decapsulate(&dk, &ct).unwrap();
        let independent_dk = mlkem768::MlKem768PrivateKey::from(dk);
        let independent_ct = mlkem768::MlKem768Ciphertext::from(ct);
        let independent = mlkem768::decapsulate(&independent_dk, &independent_ct);
        assert_eq!(selected.as_slice(), independent.as_ref());
    }
}
