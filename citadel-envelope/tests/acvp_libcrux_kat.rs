// SPDX-License-Identifier: AGPL-3.0-or-later
//! NIST ACVP ML-KEM-768 Known Answer Tests via libcrux (dev-only provider).
//!
//! PQClean (production provider) does not expose deterministic seed-based
//! keygen or encapsulate APIs, so full ACVP vector validation is not possible
//! through the production path. libcrux (dev dependency) exposes these APIs,
//! and since both implement the same FIPS 203 ML-KEM-768 algorithm, passing
//! ACVP vectors through libcrux validates algorithmic correctness.
//!
//! Vectors sourced from NIST ACVP Server repository:
//!   https://github.com/usnistgov/ACVP-Server
//!
//! Coverage: 25 keygen + 25 encapsulation + 10 decapsulation = 60 vectors.

use libcrux_ml_kem::mlkem768;

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

fn load_vectors() -> Vectors {
    let json = include_str!("acvp_mlkem768_vectors.json");
    serde_json::from_str(json).expect("failed to parse ACVP vectors")
}

#[test]
fn acvp_keygen_25_vectors() {
    let vectors = load_vectors();
    assert_eq!(vectors.keygen.len(), 25, "expected 25 keygen vectors");

    for v in &vectors.keygen {
        let d = from_hex(&v.d);
        let z = from_hex(&v.z);
        let expected_ek = from_hex(&v.ek);
        let expected_dk = from_hex(&v.dk);

        // libcrux seed = d[32] || z[32] = 64 bytes
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);

        let keypair = mlkem768::generate_key_pair(seed);
        let (dk, ek) = keypair.into_parts();

        let ek_bytes = ek.as_slice();
        let dk_bytes = dk.as_slice();

        assert_eq!(
            ek_bytes, &expected_ek[..],
            "ACVP keygen tc{}: encapsulation key mismatch",
            v.tc_id
        );
        assert_eq!(
            dk_bytes, &expected_dk[..],
            "ACVP keygen tc{}: decapsulation key mismatch",
            v.tc_id
        );
    }
}

#[test]
fn acvp_encap_25_vectors() {
    let vectors = load_vectors();
    assert_eq!(vectors.encap.len(), 25, "expected 25 encap vectors");

    for v in &vectors.encap {
        let ek_bytes = from_hex(&v.ek);
        let m = from_hex(&v.m);
        let expected_ct = from_hex(&v.c);
        let expected_ss = from_hex(&v.k);

        let ek_arr: [u8; 1184] = ek_bytes.try_into().expect("ek must be 1184 bytes");
        let ek = mlkem768::MlKem768PublicKey::from(ek_arr);

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&m);

        let (ct, ss) = mlkem768::encapsulate(&ek, seed);

        assert_eq!(
            ct.as_ref(),
            &expected_ct[..],
            "ACVP encap tc{}: ciphertext mismatch",
            v.tc_id
        );
        assert_eq!(
            ss.as_ref(),
            &expected_ss[..],
            "ACVP encap tc{}: shared secret mismatch",
            v.tc_id
        );
    }
}

#[test]
fn acvp_decap_10_vectors() {
    let vectors = load_vectors();
    assert_eq!(vectors.decap.len(), 10, "expected 10 decap vectors");

    for v in &vectors.decap {
        let dk_bytes = from_hex(&v.dk);
        let ct_bytes = from_hex(&v.c);
        let expected_ss = from_hex(&v.k);

        let dk_arr: [u8; 2400] = dk_bytes.try_into().expect("dk must be 2400 bytes");
        let ct_arr: [u8; 1088] = ct_bytes.try_into().expect("ct must be 1088 bytes");

        let dk = mlkem768::MlKem768PrivateKey::from(dk_arr);
        let ct = mlkem768::MlKem768Ciphertext::from(ct_arr);

        let ss = mlkem768::decapsulate(&dk, &ct);

        assert_eq!(
            ss.as_ref(),
            &expected_ss[..],
            "ACVP decap tc{}: shared secret mismatch",
            v.tc_id
        );
    }
}
