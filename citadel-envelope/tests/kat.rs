// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Envelope format and error tests. Historical v1 migration has a separate suite.

use citadel_envelope::{inspect, Aad, Citadel, Context, OpenError};

use citadel_envelope::wire::{
    AEAD_TAG_BYTES, HEADER_BYTES, KEM_CIPHERTEXT_BYTES, MIN_CIPHERTEXT_BYTES, NONCE_BYTES,
    SUITE_AEAD_AES256GCM, SUITE_KEM_HYBRID_X25519_MLKEM768,
};

#[test]
fn test_wire_constants() {
    assert_eq!(KEM_CIPHERTEXT_BYTES, 1120);
    assert_eq!(NONCE_BYTES, 12);
    assert_eq!(AEAD_TAG_BYTES, 16);
    assert_eq!(HEADER_BYTES, 6);
    assert_eq!(MIN_CIPHERTEXT_BYTES, 6 + 1120 + 12 + 16);
}

#[test]
fn test_wire_format_structure() {
    let citadel = Citadel::new();
    let (pk, _) = citadel.generate_keypair();

    let ct = citadel
        .seal(&pk, b"test", &Aad::empty(), &Context::empty())
        .unwrap();

    assert!(ct.starts_with(b"CTD2"));
    assert_eq!(ct[4], 2);
    assert_eq!(ct[5], 0);
    assert_eq!(ct[6], SUITE_KEM_HYBRID_X25519_MLKEM768);
    assert_eq!(ct[7], 0xC1);
    assert_eq!(ct[8], SUITE_AEAD_AES256GCM);
    assert_eq!(u16::from_be_bytes([ct[10], ct[11]]), 98);
    assert_eq!(
        u16::from_be_bytes([ct[12], ct[13]]) as usize,
        KEM_CIPHERTEXT_BYTES
    );
    let info = inspect(&ct).unwrap();
    assert_eq!(info.version, 2);
    assert!(!info.streaming);
    assert_eq!(info.plaintext_bytes, 4);
}

#[test]
fn test_minimum_ciphertext_roundtrip() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let ct = citadel
        .seal(&pk, b"", &Aad::empty(), &Context::empty())
        .unwrap();
    assert_eq!(ct.len(), 98 + KEM_CIPHERTEXT_BYTES + AEAD_TAG_BYTES);

    let pt = citadel
        .open(&sk, &ct, &Aad::empty(), &Context::empty())
        .unwrap();
    assert!(pt.is_empty());
}

#[test]
fn test_self_consistency() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    for i in 0..10 {
        let plaintext = format!("msg {}", i).into_bytes();
        let aad = Aad::raw(&format!("aad {}", i).into_bytes());

        let ct = citadel
            .seal(&pk, &plaintext, &aad, &Context::raw(b"ctx"))
            .unwrap();
        let pt = citadel.open(&sk, &ct, &aad, &Context::raw(b"ctx")).unwrap();
        assert_eq!(pt, plaintext);
    }
}

#[test]
fn test_rejects_invalid_version() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let mut ct = citadel
        .seal(&pk, b"test", &Aad::empty(), &Context::empty())
        .unwrap();
    ct[0] = 0x99;
    assert!(citadel
        .open(&sk, &ct, &Aad::empty(), &Context::empty())
        .is_err());
}

#[test]
fn test_uniform_error_messages() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let ct = citadel
        .seal(&pk, b"test", &Aad::raw(b"aad"), &Context::raw(b"ctx"))
        .unwrap();

    let mut ct_bad_suite = ct.clone();
    ct_bad_suite[1] ^= 0x01; // suite_kem byte

    let errors: Vec<OpenError> = vec![
        citadel
            .open(&sk, b"short", &Aad::empty(), &Context::empty())
            .unwrap_err(),
        citadel
            .open(&sk, &ct, &Aad::raw(b"wrong"), &Context::raw(b"ctx"))
            .unwrap_err(),
        citadel
            .open(&sk, &ct, &Aad::raw(b"aad"), &Context::raw(b"wrong"))
            .unwrap_err(),
        citadel
            .open(&sk, &ct_bad_suite, &Aad::raw(b"aad"), &Context::raw(b"ctx"))
            .unwrap_err(),
    ];

    let first = format!("{}", errors[0]);
    for e in errors {
        assert_eq!(format!("{}", e), first);
    }
}
