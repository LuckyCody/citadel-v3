// SPDX-License-Identifier: AGPL-3.0-or-later
//! Known Answer / envelope-only tests (v1 structured wire)

use citadel_envelope::{wire, Aad, Citadel, Context, OpenError};

use citadel_envelope::wire::{
    AEAD_TAG_BYTES, FLAGS_V1, HEADER_BYTES, KEM_CIPHERTEXT_BYTES, MIN_CIPHERTEXT_BYTES,
    NONCE_BYTES, PROTOCOL_VERSION, SUITE_AEAD_AES256GCM, SUITE_KEM_HYBRID_X25519_MLKEM768,
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

    let parts = wire::decode_wire(&ct).unwrap();
    assert_eq!(parts.version, PROTOCOL_VERSION);
    assert_eq!(parts.suite_kem, SUITE_KEM_HYBRID_X25519_MLKEM768);
    assert_eq!(parts.suite_aead, SUITE_AEAD_AES256GCM);
    assert_eq!(parts.flags, FLAGS_V1);
    assert_eq!(parts.kem_ct_len as usize, KEM_CIPHERTEXT_BYTES);
    assert_eq!(parts.kem_ciphertext.len(), 1120);
    assert_eq!(parts.nonce.len(), 12);
    assert!(parts.aead_ciphertext.len() >= 16);
}

#[test]
fn test_minimum_ciphertext_roundtrip() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let ct = citadel
        .seal(&pk, b"", &Aad::empty(), &Context::empty())
        .unwrap();
    assert_eq!(ct.len(), MIN_CIPHERTEXT_BYTES);

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
