// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
use citadel_envelope::wire::{
    KEM_CIPHERTEXT_BYTES, MIN_CIPHERTEXT_BYTES, SUITE_AEAD_AES256GCM,
    SUITE_KEM_HYBRID_X25519_MLKEM768,
};
use citadel_envelope::{Aad, Citadel, Context, OpenError, PublicKey, SecretKey};

fn setup() -> (Citadel, PublicKey, SecretKey) {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();
    (cit, pk, sk)
}

#[test]
fn roundtrip_basic() {
    let (cit, pk, sk) = setup();
    let plaintext = b"hello post-quantum world";
    let aad = Aad::raw(b"test-aad");
    let ctx = Context::raw(b"test-context");

    let ct = cit.seal(&pk, plaintext, &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(&pt, plaintext);
}

#[test]
fn roundtrip_empty_plaintext() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"", &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn roundtrip_large_plaintext() {
    let (cit, pk, sk) = setup();
    let plaintext = vec![0xABu8; 65536];
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn wrong_aad_fails() {
    let (cit, pk, sk) = setup();
    let ctx = Context::raw(b"ctx");
    let ct = cit
        .seal(&pk, b"data", &Aad::raw(b"good-aad"), &ctx)
        .unwrap();
    let result = cit.open(&sk, &ct, &Aad::raw(b"bad-aad"), &ctx);
    assert_eq!(result, Err(OpenError));
}

#[test]
fn wrong_context_fails() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ct = cit
        .seal(&pk, b"data", &aad, &Context::raw(b"good-ctx"))
        .unwrap();
    let result = cit.open(&sk, &ct, &aad, &Context::raw(b"bad-ctx"));
    assert_eq!(result, Err(OpenError));
}

#[test]
fn wrong_key_fails() {
    let (cit, pk, _sk) = setup();
    let (_, _, sk2) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    let result = cit.open(&sk2, &ct, &aad, &ctx);
    assert_eq!(result, Err(OpenError));
}

#[test]
fn header_version_check() {
    let (cit, pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    assert_eq!(&ct[..4], b"CTD2");
    assert_eq!(ct[4], 2);
    assert_eq!(ct[5], 0);
    assert_eq!(ct[6], SUITE_KEM_HYBRID_X25519_MLKEM768);
    assert_eq!(ct[8], SUITE_AEAD_AES256GCM);
    let kem_ct_len = u16::from_be_bytes([ct[12], ct[13]]);
    assert_eq!(kem_ct_len as usize, KEM_CIPHERTEXT_BYTES);
}

#[test]
fn ciphertext_minimum_size() {
    let (cit, pk, _sk) = setup();
    let ct = cit
        .seal(&pk, b"", &Aad::empty(), &Context::empty())
        .unwrap();
    assert!(ct.len() >= MIN_CIPHERTEXT_BYTES);
}

#[test]
fn tamper_version_fails() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let mut ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    ct[0] = 0xFF;
    assert_eq!(cit.open(&sk, &ct, &aad, &ctx), Err(OpenError));
}

#[test]
fn tamper_suite_kem_fails() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let mut ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    ct[6] = 0xA2; // old ML-KEM-only suite ID
    assert_eq!(cit.open(&sk, &ct, &aad, &ctx), Err(OpenError));
}

#[test]
fn tamper_kem_ciphertext_fails() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let mut ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    ct[98 + 10] ^= 0x01;
    assert_eq!(cit.open(&sk, &ct, &aad, &ctx), Err(OpenError));
}

#[test]
fn tamper_nonce_fails() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let mut ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    let nonce_offset = 86;
    ct[nonce_offset] ^= 0x01;
    assert_eq!(cit.open(&sk, &ct, &aad, &ctx), Err(OpenError));
}

#[test]
fn tamper_aead_ciphertext_fails() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let mut ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert_eq!(cit.open(&sk, &ct, &aad, &ctx), Err(OpenError));
}

#[test]
fn truncated_fails() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();
    assert_eq!(cit.open(&sk, &ct[..10], &aad, &ctx), Err(OpenError));
    assert_eq!(cit.open(&sk, b"short", &aad, &ctx), Err(OpenError));
    assert_eq!(cit.open(&sk, b"", &aad, &ctx), Err(OpenError));
}

#[test]
fn all_errors_are_uniform() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();

    let err1 = cit.open(&sk, &ct, &Aad::raw(b"bad"), &ctx).unwrap_err();
    let err2 = cit.open(&sk, &ct, &aad, &Context::raw(b"bad")).unwrap_err();
    let err3 = cit.open(&sk, b"short", &aad, &ctx).unwrap_err();

    let mut tampered = ct.clone();
    tampered[98] ^= 0x01;
    let err4 = cit.open(&sk, &tampered, &aad, &ctx).unwrap_err();

    // All errors must be identical
    assert_eq!(err1, err2);
    assert_eq!(err2, err3);
    assert_eq!(err3, err4);
    assert_eq!(format!("{}", err1), "decryption failed");
}

#[test]
fn key_serialization_roundtrip() {
    let (cit, pk, sk) = setup();
    let plaintext = b"key serialization test";

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    let pk2 = PublicKey::from_bytes(&pk_bytes).unwrap();
    let sk2 = SecretKey::from_bytes(&sk_bytes).unwrap();

    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk2, plaintext, &aad, &ctx).unwrap();
    let pt = cit.open(&sk2, &ct, &aad, &ctx).unwrap();
    assert_eq!(&pt, plaintext);
}
