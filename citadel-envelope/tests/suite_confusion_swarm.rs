// SPDX-License-Identifier: AGPL-3.0-or-later
use citadel_envelope::{Aad, Citadel, Context};

#[test]
fn red_suite_byte_flipped_to_unsupported_is_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    let mut envelope = pristine.clone();
    envelope[6] = 0xA4;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "unsupported suite byte 0xA4 was accepted"
    );
}

#[test]
fn red_reserved_suite_bytes_are_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    for bad in [0xA5u8, 0xA6] {
        let mut envelope = pristine.clone();
        envelope[6] = bad;
        assert!(
            citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
            "reserved suite byte {bad:#04x} was accepted"
        );
    }
}

#[test]
fn red_unknown_suite_bytes_are_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    for bad in [0x00u8, 0x01, 0xA2, 0xB1, 0xFF] {
        let mut envelope = pristine.clone();
        envelope[6] = bad;
        assert!(
            citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
            "unknown suite byte {bad:#04x} was accepted"
        );
    }
}

#[test]
fn red_every_non_a3_suite_byte_is_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    for suite_byte in 0..=255 {
        if suite_byte == 0xA3 {
            continue;
        }
        let mut envelope = pristine.clone();
        envelope[6] = suite_byte;
        assert!(
            citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
            "non-A3 suite byte {suite_byte:#04x} was accepted"
        );
    }

    // Verify A3 still works
    let mut envelope = pristine.clone();
    envelope[6] = 0xA3;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_ok(),
        "valid suite byte 0xA3 was rejected"
    );
}

#[test]
fn red_kem_ct_len_field_mismatch_is_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    for bad_len in [1119u16, 1121, 0, 65535] {
        let mut envelope = pristine.clone();
        envelope[12..14].copy_from_slice(&bad_len.to_be_bytes());
        assert!(
            citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
            "kem_ciphertext length {bad_len} was accepted"
        );
    }
}

#[test]
fn red_truncated_envelope_is_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    for cut in [1, 16, 100] {
        let mut envelope = pristine.clone();
        envelope.truncate(envelope.len() - cut);
        assert!(
            citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
            "truncated by {cut}"
        );
    }
}

#[test]
fn red_padded_envelope_is_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    for pad in [1, 16, 1120] {
        let mut envelope = pristine.clone();
        envelope.extend(std::iter::repeat(0u8).take(pad));
        assert!(
            citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
            "padded by {pad}"
        );
    }
}

#[test]
fn red_declared_plaintext_len_mismatch_is_rejected() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    let actual_len = b"secret".len() as u64;

    for bad_len in [0u64, 1, actual_len + 1] {
        let mut envelope = pristine.clone();
        envelope[14..22].copy_from_slice(&bad_len.to_be_bytes());
        assert!(
            citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
            "declared plaintext length {bad_len} was accepted"
        );
    }
}

#[test]
fn red_header_fixed_fields_are_rejected_when_altered() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object-id", 1);
    let ctx = Context::for_application("myapp", "prod");
    let pristine = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();

    let mut envelope = pristine.clone();
    envelope[0] ^= 1;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "magic byte was altered"
    );

    let mut envelope = pristine.clone();
    envelope[4] ^= 1;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "version byte was altered"
    );

    let mut envelope = pristine.clone();
    envelope[5] ^= 1;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "flags byte was altered"
    );

    let mut envelope = pristine.clone();
    envelope[7] ^= 1;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "kdf id byte was altered"
    );

    let mut envelope = pristine.clone();
    envelope[8] ^= 1;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "aead id byte was altered"
    );

    let mut envelope = pristine.clone();
    envelope[9] ^= 1;
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "reserved zero byte was altered"
    );

    let mut envelope = pristine.clone();
    envelope[10..12].copy_from_slice(&u16::to_be_bytes(97));
    assert!(
        citadel.open(&sk, &envelope, &aad, &ctx).is_err(),
        "header length field was altered"
    );
}
