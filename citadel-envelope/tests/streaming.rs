// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for streaming authenticated encryption (V2 — P046).

use citadel_envelope::stream::{StreamDecryptor, StreamEncryptor};
use citadel_envelope::{Aad, Citadel, Context, OpenError};

fn setup() -> (citadel_envelope::PublicKey, citadel_envelope::SecretKey) {
    let cit = Citadel::new();
    cit.generate_keypair()
}

#[test]
fn stream_single_chunk_roundtrip() {
    let (pk, sk) = setup();
    let aad = Aad::raw(b"test-aad");
    let ctx = Context::raw(b"test-ctx");

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let chunk = enc
        .encrypt_chunk(b"hello streaming world", true, &aad)
        .unwrap();
    assert!(enc.is_finalized());

    let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    let (pt, done) = dec.decrypt_chunk(&chunk, &aad).unwrap();
    assert!(done);
    assert_eq!(pt, b"hello streaming world");
    assert!(dec.is_done());
}

#[test]
fn stream_multi_chunk_roundtrip() {
    let (pk, sk) = setup();
    let aad = Aad::raw(b"multi-chunk");
    let ctx = Context::raw(b"ctx");

    let chunks_data: &[&[u8]] = &[b"chunk one ", b"chunk two ", b"chunk three"];

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();

    let mut encrypted_chunks = Vec::new();
    let n = chunks_data.len();
    for (i, data) in chunks_data.iter().enumerate() {
        let is_final = i == n - 1;
        let ct = enc.encrypt_chunk(data, is_final, &aad).unwrap();
        encrypted_chunks.push(ct);
    }
    assert!(enc.is_finalized());
    assert_eq!(enc.chunk_count(), n as u32);

    let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    let mut all_plaintext = Vec::new();
    for (i, ct) in encrypted_chunks.iter().enumerate() {
        let (pt, done) = dec.decrypt_chunk(ct, &aad).unwrap();
        all_plaintext.extend_from_slice(&pt);
        let is_last = i == encrypted_chunks.len() - 1;
        assert_eq!(done, is_last);
    }
    assert!(dec.is_done());
    assert_eq!(all_plaintext, b"chunk one chunk two chunk three");
}

#[test]
fn stream_empty_final_chunk() {
    let (pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let c1 = enc.encrypt_chunk(b"data", false, &aad).unwrap();
    let c2 = enc.encrypt_chunk(b"", true, &aad).unwrap(); // Empty final chunk allowed.

    let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    let (pt1, done1) = dec.decrypt_chunk(&c1, &aad).unwrap();
    assert_eq!(pt1, b"data");
    assert!(!done1);
    let (pt2, done2) = dec.decrypt_chunk(&c2, &aad).unwrap();
    assert_eq!(pt2, b"");
    assert!(done2);
}

#[test]
fn stream_wrong_aad_rejected() {
    let (pk, sk) = setup();
    let aad = Aad::raw(b"correct-aad");
    let ctx = Context::raw(b"ctx");

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let chunk = enc.encrypt_chunk(b"data", true, &aad).unwrap();

    let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    let wrong_aad = Aad::raw(b"wrong-aad");
    let result = dec.decrypt_chunk(&chunk, &wrong_aad);
    assert_eq!(result, Err(OpenError));
}

#[test]
fn stream_wrong_key_rejected() {
    let (pk, _sk) = setup();
    let (_, sk2) = setup(); // Different keypair.
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let chunk = enc.encrypt_chunk(b"data", true, &aad).unwrap();

    // from_header with wrong secret key produces a wrong stream_key via KEM.
    // Chunk decryption MUST fail due to wrong AEAD key.
    let mut dec = StreamDecryptor::from_header(&sk2, &header, &aad, &ctx).unwrap();
    let result = dec.decrypt_chunk(&chunk, &aad);
    assert_eq!(
        result,
        Err(OpenError),
        "wrong key should cause AEAD failure on chunk decryption"
    );
}

#[test]
fn stream_reordered_chunks_rejected() {
    let (pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let _c1 = enc.encrypt_chunk(b"first", false, &aad).unwrap();
    let c2 = enc.encrypt_chunk(b"second", true, &aad).unwrap();

    let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    // Deliver c2 before c1 (wrong order).
    let result = dec.decrypt_chunk(&c2, &aad);
    assert_eq!(
        result,
        Err(OpenError),
        "out-of-order chunk should be rejected"
    );
}

#[test]
fn stream_truncation_detected() {
    let (pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let c1 = enc.encrypt_chunk(b"first", false, &aad).unwrap();
    let _c2 = enc.encrypt_chunk(b"second", true, &aad).unwrap(); // Not delivered.

    let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    let (pt1, done1) = dec.decrypt_chunk(&c1, &aad).unwrap();
    assert_eq!(pt1, b"first");
    assert!(!done1);
    // Stream is NOT done — receiver knows there should be more data.
    assert!(
        !dec.is_done(),
        "stream should not be marked done after non-final chunk"
    );
}

#[test]
fn stream_write_after_final_rejected() {
    let (pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let _header = enc.header().to_vec();
    let _ = enc.encrypt_chunk(b"data", true, &aad).unwrap();
    assert!(enc.is_finalized());

    // Second call after final should be rejected.
    let result = enc.encrypt_chunk(b"more", false, &aad);
    assert!(result.is_err(), "encrypt after finalized should fail");
}

#[test]
fn stream_header_version_v2() {
    let (pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header();

    // Version byte must be 0x02.
    assert_eq!(header[0], 0x02, "stream header version should be 0x02");
    // Flags byte must be 0x01 (STREAM flag).
    assert_eq!(header[3], 0x01, "stream header flags should be 0x01");
    // Stream header length.
    assert_eq!(
        header.len(),
        citadel_envelope::wire::STREAM_HEADER_BYTES,
        "stream header should be exactly STREAM_HEADER_BYTES"
    );
}

#[test]
fn stream_header_rejected_by_v1_decoder() {
    use citadel_envelope::wire::decode_wire;

    let (pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header();

    // V1 decoder should reject a stream header (version mismatch / length check).
    let result = decode_wire(header);
    assert!(
        result.is_err(),
        "V1 wire decoder should reject V2 stream header"
    );
}

#[test]
fn inspect_stream_header_succeeds() {
    // inspect() must handle both V1 and V2 stream headers (P049 fix).
    use citadel_envelope::inspect;

    let (pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
    // Pass header + some chunk data so inspect() has >= MIN_CIPHERTEXT_BYTES.
    // Actually inspect() routes on version byte, so just the header is enough
    // since we check version=0x02 first before length requirements.
    let header = enc.header().to_vec();

    let info = inspect(&header).expect("inspect() should succeed on V2 stream header");
    assert_eq!(info.version, 0x02, "version should be 0x02");
    assert!(info.streaming, "streaming flag should be true");
    assert_eq!(info.kem_suite, "X25519+ML-KEM-768");
    assert_eq!(info.aead_suite, "AES-256-GCM");
    assert_eq!(
        info.plaintext_bytes, 0,
        "stream header carries no plaintext info"
    );
}

#[test]
fn inspect_v1_envelope_still_works() {
    // Regression: inspect() must still work correctly on V1 envelopes.
    use citadel_envelope::{inspect, wire::MIN_CIPHERTEXT_BYTES, Citadel};

    let (pk, _sk) = setup();
    let cit = Citadel::new();
    let ct = cit
        .seal(&pk, b"hello", &Aad::raw(b"a"), &Context::raw(b"c"))
        .unwrap();

    let info = inspect(&ct).expect("inspect() should work on V1 envelope");
    assert_eq!(info.version, 0x01);
    assert!(!info.streaming, "V1 envelope should not be streaming");
    assert_eq!(info.kem_suite, "X25519+ML-KEM-768");
    assert!(info.total_bytes >= MIN_CIPHERTEXT_BYTES);
    assert_eq!(info.plaintext_bytes, b"hello".len());
}
