// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Integration tests for the Citadel V3 stream format (stream_v3.rs).
//!
//! Validates security properties required by the V3 specification:
//! - CTDL magic + version byte
//! - Authenticated header (header_tag)
//! - 16-byte stream_id
//! - HKDF-derived per-chunk nonces
//! - HMAC-SHA256 final tag covering full stream

use citadel_envelope::{
    stream_v3::{
        decrypt_stream_v3, encrypt_stream_v3, EncryptedStreamV3, StreamV3Decryptor,
        StreamV3Encryptor, STREAM_V3_FLAGS, STREAM_V3_HEADER_BYTES, STREAM_V3_MAGIC,
        STREAM_V3_SUITE_AEAD, STREAM_V3_SUITE_KEM, STREAM_V3_VERSION,
    },
    Aad, Citadel, Context, PublicKey, SecretKey,
};

fn setup() -> (PublicKey, SecretKey) {
    let cit = Citadel::new();
    cit.generate_keypair()
}

fn aad() -> Aad {
    Aad::raw(b"v3-test-aad")
}
fn ctx() -> Context {
    Context::raw(b"v3-test-context")
}

// ---------------------------------------------------------------------------
// Header format tests
// ---------------------------------------------------------------------------

#[test]
fn v3_header_has_ctdl_magic() {
    let (pk, _sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header();
    assert_eq!(
        &header[..4],
        STREAM_V3_MAGIC,
        "first 4 bytes must be b\"CTDL\""
    );
}

#[test]
fn v3_header_has_correct_version() {
    let (pk, _sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    assert_eq!(
        enc.header()[4],
        STREAM_V3_VERSION,
        "version byte must be 0x03"
    );
}

#[test]
fn v3_header_has_fixed_flags_and_suites() {
    let (pk, _sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header();

    assert_eq!(
        header[5], STREAM_V3_FLAGS,
        "flags byte must be fixed/reserved"
    );
    assert_eq!(header[6], STREAM_V3_SUITE_KEM, "KEM suite must be fixed");
    assert_eq!(header[7], STREAM_V3_SUITE_AEAD, "AEAD suite must be fixed");
}

#[test]
fn v3_header_length_is_correct() {
    let (pk, _sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    assert_eq!(enc.header().len(), STREAM_V3_HEADER_BYTES);
}

#[test]
fn v3_stream_id_is_16_bytes_and_unique() {
    let (pk, _sk) = setup();
    let enc1 = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let enc2 = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    assert_eq!(enc1.stream_id().len(), 16);
    assert_ne!(
        enc1.stream_id(),
        enc2.stream_id(),
        "each stream must have a unique stream_id"
    );
}

// ---------------------------------------------------------------------------
// Roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn v3_single_chunk_roundtrip() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let chunk = enc.encrypt_chunk(b"hello v3", true, &aad()).unwrap();
    let final_tag = enc.final_tag().unwrap();

    let (mut dec, parsed) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    assert_eq!(parsed.version, 0x03);
    let (pt, done) = dec.decrypt_chunk(&chunk, &aad()).unwrap();
    assert!(done);
    assert_eq!(pt, b"hello v3");
    dec.verify_final_tag(&final_tag)
        .expect("final tag must verify");
}

#[test]
fn v3_multi_chunk_roundtrip() {
    let (pk, sk) = setup();
    let chunks_data: &[&[u8]] = &[b"chunk-one", b"chunk-two", b"chunk-three"];

    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let mut encoded: Vec<Vec<u8>> = Vec::new();
    for (i, data) in chunks_data.iter().enumerate() {
        let is_final = i == chunks_data.len() - 1;
        encoded.push(enc.encrypt_chunk(data, is_final, &aad()).unwrap());
    }
    let final_tag = enc.final_tag().unwrap();
    assert_eq!(enc.chunk_count(), 3);

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    for (i, chunk) in encoded.iter().enumerate() {
        let (pt, done) = dec.decrypt_chunk(chunk, &aad()).unwrap();
        assert_eq!(pt, chunks_data[i]);
        assert_eq!(done, i == chunks_data.len() - 1);
    }
    dec.verify_final_tag(&final_tag)
        .expect("final tag must verify");
}

#[test]
fn v3_empty_plaintext_chunk() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let chunk = enc.encrypt_chunk(b"", true, &aad()).unwrap();
    let final_tag = enc.final_tag().unwrap();

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    let (pt, done) = dec.decrypt_chunk(&chunk, &aad()).unwrap();
    assert!(done);
    assert!(pt.is_empty());
    dec.verify_final_tag(&final_tag).unwrap();
}

// ---------------------------------------------------------------------------
// Security rejection tests
// ---------------------------------------------------------------------------

#[test]
fn v3_wrong_key_rejected() {
    let (pk, _sk) = setup();
    let (_pk2, sk2) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let _ = enc.encrypt_chunk(b"secret", true, &aad()).unwrap();

    let result = StreamV3Decryptor::from_header(&sk2, &header, &aad(), &ctx());
    assert!(
        result.is_err(),
        "wrong key must be rejected at header decapsulation"
    );
}

#[test]
fn v3_tampered_header_tag_rejected() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let mut header = enc.header().to_vec();
    let _ = enc.encrypt_chunk(b"data", true, &aad()).unwrap();

    // Flip a byte in the header_tag (last 16 bytes of header)
    let tag_start = header.len() - 16;
    header[tag_start] ^= 0xFF;

    let result = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx());
    assert!(result.is_err(), "tampered header_tag must be rejected");
}

#[test]
fn v3_nonzero_flags_rejected() {
    let (pk, sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let mut header = enc.header().to_vec();

    header[5] ^= 0x01;

    let result = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx());
    assert!(result.is_err(), "nonzero/reserved flags must be rejected");
}

#[test]
fn v3_wrong_kem_suite_rejected() {
    let (pk, sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let mut header = enc.header().to_vec();

    header[6] ^= 0x01;

    let result = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx());
    assert!(result.is_err(), "wrong KEM suite must be rejected");
}

#[test]
fn v3_wrong_aead_suite_rejected() {
    let (pk, sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let mut header = enc.header().to_vec();

    header[7] ^= 0x01;

    let result = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx());
    assert!(result.is_err(), "wrong AEAD suite must be rejected");
}

#[test]
fn v3_tampered_chunk_rejected() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let mut chunk = enc.encrypt_chunk(b"important data", true, &aad()).unwrap();
    let _final_tag = enc.final_tag().unwrap();

    // Flip a byte in the AEAD ciphertext region
    let mid = chunk.len() / 2;
    chunk[mid] ^= 0x5A;

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    let result = dec.decrypt_chunk(&chunk, &aad());
    assert!(
        result.is_err(),
        "tampered chunk ciphertext must be rejected by GCM"
    );
}

#[test]
fn v3_wrong_aad_rejected() {
    let (pk, sk) = setup();
    let wrong_aad = Aad::raw(b"attacker-controlled-aad");
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let chunk = enc.encrypt_chunk(b"secret", true, &aad()).unwrap();
    let _final_tag = enc.final_tag().unwrap();

    // Decrypt succeeds with correct header but chunk decryption must fail with wrong AAD
    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    let result = dec.decrypt_chunk(&chunk, &wrong_aad);
    assert!(result.is_err(), "wrong AAD must be rejected by chunk GCM");
}

#[test]
fn v3_out_of_order_chunk_rejected() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let _c0 = enc.encrypt_chunk(b"first", false, &aad()).unwrap();
    let c1 = enc.encrypt_chunk(b"second", true, &aad()).unwrap();
    let _ft = enc.final_tag().unwrap();

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    // Deliver chunks out of order (c1 before c0)
    let result = dec.decrypt_chunk(&c1, &aad());
    assert!(result.is_err(), "out-of-order chunk must be rejected");
}

#[test]
fn v3_tampered_final_tag_rejected() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let chunk = enc.encrypt_chunk(b"data", true, &aad()).unwrap();
    let mut final_tag = enc.final_tag().unwrap();

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    let (_, done) = dec.decrypt_chunk(&chunk, &aad()).unwrap();
    assert!(done);

    // Corrupt the final tag
    final_tag[0] ^= 0xFF;
    let result = dec.verify_final_tag(&final_tag);
    assert!(result.is_err(), "tampered final_tag must be rejected");
}

#[test]
fn v3_encrypt_after_finalization_rejected() {
    let (pk, _sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    enc.encrypt_chunk(b"last", true, &aad()).unwrap();
    assert!(enc.is_finalized());
    let result = enc.encrypt_chunk(b"extra", false, &aad());
    assert!(result.is_err(), "encrypt after finalization must error");
}

#[test]
fn v3_final_tag_before_finalization_rejected() {
    let (pk, _sk) = setup();
    let enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    // final_tag() without any finalized chunk must error
    let result = enc.final_tag();
    assert!(result.is_err(), "final_tag before finalization must error");
}

#[test]
fn v3_different_context_produces_different_stream_key() {
    let (pk, sk) = setup();
    let ctx2 = Context::raw(b"totally-different-context");
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let _chunk = enc.encrypt_chunk(b"secret", true, &aad()).unwrap();
    let _ft = enc.final_tag().unwrap();

    // Context is bound into the stream key and header key derivation.
    // A wrong context produces a different header_key → header_tag verification fails
    // → from_header returns Err, making the stream undecipherable without the correct context.
    let result = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx2);
    assert!(
        result.is_err(),
        "wrong context must be rejected at header verification"
    );
}

// ─── P065: Scale and correctness-at-scale tests ──────────────────────────────

#[test]
fn stream_v3_ten_thousand_chunks() {
    // Verifies seq counter doesn't overflow/corrupt across 10,000 chunks,
    // and that final_tag covers the correct total chunk count.
    let (pk, sk) = setup();
    let aad = aad();
    let ctx = ctx();
    const N: u64 = 10_000;

    let mut enc = StreamV3Encryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();

    let mut enc_chunks = Vec::with_capacity(N as usize);
    for i in 0..N {
        let is_final = i == N - 1;
        // 1 byte per chunk — tests the seq counter exhaustively
        let pt = [(i & 0xFF) as u8];
        enc_chunks.push(enc.encrypt_chunk(&pt, is_final, &aad).unwrap());
    }
    assert_eq!(
        enc.chunk_count(),
        N,
        "chunk_count must equal N after encryption"
    );
    let final_tag = enc.final_tag().unwrap();

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    for (i, ct) in enc_chunks.iter().enumerate() {
        let (pt, is_final) = dec.decrypt_chunk(ct, &aad).unwrap();
        assert_eq!(
            pt,
            &[(i as u64 & 0xFF) as u8],
            "chunk {i} plaintext mismatch"
        );
        if i as u64 == N - 1 {
            assert!(is_final, "last chunk must be marked final");
        }
    }
    assert_eq!(dec.chunks_received(), N);
    dec.verify_final_tag(&final_tag)
        .expect("final_tag must verify after 10,000 chunks");
}

#[test]
fn stream_v3_large_payload() {
    // 100 chunks × 512 KB = ~50 MB simulated stream.
    // Verifies no memory corruption, correct roundtrip, and final tag.
    let (pk, sk) = setup();
    let aad = aad();
    let ctx = ctx();
    const CHUNKS: usize = 100;
    const CHUNK_SIZE: usize = 512 * 1024; // 512 KB

    // Generate deterministic payload (avoids huge allocation of random bytes).
    let plaintext_chunk: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i ^ 0xA5) as u8).collect();

    let mut enc = StreamV3Encryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let mut enc_chunks = Vec::with_capacity(CHUNKS);
    for i in 0..CHUNKS {
        let is_final = i == CHUNKS - 1;
        enc_chunks.push(enc.encrypt_chunk(&plaintext_chunk, is_final, &aad).unwrap());
    }
    let final_tag = enc.final_tag().unwrap();

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    for (i, ct) in enc_chunks.iter().enumerate() {
        let (pt, is_final) = dec.decrypt_chunk(ct, &aad).unwrap();
        assert_eq!(pt, plaintext_chunk, "chunk {i} roundtrip failed");
        if i == CHUNKS - 1 {
            assert!(is_final);
        }
    }
    dec.verify_final_tag(&final_tag)
        .expect("final_tag must verify after large payload");
}

#[test]
fn stream_v3_missing_final_chunk_detected() {
    // Encrypt 3 chunks (chunk 2 is final). Decrypt only chunks 0 and 1.
    // Attempt to verify_final_tag with chunk 0+1 only — must return Err because
    // the decryptor's total_chunks_received != encryptor's total_chunks.
    let (pk, sk) = setup();
    let aad = aad();
    let ctx = ctx();

    let mut enc = StreamV3Encryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let chunk0 = enc.encrypt_chunk(b"first", false, &aad).unwrap();
    let chunk1 = enc.encrypt_chunk(b"second", false, &aad).unwrap();
    let _chunk2 = enc.encrypt_chunk(b"third (final)", true, &aad).unwrap();
    let final_tag = enc.final_tag().unwrap(); // covers 3 chunks

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    dec.decrypt_chunk(&chunk0, &aad).unwrap();
    dec.decrypt_chunk(&chunk1, &aad).unwrap();
    // Receive 2 chunks, then try to verify the tag that covers 3.
    // The HMAC input includes total_chunks[8BE], so this must fail.
    let result = dec.verify_final_tag(&final_tag);
    assert!(
        result.is_err(),
        "verify_final_tag must fail when the final chunk is missing (total_chunks mismatch)"
    );
}

#[test]
fn stream_v3_tampered_sequence_number_rejected() {
    // Flip the sequence number bytes in a chunk — must be caught by AEAD because
    // the seq is included in the per-chunk AAD which is authenticated.
    let (pk, sk) = setup();
    let aad = aad();
    let ctx = ctx();

    let mut enc = StreamV3Encryptor::new(&pk, &aad, &ctx).unwrap();
    let header = enc.header().to_vec();
    let mut chunk = enc.encrypt_chunk(b"data", true, &aad).unwrap();

    // Flip the seq bytes (first 8 bytes of the chunk frame).
    chunk[3] ^= 0xFF;

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
    let result = dec.decrypt_chunk(&chunk, &aad);
    // Either the seq check (wrong seq number) or AEAD auth fails.
    assert!(result.is_err(), "tampered sequence number must be rejected");
}

// ---------------------------------------------------------------------------
// P067 — Missing adversarial tests from the required matrix
// ---------------------------------------------------------------------------

/// P067 — Duplicate chunk: replaying an already-consumed chunk must be rejected.
///
/// After chunk seq=0 is successfully decrypted, the decryptor advances its
/// expected sequence to 1. Re-delivering chunk seq=0 (exact same bytes)
/// must be rejected because the expected seq no longer matches.
#[test]
fn v3_duplicate_chunk_rejected() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let chunk0 = enc.encrypt_chunk(b"chunk-zero", false, &aad()).unwrap();
    let chunk1 = enc.encrypt_chunk(b"chunk-one", true, &aad()).unwrap();
    let _ft = enc.final_tag().unwrap();

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();

    // Decrypt chunk0 once (succeeds).
    let (pt, done) = dec.decrypt_chunk(&chunk0, &aad()).unwrap();
    assert_eq!(pt, b"chunk-zero");
    assert!(!done);

    // Re-deliver chunk0 (duplicate replay) — must fail because expected seq is now 1.
    let result = dec.decrypt_chunk(&chunk0, &aad());
    assert!(
        result.is_err(),
        "duplicate/replayed chunk must be rejected (expected seq 1, got seq 0 again)"
    );

    // Verify chunk1 is still valid (decryptor state is defined after rejection).
    // Note: after a failed decrypt, the decryptor does NOT advance the seq counter
    // (the tampered chunk was rejected before state mutation). Deliver the real chunk1.
    let result2 = dec.decrypt_chunk(&chunk1, &aad());
    assert!(
        result2.is_ok(),
        "legitimate chunk after duplicate must succeed: {:?}",
        result2
    );
}

/// P067 — Cross-stream chunk injection: a valid chunk from stream A injected
/// into stream B at the same sequence position must be rejected.
///
/// Both streams use the same recipient keypair, so the KEM output is the
/// same structural type. However:
/// - Stream A's chunk nonce = HKDF(streamA_key, "citadel-v3-nonce|seq=0")
/// - Stream B's chunk nonce = HKDF(streamB_key, "citadel-v3-nonce|seq=0")
///   Because streamA_key ≠ streamB_key (different KEM shared secrets and
///   different stream_ids), the nonces differ → AEAD auth fails.
#[test]
fn v3_cross_stream_chunk_injection_rejected() {
    let (pk, sk) = setup();

    // Encrypt a chunk in stream A.
    let mut enc_a = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header_a = enc_a.header().to_vec();
    let chunk_a0 = enc_a.encrypt_chunk(b"stream-A data", true, &aad()).unwrap();
    let _ft_a = enc_a.final_tag().unwrap();

    // Set up stream B with the same key but independent KEM encapsulation.
    let mut enc_b = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header_b = enc_b.header().to_vec();
    let _chunk_b0 = enc_b.encrypt_chunk(b"stream-B data", true, &aad()).unwrap();
    let _ft_b = enc_b.final_tag().unwrap();

    // Stream A's stream_id must differ from B's (each stream is independent).
    assert_ne!(
        enc_a.stream_id(),
        enc_b.stream_id(),
        "each stream must have a unique stream_id"
    );

    // Open stream B's header successfully.
    let (mut dec_b, _) = StreamV3Decryptor::from_header(&sk, &header_b, &aad(), &ctx()).unwrap();

    // Inject chunk_a0 (from stream A) into stream B's decryptor.
    // Must fail: chunk_a0 was encrypted with stream A's key and nonce,
    // which differ from stream B's key and nonce for seq=0.
    let result = dec_b.decrypt_chunk(&chunk_a0, &aad());
    assert!(
        result.is_err(),
        "chunk from stream A injected into stream B must be rejected by AEAD authentication"
    );
    drop(header_a); // suppress unused warning
}

/// P067 — Deleted middle chunk: skipping chunk N and delivering chunk N+1
/// must be rejected because the expected sequence number does not match.
///
/// If the decryptor expects seq=1 but receives a chunk with seq=2, it must
/// reject the delivery (the seq is authenticated — tampering with seq bytes
/// is also rejected, tested separately in v3_tampered_sequence_number_rejected).
#[test]
fn v3_deleted_middle_chunk_rejected() {
    let (pk, sk) = setup();
    let mut enc = StreamV3Encryptor::new(&pk, &aad(), &ctx()).unwrap();
    let header = enc.header().to_vec();
    let _chunk0 = enc.encrypt_chunk(b"first", false, &aad()).unwrap();
    let chunk1 = enc.encrypt_chunk(b"second", false, &aad()).unwrap();
    let chunk2 = enc.encrypt_chunk(b"third (final)", true, &aad()).unwrap();
    let _ft = enc.final_tag().unwrap();

    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();

    // Skip chunk0 entirely. Deliver chunk1 (seq=1) as the first chunk to the decryptor.
    // The decryptor expects seq=0 next; receiving seq=1 must be rejected.
    let result = dec.decrypt_chunk(&chunk1, &aad());
    assert!(
        result.is_err(),
        "skipping chunk 0 and delivering chunk 1 first must be rejected \
         (seq mismatch: expected 0, got 1)"
    );

    drop(chunk2); // suppress unused warning
}

// ---------------------------------------------------------------------------
// High-level truncation-safe API (encrypt_stream_v3 / decrypt_stream_v3)
// ---------------------------------------------------------------------------

#[test]
fn hl_stream_roundtrip() {
    let (pk, sk) = setup();
    let parts: [&[u8]; 3] = [b"alpha", b"bravo", b"charlie-final"];
    let EncryptedStreamV3 {
        header,
        frames,
        final_tag,
    } = encrypt_stream_v3(&pk, &parts, &aad(), &ctx()).expect("encrypt");
    let frame_refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let pt =
        decrypt_stream_v3(&sk, &header, &frame_refs, &final_tag, &aad(), &ctx()).expect("decrypt");
    assert_eq!(pt, b"alphabravocharlie-final");
}

#[test]
fn hl_stream_truncation_rejected() {
    // The whole point: a dropped tail (missing final chunk) MUST be rejected by the
    // high-level API, with no separate finalize call required from the caller.
    let (pk, sk) = setup();
    let parts: [&[u8]; 3] = [b"one", b"two", b"three-final"];
    let EncryptedStreamV3 {
        header,
        frames,
        final_tag,
    } = encrypt_stream_v3(&pk, &parts, &aad(), &ctx()).expect("encrypt");

    // Attacker delivers only the first two frames (drops the final chunk).
    let truncated: Vec<&[u8]> = frames[..2].iter().map(|f| f.as_slice()).collect();
    let r = decrypt_stream_v3(&sk, &header, &truncated, &final_tag, &aad(), &ctx());
    assert!(
        r.is_err(),
        "high-level decrypt must reject a truncated stream (missing final chunk)"
    );
}

#[test]
fn hl_stream_tampered_final_tag_rejected() {
    let (pk, sk) = setup();
    let parts: [&[u8]; 2] = [b"data", b"more-final"];
    let EncryptedStreamV3 {
        header,
        frames,
        mut final_tag,
    } = encrypt_stream_v3(&pk, &parts, &aad(), &ctx()).expect("encrypt");
    final_tag[0] ^= 0xFF;
    let frame_refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let r = decrypt_stream_v3(&sk, &header, &frame_refs, &final_tag, &aad(), &ctx());
    assert!(r.is_err(), "tampered final tag must be rejected");
}

#[test]
fn hl_stream_extra_chunk_after_final_rejected() {
    // Append an extra (valid-looking) frame after the final chunk: the last supplied
    // frame is not the encoder's final, so the API must reject.
    let (pk, sk) = setup();
    let parts: [&[u8]; 2] = [b"x", b"y-final"];
    let EncryptedStreamV3 {
        header,
        frames,
        final_tag,
    } = encrypt_stream_v3(&pk, &parts, &aad(), &ctx()).expect("encrypt");
    // Duplicate the final frame so a non-final/na frame trails the sequence.
    let mut refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    refs.push(frames[1].as_slice()); // extra frame after final
    let r = decrypt_stream_v3(&sk, &header, &refs, &final_tag, &aad(), &ctx());
    assert!(r.is_err(), "a chunk after the final one must be rejected");
}

// Part B: the consuming finish() is the safe terminal for the low-level API; a stream
// missing its final chunk must be rejected by finish() (truncation detection).
#[test]
fn hl_finish_rejects_truncated_low_level() {
    let (pk, sk) = setup();
    let parts: [&[u8]; 3] = [b"a", b"b", b"c-final"];
    let EncryptedStreamV3 {
        header,
        frames,
        final_tag,
    } = encrypt_stream_v3(&pk, &parts, &aad(), &ctx()).unwrap();
    let (mut dec, _) = StreamV3Decryptor::from_header(&sk, &header, &aad(), &ctx()).unwrap();
    // Feed only the first two chunks (final chunk dropped), then finalize.
    dec.decrypt_chunk(frames[0].as_slice(), &aad()).unwrap();
    dec.decrypt_chunk(frames[1].as_slice(), &aad()).unwrap();
    assert!(
        dec.finish(&final_tag).is_err(),
        "finish() must reject a stream whose final chunk was never received"
    );
}

#[test]
fn hl_stream_single_chunk_roundtrip() {
    let (pk, sk) = setup();
    let parts: [&[u8]; 1] = [b"only-chunk"];
    let EncryptedStreamV3 {
        header,
        frames,
        final_tag,
    } = encrypt_stream_v3(&pk, &parts, &aad(), &ctx()).expect("encrypt");
    let frame_refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let pt =
        decrypt_stream_v3(&sk, &header, &frame_refs, &final_tag, &aad(), &ctx()).expect("decrypt");
    assert_eq!(pt, b"only-chunk");
}
