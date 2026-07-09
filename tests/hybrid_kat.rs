// SPDX-License-Identifier: AGPL-3.0-or-later
//! Comprehensive tests for the X25519 + ML-KEM-768 hybrid envelope
//!
//! This test suite covers:
//! - Basic functionality (roundtrip, key serialization)
//! - Wire format validation
//! - Constraint enforcement (AAD, context, plaintext limits)
//! - Bitflip resistance across all ciphertext regions
//! - Uniform error behavior (no oracle)
//! - Edge cases and negative tests

use citadel_envelope::{
    HybridEnvelope, HybridPublicKey, HybridSecretKey,
    DecryptionError,
    MAX_AAD_BYTES, MAX_CONTEXT_BYTES,
};
use citadel_envelope::hybrid::{
    HYBRID_PUBLIC_KEY_BYTES, HYBRID_SECRET_KEY_BYTES, HYBRID_CIPHERTEXT_BYTES,
};
use citadel_envelope::hybrid_wire::{
    MIN_HYBRID_CIPHERTEXT_BYTES, SUITE_KEM_HYBRID, SUITE_AEAD_AES256GCM,
    PROTOCOL_VERSION, decode_hybrid_wire,
};

// ============================================================================
// Basic Functionality
// ============================================================================

#[test]
fn test_basic_roundtrip() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let plaintext = b"Hello, post-quantum world!";
    let aad = b"authenticated data";
    let context = b"test-context";

    let ciphertext = envelope.encrypt(&pk, plaintext, aad, context).unwrap();
    let decrypted = envelope.decrypt(&sk, &ciphertext, aad, context).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_empty_plaintext() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"", b"", b"").unwrap();
    assert_eq!(ct.len(), MIN_HYBRID_CIPHERTEXT_BYTES);

    let pt = envelope.decrypt(&sk, &ct, b"", b"").unwrap();
    assert!(pt.is_empty());
}

#[test]
fn test_empty_context_allowed() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    // Empty context is explicitly allowed per spec
    let ct = envelope.encrypt(&pk, b"test", b"aad", b"").unwrap();
    let pt = envelope.decrypt(&sk, &ct, b"aad", b"").unwrap();
    assert_eq!(pt, b"test");
}

// ============================================================================
// Key Serialization
// ============================================================================

#[test]
fn test_hybrid_constants() {
    assert_eq!(HYBRID_PUBLIC_KEY_BYTES, 32 + 1184); // X25519 + ML-KEM
    assert_eq!(HYBRID_SECRET_KEY_BYTES, 32 + 2400);
    assert_eq!(HYBRID_CIPHERTEXT_BYTES, 32 + 1088);
    assert_eq!(MIN_HYBRID_CIPHERTEXT_BYTES, 6 + 1120 + 12 + 16); // 1154
}

#[test]
fn test_key_serialization_roundtrip() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    // Serialize keys
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    assert_eq!(pk_bytes.len(), HYBRID_PUBLIC_KEY_BYTES);
    assert_eq!(sk_bytes.len(), HYBRID_SECRET_KEY_BYTES);

    // Deserialize
    let pk2 = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
    let sk2 = HybridSecretKey::from_bytes(sk_bytes.as_slice()).unwrap();

    // Test cross-compatibility
    let ct = envelope.encrypt(&pk, b"hello", b"aad", b"ctx").unwrap();
    let pt = envelope.decrypt(&sk2, &ct, b"aad", b"ctx").unwrap();
    assert_eq!(pt, b"hello");

    let ct2 = envelope.encrypt(&pk2, b"world", b"aad", b"ctx").unwrap();
    let pt2 = envelope.decrypt(&sk, &ct2, b"aad", b"ctx").unwrap();
    assert_eq!(pt2, b"world");
}

// ============================================================================
// Wire Format Validation
// ============================================================================

#[test]
fn test_wire_format_structure() {
    let envelope = HybridEnvelope::new();
    let (pk, _sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"test", b"", b"").unwrap();
    let parts = decode_hybrid_wire(&ct).unwrap();

    assert_eq!(parts.version, PROTOCOL_VERSION);
    assert_eq!(parts.suite_kem, SUITE_KEM_HYBRID);
    assert_eq!(parts.suite_aead, SUITE_AEAD_AES256GCM);
    assert_eq!(parts.flags, 0x00);
    assert_eq!(parts.kem_ct_len as usize, HYBRID_CIPHERTEXT_BYTES);
    assert_eq!(parts.kem_ciphertext.len(), 1120);
    assert_eq!(parts.x25519_ciphertext.len(), 32);
    assert_eq!(parts.mlkem_ciphertext.len(), 1088);
    assert_eq!(parts.nonce.len(), 12);
    assert!(parts.aead_ciphertext.len() >= 16);
}

#[test]
fn test_minimum_ciphertext_roundtrip() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    // Empty plaintext = minimum ciphertext
    let ct = envelope.encrypt(&pk, b"", b"", b"").unwrap();
    assert_eq!(ct.len(), MIN_HYBRID_CIPHERTEXT_BYTES);

    let pt = envelope.decrypt(&sk, &ct, b"", b"").unwrap();
    assert!(pt.is_empty());
}

// ============================================================================
// Constraint Enforcement (Encryption)
// ============================================================================

#[test]
fn test_encrypt_rejects_oversized_aad() {
    let envelope = HybridEnvelope::new();
    let (pk, _sk) = envelope.keygen();

    let oversized_aad = vec![0u8; MAX_AAD_BYTES + 1];
    let result = envelope.encrypt(&pk, b"test", &oversized_aad, b"ctx");
    assert!(result.is_err());
}

#[test]
fn test_encrypt_accepts_max_aad() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let max_aad = vec![0u8; MAX_AAD_BYTES];
    let ct = envelope.encrypt(&pk, b"test", &max_aad, b"ctx").unwrap();
    let pt = envelope.decrypt(&sk, &ct, &max_aad, b"ctx").unwrap();
    assert_eq!(pt, b"test");
}

#[test]
fn test_encrypt_rejects_oversized_context() {
    let envelope = HybridEnvelope::new();
    let (pk, _sk) = envelope.keygen();

    let oversized_context = vec![0u8; MAX_CONTEXT_BYTES + 1];
    let result = envelope.encrypt(&pk, b"test", b"aad", &oversized_context);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_accepts_max_context() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let max_context = vec![0u8; MAX_CONTEXT_BYTES];
    let ct = envelope.encrypt(&pk, b"test", b"aad", &max_context).unwrap();
    let pt = envelope.decrypt(&sk, &ct, b"aad", &max_context).unwrap();
    assert_eq!(pt, b"test");
}

// ============================================================================
// Constraint Enforcement (Decryption) - Uniform Errors
// ============================================================================

#[test]
fn test_decrypt_rejects_oversized_aad() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();

    // Attacker tries oversized AAD
    let oversized_aad = vec![0u8; MAX_AAD_BYTES + 1];
    let result = envelope.decrypt(&sk, &ct, &oversized_aad, b"ctx");
    assert!(result.is_err());
}

#[test]
fn test_decrypt_rejects_oversized_context() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();

    // Attacker tries oversized context
    let oversized_context = vec![0u8; MAX_CONTEXT_BYTES + 1];
    let result = envelope.decrypt(&sk, &ct, b"aad", &oversized_context);
    assert!(result.is_err());
}

// ============================================================================
// Bitflip Resistance
// ============================================================================

#[test]
fn test_bitflip_header() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();

    // Flip each byte in header (bytes 0-5)
    for i in 0..6 {
        let mut tampered = ct.clone();
        tampered[i] ^= 0x01;
        assert!(
            envelope.decrypt(&sk, &tampered, b"aad", b"ctx").is_err(),
            "Expected decryption to fail with tampered header byte {}",
            i
        );
    }
}

#[test]
fn test_bitflip_x25519_region() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();

    // Flip each byte in X25519 region (bytes 6-37)
    for i in 6..38 {
        let mut tampered = ct.clone();
        tampered[i] ^= 0x01;
        assert!(
            envelope.decrypt(&sk, &tampered, b"aad", b"ctx").is_err(),
            "Expected decryption to fail with tampered X25519 byte {}",
            i
        );
    }
}

#[test]
fn test_bitflip_mlkem_region() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();

    // Flip some bytes in ML-KEM region (bytes 38-1125)
    // Test first, middle, and last bytes
    for i in [38, 500, 1000, 1125] {
        let mut tampered = ct.clone();
        tampered[i] ^= 0x01;
        assert!(
            envelope.decrypt(&sk, &tampered, b"aad", b"ctx").is_err(),
            "Expected decryption to fail with tampered ML-KEM byte {}",
            i
        );
    }
}

#[test]
fn test_bitflip_nonce() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();

    // Nonce starts at 6 + 1120 = 1126
    let nonce_start = 6 + HYBRID_CIPHERTEXT_BYTES;
    for i in nonce_start..(nonce_start + 12) {
        let mut tampered = ct.clone();
        tampered[i] ^= 0x01;
        assert!(
            envelope.decrypt(&sk, &tampered, b"aad", b"ctx").is_err(),
            "Expected decryption to fail with tampered nonce byte {}",
            i
        );
    }
}

#[test]
fn test_bitflip_aead_tag() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();

    // Tag is the last 16 bytes
    let tag_start = ct.len() - 16;
    for i in tag_start..ct.len() {
        let mut tampered = ct.clone();
        tampered[i] ^= 0x01;
        assert!(
            envelope.decrypt(&sk, &tampered, b"aad", b"ctx").is_err(),
            "Expected decryption to fail with tampered tag byte {}",
            i
        );
    }
}

// ============================================================================
// Uniform Error Behavior (No Oracle)
// ============================================================================

#[test]
fn test_uniform_error_messages() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();

    // Collect different error scenarios
    let errors: Vec<DecryptionError> = vec![
        // Too short
        envelope.decrypt(&sk, b"short", b"", b"").unwrap_err(),
        // Wrong AAD
        envelope.decrypt(&sk, &ct, b"wrong_aad", b"ctx").unwrap_err(),
        // Wrong context
        envelope.decrypt(&sk, &ct, b"aad", b"wrong_ctx").unwrap_err(),
        // Oversized AAD
        envelope
            .decrypt(&sk, &ct, &vec![0u8; MAX_AAD_BYTES + 1], b"ctx")
            .unwrap_err(),
        // Oversized context
        envelope
            .decrypt(&sk, &ct, b"aad", &vec![0u8; MAX_CONTEXT_BYTES + 1])
            .unwrap_err(),
    ];

    // All errors should have the same message (no oracle)
    let first = format!("{}", errors[0]);
    for e in &errors {
        assert_eq!(format!("{}", e), first);
    }
    assert_eq!(first, "decryption failed");
}

#[test]
fn test_all_error_types_uniform() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();

    // Tampered ciphertext
    let mut tampered = ct.clone();
    tampered[50] ^= 0x01;

    // Wrong key
    let (_pk2, sk2) = envelope.keygen();

    let scenarios = [
        ("truncated", envelope.decrypt(&sk, &ct[..100], b"aad", b"ctx")),
        ("wrong_aad", envelope.decrypt(&sk, &ct, b"wrong", b"ctx")),
        ("wrong_ctx", envelope.decrypt(&sk, &ct, b"aad", b"wrong")),
        ("tampered", envelope.decrypt(&sk, &tampered, b"aad", b"ctx")),
        ("wrong_key", envelope.decrypt(&sk2, &ct, b"aad", b"ctx")),
    ];

    for (name, result) in scenarios {
        let err = result.unwrap_err();
        assert_eq!(
            format!("{}", err),
            "decryption failed",
            "Scenario '{}' should produce uniform error",
            name
        );
    }
}

// ============================================================================
// Header Mutations
// ============================================================================

#[test]
fn test_header_mutations() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();

    // Wrong version
    let mut bad = ct.clone();
    bad[0] = 0x99;
    assert!(envelope.decrypt(&sk, &bad, b"aad", b"ctx").is_err());

    // Wrong KEM suite
    let mut bad = ct.clone();
    bad[1] = 0xA2; // ML-KEM only
    assert!(envelope.decrypt(&sk, &bad, b"aad", b"ctx").is_err());

    // Wrong AEAD suite
    let mut bad = ct.clone();
    bad[2] = 0x99;
    assert!(envelope.decrypt(&sk, &bad, b"aad", b"ctx").is_err());

    // Non-zero flags
    let mut bad = ct.clone();
    bad[3] = 0x01;
    assert!(envelope.decrypt(&sk, &bad, b"aad", b"ctx").is_err());
}

// ============================================================================
// Truncation Attacks
// ============================================================================

#[test]
fn test_truncation_attacks() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();

    // Various truncation lengths
    for len in [0, 1, 5, 6, 100, 500, 1000, MIN_HYBRID_CIPHERTEXT_BYTES - 1] {
        let truncated = &ct[..len.min(ct.len())];
        assert!(
            envelope.decrypt(&sk, truncated, b"aad", b"ctx").is_err(),
            "Expected decryption to fail with length {}",
            len
        );
    }
}

// ============================================================================
// Cross-Key Rejection
// ============================================================================

#[test]
fn test_cross_key_rejection() {
    let envelope = HybridEnvelope::new();
    let (pk1, sk1) = envelope.keygen();
    let (pk2, sk2) = envelope.keygen();

    // Encrypt to pk1
    let ct = envelope.encrypt(&pk1, b"secret", b"aad", b"ctx").unwrap();

    // Should decrypt with sk1
    let pt = envelope.decrypt(&sk1, &ct, b"aad", b"ctx").unwrap();
    assert_eq!(pt, b"secret");

    // Should fail with sk2
    assert!(envelope.decrypt(&sk2, &ct, b"aad", b"ctx").is_err());
}

// ============================================================================
// Randomization
// ============================================================================

#[test]
fn test_distinct_ciphertexts() {
    let envelope = HybridEnvelope::new();
    let (pk, _sk) = envelope.keygen();

    // Same plaintext should produce different ciphertexts
    let ct1 = envelope.encrypt(&pk, b"same", b"aad", b"ctx").unwrap();
    let ct2 = envelope.encrypt(&pk, b"same", b"aad", b"ctx").unwrap();

    assert_ne!(ct1, ct2, "Ciphertexts should be randomized");
}

// ============================================================================
// AAD and Context Binding
// ============================================================================

#[test]
fn test_aad_context_binding() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.encrypt(&pk, b"secret", b"aad1", b"ctx1").unwrap();

    // Correct AAD and context
    let pt = envelope.decrypt(&sk, &ct, b"aad1", b"ctx1").unwrap();
    assert_eq!(pt, b"secret");

    // Wrong AAD
    assert!(envelope.decrypt(&sk, &ct, b"aad2", b"ctx1").is_err());

    // Wrong context
    assert!(envelope.decrypt(&sk, &ct, b"aad1", b"ctx2").is_err());

    // Both wrong
    assert!(envelope.decrypt(&sk, &ct, b"aad2", b"ctx2").is_err());
}

// ============================================================================
// Seal/Open Aliases
// ============================================================================

#[test]
fn test_seal_open_aliases() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    let ct = envelope.seal(&pk, b"test", b"aad", b"ctx").unwrap();
    let pt = envelope.open(&sk, &ct, b"aad", b"ctx").unwrap();

    assert_eq!(pt, b"test");
}

// ============================================================================
// Large Data
// ============================================================================

#[test]
fn test_large_plaintext() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    // 1 MB plaintext
    let plaintext = vec![0x42u8; 1024 * 1024];

    let ciphertext = envelope.encrypt(&pk, &plaintext, b"aad", b"ctx").unwrap();
    let decrypted = envelope.decrypt(&sk, &ciphertext, b"aad", b"ctx").unwrap();

    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// Consistency
// ============================================================================

#[test]
fn test_consistency_multiple_roundtrips() {
    let envelope = HybridEnvelope::new();
    let (pk, sk) = envelope.keygen();

    for i in 0..10 {
        let plaintext = format!("message {}", i).into_bytes();
        let aad = format!("aad {}", i).into_bytes();

        let ct = envelope.encrypt(&pk, &plaintext, &aad, b"ctx").unwrap();
        let pt = envelope.decrypt(&sk, &ct, &aad, b"ctx").unwrap();

        assert_eq!(pt, plaintext);
    }
}
