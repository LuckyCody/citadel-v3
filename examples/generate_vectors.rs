// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test vector generator for Citadel Envelope
//!
//! Generates real test vectors with actual keys and ciphertexts.
//! Run with: `cargo run --release --example generate_vectors > test_vectors_real.json`

use citadel_envelope::{
    HybridEnvelope, HybridPublicKey, HybridSecretKey,
    MAX_AAD_BYTES, MAX_CONTEXT_BYTES,
};
use citadel_envelope::hybrid::{HYBRID_PUBLIC_KEY_BYTES, HYBRID_SECRET_KEY_BYTES, HYBRID_CIPHERTEXT_BYTES};
use citadel_envelope::hybrid_wire::{
    HEADER_BYTES, NONCE_BYTES, MIN_HYBRID_CIPHERTEXT_BYTES,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let envelope = HybridEnvelope::new();
    
    println!("{{");
    println!("  \"spec_version\": \"1.0.0\",");
    println!("  \"generator\": \"citadel-envelope test vector generator\",");
    println!("  \"generated_at\": \"{}\",", chrono_lite());
    
    // Constants verification
    println!("  \"constants\": {{");
    println!("    \"HEADER_BYTES\": {},", HEADER_BYTES);
    println!("    \"HYBRID_KEM_CT_BYTES\": {},", HYBRID_CIPHERTEXT_BYTES);
    println!("    \"NONCE_BYTES\": {},", NONCE_BYTES);
    println!("    \"MIN_CIPHERTEXT_BYTES\": {},", MIN_HYBRID_CIPHERTEXT_BYTES);
    println!("    \"PUBLIC_KEY_BYTES\": {},", HYBRID_PUBLIC_KEY_BYTES);
    println!("    \"SECRET_KEY_BYTES\": {},", HYBRID_SECRET_KEY_BYTES);
    println!("    \"MAX_AAD_BYTES\": {},", MAX_AAD_BYTES);
    println!("    \"MAX_CONTEXT_BYTES\": {}", MAX_CONTEXT_BYTES);
    println!("  }},");
    
    // Generate primary keypair
    let (pk, sk) = envelope.keygen();
    
    println!("  \"primary_keypair\": {{");
    println!("    \"public_key\": \"{}\",", hex(&pk.to_bytes()));
    println!("    \"secret_key\": \"{}\",", hex(&*sk.to_bytes()));
    println!("    \"public_key_bytes\": {},", pk.to_bytes().len());
    println!("    \"secret_key_bytes\": {}", sk.to_bytes().len());
    println!("  }},");
    
    println!("  \"test_vectors\": [");
    
    // Test vector 1: Basic roundtrip
    generate_basic_roundtrip(&envelope, &pk, &sk);
    println!(",");
    
    // Test vector 2: With AAD
    generate_with_aad(&envelope, &pk, &sk);
    println!(",");
    
    // Test vector 3: With context
    generate_with_context(&envelope, &pk, &sk);
    println!(",");
    
    // Test vector 4: Empty plaintext
    generate_empty_plaintext(&envelope, &pk, &sk);
    println!(",");
    
    // Test vector 5: With both AAD and context
    generate_full(&envelope, &pk, &sk);
    
    println!("  ]");
    println!("}}");
}

fn chrono_lite() -> String {
    // Simple timestamp without external dependency
    "2026-01-28T00:00:00Z".to_string()
}

fn generate_basic_roundtrip(envelope: &HybridEnvelope, pk: &HybridPublicKey, sk: &HybridSecretKey) {
    let plaintext = b"Hello, World!";
    let aad = b"";
    let context = b"";
    
    let ciphertext = envelope.encrypt(pk, plaintext, aad, context).unwrap();
    let decrypted = envelope.decrypt(sk, &ciphertext, aad, context).unwrap();
    
    assert_eq!(decrypted, plaintext, "Roundtrip failed!");
    
    println!("    {{");
    println!("      \"name\": \"basic_roundtrip\",");
    println!("      \"description\": \"Basic encryption/decryption with no AAD or context\",");
    println!("      \"plaintext\": \"{}\",", hex(plaintext));
    println!("      \"plaintext_ascii\": \"Hello, World!\",");
    println!("      \"aad\": \"\",");
    println!("      \"context\": \"\",");
    println!("      \"ciphertext\": \"{}\",", hex(&ciphertext));
    println!("      \"ciphertext_bytes\": {},", ciphertext.len());
    println!("      \"expected\": \"success\"");
    print!("    }}");
}

fn generate_with_aad(envelope: &HybridEnvelope, pk: &HybridPublicKey, sk: &HybridSecretKey) {
    let plaintext = b"Secret message";
    let aad = b"metadata:user=alice";
    let context = b"";
    
    let ciphertext = envelope.encrypt(pk, plaintext, aad, context).unwrap();
    let decrypted = envelope.decrypt(sk, &ciphertext, aad, context).unwrap();
    
    assert_eq!(decrypted, plaintext, "Roundtrip failed!");
    
    println!("    {{");
    println!("      \"name\": \"with_aad\",");
    println!("      \"description\": \"Encryption with additional authenticated data\",");
    println!("      \"plaintext\": \"{}\",", hex(plaintext));
    println!("      \"plaintext_ascii\": \"Secret message\",");
    println!("      \"aad\": \"{}\",", hex(aad));
    println!("      \"aad_ascii\": \"metadata:user=alice\",");
    println!("      \"context\": \"\",");
    println!("      \"ciphertext\": \"{}\",", hex(&ciphertext));
    println!("      \"ciphertext_bytes\": {},", ciphertext.len());
    println!("      \"expected\": \"success\"");
    print!("    }}");
}

fn generate_with_context(envelope: &HybridEnvelope, pk: &HybridPublicKey, sk: &HybridSecretKey) {
    let plaintext = b"Context-bound data";
    let aad = b"";
    let context = b"myapp.v1";
    
    let ciphertext = envelope.encrypt(pk, plaintext, aad, context).unwrap();
    let decrypted = envelope.decrypt(sk, &ciphertext, aad, context).unwrap();
    
    assert_eq!(decrypted, plaintext, "Roundtrip failed!");
    
    println!("    {{");
    println!("      \"name\": \"with_context\",");
    println!("      \"description\": \"Encryption with application context for domain separation\",");
    println!("      \"plaintext\": \"{}\",", hex(plaintext));
    println!("      \"plaintext_ascii\": \"Context-bound data\",");
    println!("      \"aad\": \"\",");
    println!("      \"context\": \"{}\",", hex(context));
    println!("      \"context_ascii\": \"myapp.v1\",");
    println!("      \"ciphertext\": \"{}\",", hex(&ciphertext));
    println!("      \"ciphertext_bytes\": {},", ciphertext.len());
    println!("      \"expected\": \"success\"");
    print!("    }}");
}

fn generate_empty_plaintext(envelope: &HybridEnvelope, pk: &HybridPublicKey, sk: &HybridSecretKey) {
    let plaintext = b"";
    let aad = b"aad for empty";
    let context = b"ctx";
    
    let ciphertext = envelope.encrypt(pk, plaintext, aad, context).unwrap();
    let decrypted = envelope.decrypt(sk, &ciphertext, aad, context).unwrap();
    
    assert!(decrypted.is_empty(), "Roundtrip failed!");
    
    println!("    {{");
    println!("      \"name\": \"empty_plaintext\",");
    println!("      \"description\": \"Valid edge case: encrypting empty plaintext\",");
    println!("      \"plaintext\": \"\",");
    println!("      \"aad\": \"{}\",", hex(aad));
    println!("      \"context\": \"{}\",", hex(context));
    println!("      \"ciphertext\": \"{}\",", hex(&ciphertext));
    println!("      \"ciphertext_bytes\": {},", ciphertext.len());
    println!("      \"expected\": \"success\"");
    print!("    }}");
}

fn generate_full(envelope: &HybridEnvelope, pk: &HybridPublicKey, sk: &HybridSecretKey) {
    let plaintext = b"Full test with all parameters";
    let aad = b"application/json";
    let context = b"citadel-test-v1";
    
    let ciphertext = envelope.encrypt(pk, plaintext, aad, context).unwrap();
    let decrypted = envelope.decrypt(sk, &ciphertext, aad, context).unwrap();
    
    assert_eq!(decrypted, plaintext, "Roundtrip failed!");
    
    println!("    {{");
    println!("      \"name\": \"full_parameters\",");
    println!("      \"description\": \"Encryption with both AAD and context\",");
    println!("      \"plaintext\": \"{}\",", hex(plaintext));
    println!("      \"plaintext_ascii\": \"Full test with all parameters\",");
    println!("      \"aad\": \"{}\",", hex(aad));
    println!("      \"aad_ascii\": \"application/json\",");
    println!("      \"context\": \"{}\",", hex(context));
    println!("      \"context_ascii\": \"citadel-test-v1\",");
    println!("      \"ciphertext\": \"{}\",", hex(&ciphertext));
    println!("      \"ciphertext_bytes\": {},", ciphertext.len());
    println!("      \"expected\": \"success\"");
    print!("    }}");
}
