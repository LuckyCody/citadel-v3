// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test vector generator for Citadel Envelope
//!
//! Generates real round-trip test vectors (envelope v2, suite 0xA3) with actual
//! keys and ciphertexts through the public `Citadel` API.
//!
//! Run from a UTF-8 shell (bash; a PowerShell `>` redirect writes UTF-16):
//! `cargo run -p citadel-envelope --example generate_vectors > test_vectors.json`

use citadel_envelope::wire::{
    KEM_CIPHERTEXT_BYTES, KEM_PUBLIC_KEY_BYTES, KEM_SECRET_KEY_BYTES, NONCE_BYTES,
};
use citadel_envelope::{Aad, Citadel, Context, PublicKey, SecretKey, MIN_ENVELOPE_V2_BYTES};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let citadel = Citadel::new();

    println!("{{");
    println!("  \"spec_version\": \"2.0.0\",");
    println!("  \"generator\": \"citadel-envelope test vector generator\",");
    println!("  \"generated_at\": \"{}\",", chrono_lite());

    // Constants verification
    println!("  \"constants\": {{");
    println!("    \"KEM_CT_BYTES\": {},", KEM_CIPHERTEXT_BYTES);
    println!("    \"NONCE_BYTES\": {},", NONCE_BYTES);
    println!("    \"MIN_ENVELOPE_V2_BYTES\": {},", MIN_ENVELOPE_V2_BYTES);
    println!("    \"PUBLIC_KEY_BYTES\": {},", KEM_PUBLIC_KEY_BYTES);
    println!("    \"SECRET_KEY_BYTES\": {}", KEM_SECRET_KEY_BYTES);
    println!("  }},");

    // Generate primary keypair
    let (pk, sk) = citadel.generate_keypair();

    println!("  \"primary_keypair\": {{");
    println!("    \"public_key\": \"{}\",", hex(&pk.to_bytes()));
    println!("    \"secret_key\": \"{}\",", hex(&sk.to_bytes()));
    println!("    \"public_key_bytes\": {},", pk.to_bytes().len());
    println!("    \"secret_key_bytes\": {}", sk.to_bytes().len());
    println!("  }},");

    println!("  \"test_vectors\": [");

    // Test vector 1: Basic roundtrip
    generate_basic_roundtrip(&citadel, &pk, &sk);
    println!(",");

    // Test vector 2: With AAD
    generate_with_aad(&citadel, &pk, &sk);
    println!(",");

    // Test vector 3: With context
    generate_with_context(&citadel, &pk, &sk);
    println!(",");

    // Test vector 4: Empty plaintext
    generate_empty_plaintext(&citadel, &pk, &sk);
    println!(",");

    // Test vector 5: With both AAD and context
    generate_full(&citadel, &pk, &sk);

    println!("  ]");
    println!("}}");
}

fn chrono_lite() -> String {
    // Simple timestamp without external dependency
    "2026-09-02T00:00:00Z".to_string()
}

fn roundtrip(
    citadel: &Citadel,
    pk: &PublicKey,
    sk: &SecretKey,
    plaintext: &[u8],
    aad: &[u8],
    context: &[u8],
) -> Vec<u8> {
    let aad = Aad::raw(aad);
    let context = Context::raw(context);
    let ciphertext = citadel.seal(pk, plaintext, &aad, &context).unwrap();
    let decrypted = citadel.open(sk, &ciphertext, &aad, &context).unwrap();
    assert_eq!(decrypted, plaintext, "Roundtrip failed!");
    ciphertext
}

fn generate_basic_roundtrip(citadel: &Citadel, pk: &PublicKey, sk: &SecretKey) {
    let plaintext = b"Hello, World!";
    let ciphertext = roundtrip(citadel, pk, sk, plaintext, b"", b"");

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

fn generate_with_aad(citadel: &Citadel, pk: &PublicKey, sk: &SecretKey) {
    let plaintext = b"Secret message";
    let aad = b"metadata:user=alice";
    let ciphertext = roundtrip(citadel, pk, sk, plaintext, aad, b"");

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

fn generate_with_context(citadel: &Citadel, pk: &PublicKey, sk: &SecretKey) {
    let plaintext = b"Context-bound data";
    let context = b"myapp.v1";
    let ciphertext = roundtrip(citadel, pk, sk, plaintext, b"", context);

    println!("    {{");
    println!("      \"name\": \"with_context\",");
    println!(
        "      \"description\": \"Encryption with application context for domain separation\","
    );
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

fn generate_empty_plaintext(citadel: &Citadel, pk: &PublicKey, sk: &SecretKey) {
    let aad = b"aad for empty";
    let context = b"ctx";
    let ciphertext = roundtrip(citadel, pk, sk, b"", aad, context);

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

fn generate_full(citadel: &Citadel, pk: &PublicKey, sk: &SecretKey) {
    let plaintext = b"Full test with all parameters";
    let aad = b"application/json";
    let context = b"citadel-test-v1";
    let ciphertext = roundtrip(citadel, pk, sk, plaintext, aad, context);

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
