// SPDX-License-Identifier: AGPL-3.0-or-later
//! Citadel Envelope — Interactive Demo
//!
//! Run with: `cargo run --example demo --features std`
//!
//! Walks through the full Citadel API: keygen → seal → open, AAD/context
//! binding, tamper detection, and key/ciphertext size reporting.

use citadel_envelope::{
    wire::{
        AEAD_TAG_BYTES, HEADER_BYTES, KEM_CIPHERTEXT_BYTES, KEM_PUBLIC_KEY_BYTES,
        KEM_SECRET_KEY_BYTES, MIN_CIPHERTEXT_BYTES, NONCE_BYTES, PROTOCOL_VERSION,
        SUITE_AEAD_AES256GCM, SUITE_KEM_HYBRID_X25519_MLKEM768,
    },
    Aad, Citadel, Context, Envelope, HybridX25519MlKem768Provider, KemProvider,
};
use std::time::Instant;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║          Citadel Envelope v1 — Hybrid Post-Quantum Demo        ║");
    println!("║       X25519 + ML-KEM-768 (FIPS 203) + AES-256-GCM            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    demo_parameters();
    demo_keygen();
    demo_roundtrip();
    demo_aad_context_binding();
    demo_tamper_detection();
    demo_envelope_facade();
    demo_payload_scaling();

    println!("\n✓ All demos passed.");
}

// ---------------------------------------------------------------------------

fn section(title: &str) {
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ {:<63} │", title);
    println!("└─────────────────────────────────────────────────────────────────┘");
}

// ---------------------------------------------------------------------------

fn demo_parameters() {
    section("1. Protocol Parameters");

    println!("  Wire format version:  0x{:02X}", PROTOCOL_VERSION);
    println!(
        "  KEM suite:            0x{:02X}  (X25519 + ML-KEM-768 hybrid)",
        SUITE_KEM_HYBRID_X25519_MLKEM768
    );
    println!(
        "  AEAD suite:           0x{:02X}  (AES-256-GCM)",
        SUITE_AEAD_AES256GCM
    );
    println!();
    println!(
        "  Public key size:      {} bytes  (X25519: 32 + ML-KEM-768 ek: 1184)",
        KEM_PUBLIC_KEY_BYTES
    );
    println!(
        "  Secret key size:      {} bytes  (X25519: 32 + ML-KEM-768 dk: 2400)",
        KEM_SECRET_KEY_BYTES
    );
    println!(
        "  KEM ciphertext:       {} bytes  (X25519 ephemeral: 32 + ML-KEM ct: 1088)",
        KEM_CIPHERTEXT_BYTES
    );
    println!(
        "  Header:               {} bytes  (version + suites + flags + kem_ct_len)",
        HEADER_BYTES
    );
    println!("  Nonce:                {} bytes", NONCE_BYTES);
    println!("  AEAD tag:             {} bytes", AEAD_TAG_BYTES);
    println!(
        "  Min ciphertext:       {} bytes  (header + kem_ct + nonce + tag)",
        MIN_CIPHERTEXT_BYTES
    );
    println!();
    println!("  Security model:       Hybrid — security holds if EITHER");
    println!("                        X25519 (classical) OR ML-KEM-768 (PQ)");
    println!("                        remains secure.");
}

fn demo_keygen() {
    section("2. Key Generation");

    let t = Instant::now();
    let (pk, sk) = HybridX25519MlKem768Provider::keygen();
    let elapsed = t.elapsed();

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    println!("  Generated hybrid keypair in {:?}", elapsed);
    println!(
        "  Public key:  {} bytes  (first 16: {}…)",
        pk_bytes.len(),
        hex_prefix(&pk_bytes, 16)
    );
    println!(
        "  Secret key:  {} bytes  (first 16: {}…)",
        sk_bytes.len(),
        hex_prefix(&sk_bytes, 16)
    );

    // Roundtrip serialization
    let pk2 = citadel_envelope::PublicKey::from_bytes(&pk_bytes).expect("pk roundtrip");
    let sk2 = citadel_envelope::SecretKey::from_bytes(&sk_bytes).expect("sk roundtrip");
    assert_eq!(pk2.to_bytes(), pk_bytes);
    assert_eq!(sk2.to_bytes(), sk_bytes);
    println!("  Key serialization roundtrip: ✓");
}

fn demo_roundtrip() {
    section("3. Encrypt → Decrypt Roundtrip");

    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let plaintext = b"Hello from Citadel! This message is post-quantum secured.";
    let aad = Aad::raw(b"demo-aad");
    let context = Context::raw(b"demo-context");

    // Encrypt
    let t = Instant::now();
    let ciphertext = citadel.seal(&pk, plaintext, &aad, &context).unwrap();
    let enc_time = t.elapsed();

    println!(
        "  Plaintext:    {} bytes  \"{}\"",
        plaintext.len(),
        String::from_utf8_lossy(plaintext)
    );
    println!("  AAD:          \"demo-aad\"");
    println!("  Context:      \"demo-context\"");
    println!(
        "  Ciphertext:   {} bytes  (overhead: {} bytes)",
        ciphertext.len(),
        ciphertext.len() - plaintext.len()
    );
    println!("  Encrypt time: {:?}", enc_time);

    // Decrypt
    let t = Instant::now();
    let recovered = citadel.open(&sk, &ciphertext, &aad, &context).unwrap();
    let dec_time = t.elapsed();

    assert_eq!(recovered, plaintext);
    println!("  Decrypt time: {:?}", dec_time);
    println!("  Roundtrip:    ✓  plaintext matches");
}

fn demo_aad_context_binding() {
    section("4. AAD & Context Binding (Misuse Resistance)");

    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let plaintext = b"sensitive payload";
    let aad = Aad::raw(b"correct-aad");
    let context = Context::raw(b"correct-context");

    let ciphertext = citadel.seal(&pk, plaintext, &aad, &context).unwrap();

    // Wrong AAD
    let result = citadel.open(&sk, &ciphertext, &Aad::raw(b"wrong-aad"), &context);
    assert!(result.is_err());
    println!("  Wrong AAD:     Err(\"{}\")  ✓", result.unwrap_err());

    // Wrong context
    let result = citadel.open(&sk, &ciphertext, &aad, &Context::raw(b"wrong-context"));
    assert!(result.is_err());
    println!("  Wrong context: Err(\"{}\")  ✓", result.unwrap_err());

    // Wrong key
    let (_, wrong_sk) = citadel.generate_keypair();
    let result = citadel.open(&wrong_sk, &ciphertext, &aad, &context);
    assert!(result.is_err());
    println!("  Wrong key:     Err(\"{}\")  ✓", result.unwrap_err());

    println!();
    println!("  All three failures produce identical opaque errors —");
    println!("  no information leaks to distinguish failure modes.");
}

fn demo_tamper_detection() {
    section("5. Tamper Detection");

    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let plaintext = b"integrity-protected data";
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let ciphertext = citadel.seal(&pk, plaintext, &aad, &ctx).unwrap();

    let regions = [
        ("Header (version byte)", 0),
        ("Header (KEM suite)", 1),
        ("Header (AEAD suite)", 2),
        ("KEM ciphertext (byte 10)", 10),
        ("KEM ciphertext (byte 500)", 500),
        ("Nonce region", HEADER_BYTES + KEM_CIPHERTEXT_BYTES + 3),
        ("AEAD ciphertext (last byte)", ciphertext.len() - 1),
    ];

    for (label, offset) in regions {
        let mut tampered = ciphertext.clone();
        tampered[offset] ^= 0x01; // flip one bit
        let result = citadel.open(&sk, &tampered, &aad, &ctx);
        assert!(result.is_err());
        println!("  Flip bit in {:<30} → Err  ✓", label);
    }

    // Truncation
    let result = citadel.open(&sk, &ciphertext[..ciphertext.len() - 1], &aad, &ctx);
    assert!(result.is_err());
    println!("  Truncate 1 byte                          → Err  ✓");

    println!();
    println!("  All tamper attempts detected with uniform error.");
}

fn demo_envelope_facade() {
    section("6. Envelope Façade (Internal API)");

    let env = Envelope::new();
    let (pk, sk) = env.generate_keypair();

    // Build structured AAD + context
    let context = env.build_context("production", "user-data-encryption");
    let msg_id = env.generate_msg_id().unwrap();
    let aad = env
        .build_aad(
            "service-a",
            "service-b",
            "/api/v1/encrypt",
            1700000000000,
            42,
            msg_id,
        )
        .unwrap();

    println!(
        "  Context:  {} bytes  (env=production, purpose=user-data-encryption)",
        context.len()
    );
    println!(
        "  AAD:      {} bytes  (TLV: sender + recipient + route + ts + seq + msg_id)",
        aad.len()
    );
    println!("  Msg ID:   {}", hex::encode(msg_id));

    let plaintext = b"envelope facade payload";
    let ct = env.seal(&pk, plaintext, &aad, &context).unwrap();
    let recovered = env.open(&sk, &ct, &aad, &context).unwrap();
    assert_eq!(recovered, plaintext);
    println!("  Seal → Open roundtrip: ✓");

    // Also test the convenience method
    let msg_id2 = env.generate_msg_id().unwrap();
    let ct2 = env
        .seal_internal(
            &pk,
            plaintext,
            "production",
            "user-data-encryption",
            "service-a",
            "service-b",
            "/api/v1/encrypt",
            1700000000000,
            43,
            msg_id2,
        )
        .unwrap();
    let recovered2 = env
        .open_internal(
            &sk,
            &ct2,
            "production",
            "user-data-encryption",
            "service-a",
            "service-b",
            "/api/v1/encrypt",
            1700000000000,
            43,
            msg_id2,
        )
        .unwrap();
    assert_eq!(recovered2, plaintext);
    println!("  seal_internal → open_internal: ✓");
}

fn demo_payload_scaling() {
    section("7. Performance Across Payload Sizes");

    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::raw(b"perf-aad");
    let ctx = Context::raw(b"perf-ctx");

    let sizes: &[usize] = &[64, 1024, 16_384, 65_536, 262_144, 1_048_576];

    println!(
        "  {:>10}  {:>12}  {:>12}  {:>10}  {:>10}",
        "Plaintext", "Ciphertext", "Overhead", "Encrypt", "Decrypt"
    );
    println!(
        "  {:>10}  {:>12}  {:>12}  {:>10}  {:>10}",
        "─────────", "──────────", "────────", "───────", "───────"
    );

    for &size in sizes {
        let plaintext = vec![0xABu8; size];

        let t = Instant::now();
        let ct = citadel.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        let enc = t.elapsed();

        let t = Instant::now();
        let pt = citadel.open(&sk, &ct, &aad, &ctx).unwrap();
        let dec = t.elapsed();

        assert_eq!(pt, plaintext);

        let overhead = ct.len() - plaintext.len();
        println!(
            "  {:>10}  {:>12}  {:>10} B  {:>10.2?}  {:>10.2?}",
            human_bytes(size),
            human_bytes(ct.len()),
            overhead,
            enc,
            dec,
        );
    }

    println!();
    println!(
        "  Fixed overhead per message: {} bytes",
        MIN_CIPHERTEXT_BYTES - AEAD_TAG_BYTES
    );
    println!(
        "  (header: {} + kem_ct: {} + nonce: {} + aead_tag: {})",
        HEADER_BYTES, KEM_CIPHERTEXT_BYTES, NONCE_BYTES, AEAD_TAG_BYTES
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_prefix(data: &[u8], n: usize) -> String {
    let take = data.len().min(n);
    hex::encode(&data[..take])
}

fn human_bytes(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}
