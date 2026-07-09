// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fuzz target for encrypt/decrypt roundtrip
//!
//! This target verifies that encrypt(decrypt(x)) == x for arbitrary inputs.
//! Goal: Find cases where valid encryptions fail to decrypt correctly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use citadel_envelope::{Aad, Citadel, Context};

/// Structured input for roundtrip fuzzing
#[derive(Arbitrary, Debug)]
struct RoundtripInput {
    /// Plaintext to encrypt
    plaintext: Vec<u8>,
    /// Additional authenticated data
    aad: Vec<u8>,
    /// Application context  
    context: Vec<u8>,
}

// Generate a fixed keypair at startup
thread_local! {
    static KEYPAIR: (
        citadel_envelope::PublicKey,
        citadel_envelope::SecretKey
    ) = {
        let citadel = Citadel::new();
        citadel.generate_keypair()
    };
}

fuzz_target!(|input: RoundtripInput| {
    // Enforce constraints
    if input.aad.len() > 65536 {
        return;
    }
    if input.context.len() > 256 {
        return;
    }
    // Limit plaintext size to avoid OOM in fuzzing
    if input.plaintext.len() > 1024 * 1024 {
        return;
    }
    
    KEYPAIR.with(|(pk, sk)| {
        let citadel = Citadel::new();
        let aad = Aad::raw(&input.aad);
        let context = Context::raw(&input.context);
        
        // Encrypt
        let ciphertext = match citadel.seal(pk, &input.plaintext, &aad, &context) {
            Ok(ct) => ct,
            Err(_) => return, // Encryption can fail (e.g., RNG failure)
        };
        
        // Decrypt
        let decrypted = citadel.open(sk, &ciphertext, &aad, &context)
            .expect("Decryption of valid ciphertext should succeed");
        
        // Verify roundtrip
        assert_eq!(
            decrypted, input.plaintext,
            "Roundtrip failed: plaintext mismatch"
        );
    });
});
