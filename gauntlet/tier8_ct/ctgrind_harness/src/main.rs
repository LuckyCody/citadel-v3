//! Tier 8 — ctgrind constant-time check of ML-KEM-768 decapsulation.
//!
//! Marks the ML-KEM secret-key bytes as "undefined" via valgrind client
//! requests, then runs Citadel's decapsulation. Under valgrind/memcheck, ANY
//! conditional branch or memory address that depends on a secret byte is
//! reported ("Conditional jump ... depends on uninitialised value(s)"). Clean =
//! no secret-dependent control flow / addressing on this path (for this input).
//!
//! This targets exactly the operation `TIMING.md` flags a measured wobble on.

use core::ffi::c_void;

use citadel_envelope::timing_diagnostics::{hybrid_encapsulate, mlkem_decapsulate_from_key_bytes};
use citadel_envelope::wire::{KEM_CIPHERTEXT_BYTES, KEM_SECRET_KEY_BYTES};
use citadel_envelope::{HybridX25519MlKem768Provider as Provider, KemProvider};

extern "C" {
    /// Mark `n` bytes at `p` as uninitialised (valgrind memcheck client request).
    fn ct_mark_undefined(p: *mut c_void, n: usize);
}

fn main() {
    // Well-formed keypair + ciphertext (values are irrelevant to ctgrind; memcheck
    // tracks definedness, not values — we only need the real code path to run).
    let (pk, sk) = Provider::keygen();
    let sk_bytes: [u8; KEM_SECRET_KEY_BYTES] = sk.to_bytes();
    let (_ss, ct_vec) = hybrid_encapsulate(&pk).expect("encapsulate");
    let mut ct = [0u8; KEM_CIPHERTEXT_BYTES];
    ct.copy_from_slice(&ct_vec);

    // Mark the ML-KEM secret-key region (bytes 32..) as UNDEFINED = "secret".
    // The X25519 half (first 32 B) is left defined; this isolates the ML-KEM path.
    let mlkem_secret = &sk_bytes[32..];
    unsafe {
        ct_mark_undefined(mlkem_secret.as_ptr() as *mut c_void, mlkem_secret.len());
    }

    // Operation under test. Do NOT branch on the (secret-derived) result.
    let out = mlkem_decapsulate_from_key_bytes(&sk_bytes, &ct);
    let _ = std::hint::black_box(out);

    eprintln!("ctgrind: ML-KEM decapsulation completed (see valgrind report)");
}
