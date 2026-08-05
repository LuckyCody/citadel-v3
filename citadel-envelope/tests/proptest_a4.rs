// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Property-based round-trip + rejection tests for suite `0xA4` (P-384 + ML-KEM-1024).
//!
//! Spec 033 §6 "proptest round-trip over 0xA4 — composition". Complements the deterministic
//! `v2_vector_a4` and the red tests: those pin fixed inputs, these sweep the message / AAD /
//! context / tamper space.

use citadel_envelope::{Aad, CitadelP384, Context, P384MlKem1024PublicKey, P384MlKem1024SecretKey};
use proptest::prelude::*;

proptest! {
    // Keygen runs per case (P-384 + ML-KEM-1024), so keep the case count modest.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Seal then open recovers any plaintext under any AAD/context.
    #[test]
    fn a4_roundtrip_any_message(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        aad in proptest::collection::vec(any::<u8>(), 0..128),
        context in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let cit = CitadelP384::new();
        let (pk, sk) = cit.generate_keypair();
        let a = Aad::raw(&aad);
        let c = Context::raw(&context);
        let ct = cit.seal(&pk, &plaintext, &a, &c).expect("seal");
        let pt = cit.open(&sk, &ct, &a, &c).expect("open");
        prop_assert_eq!(pt, plaintext);
    }

    /// Opening with a different context must fail (context is bound into key derivation).
    #[test]
    fn a4_wrong_context_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
        ctx_a in proptest::collection::vec(any::<u8>(), 0..64),
        ctx_b in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assume!(ctx_a != ctx_b);
        let cit = CitadelP384::new();
        let (pk, sk) = cit.generate_keypair();
        let aad = Aad::empty();
        let ct = cit.seal(&pk, &plaintext, &aad, &Context::raw(&ctx_a)).expect("seal");
        prop_assert!(cit.open(&sk, &ct, &aad, &Context::raw(&ctx_b)).is_err());
    }

    /// Opening with a different AAD must fail (AAD is bound into the AEAD tag).
    #[test]
    fn a4_wrong_aad_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
        aad_a in proptest::collection::vec(any::<u8>(), 0..64),
        aad_b in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assume!(aad_a != aad_b);
        let cit = CitadelP384::new();
        let (pk, sk) = cit.generate_keypair();
        let ctx = Context::raw(b"proptest-ctx");
        let ct = cit.seal(&pk, &plaintext, &Aad::raw(&aad_a), &ctx).expect("seal");
        prop_assert!(cit.open(&sk, &ct, &Aad::raw(&aad_b), &ctx).is_err());
    }

    /// Serializing and reloading BOTH keys from bytes still round-trips — the composition of
    /// the slice-2 to_bytes/from_bytes with seal/open.
    #[test]
    fn a4_reserialized_keys_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let cit = CitadelP384::new();
        let (pk0, sk0) = cit.generate_keypair();
        let pk = P384MlKem1024PublicKey::from_bytes(&pk0.to_bytes()).expect("pk reload");
        let sk = P384MlKem1024SecretKey::from_bytes(&sk0.to_bytes()).expect("sk reload");
        let aad = Aad::empty();
        let ctx = Context::raw(b"proptest-ctx");
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).expect("seal");
        let pt = cit.open(&sk, &ct, &aad, &ctx).expect("open");
        prop_assert_eq!(pt, plaintext);
    }

    /// Any single-bit flip anywhere in the envelope must be rejected — every byte is either
    /// structurally validated by decode() or authenticated under the AEAD tag / bound into the
    /// KDF transcript, so there is no "don't care" region.
    #[test]
    fn a4_single_bit_tamper_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        flip_byte in any::<usize>(),
        flip_bit in 0u8..8,
    ) {
        let cit = CitadelP384::new();
        let (pk, sk) = cit.generate_keypair();
        let aad = Aad::empty();
        let ctx = Context::raw(b"proptest-ctx");
        let mut ct = cit.seal(&pk, &plaintext, &aad, &ctx).expect("seal");
        let idx = flip_byte % ct.len();
        ct[idx] ^= 1u8 << flip_bit;
        prop_assert!(cit.open(&sk, &ct, &aad, &ctx).is_err());
    }
}
