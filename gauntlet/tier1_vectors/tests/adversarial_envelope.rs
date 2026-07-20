// Tier 1b — adversarial composition tests against Citadel's REAL public SDK.
//
// These do not test primitives in isolation (Wycheproof does that); they attack
// Citadel's own envelope composition — the KDF binding, AAD binding, wire format,
// and v1/v2 dispatch — through the exact `Citadel::seal`/`open` surface that the
// FFI and real integrations call.
//
// Every property here is a security invariant Citadel CLAIMS (SECURITY.md
// "What We Guarantee"). A single counterexample is a real finding.

use citadel_envelope::{inspect, Aad, Citadel, Context};
use proptest::prelude::*;

fn cfg() -> ProptestConfig {
    // Enough cases to be adversarial without making KEM keygen dominate wall time.
    ProptestConfig { cases: 256, ..ProptestConfig::default() }
}

proptest! {
    #![proptest_config(cfg())]

    /// Guarantee: correct key + AAD + context round-trips exactly.
    #[test]
    fn roundtrip_is_exact(
        pt in prop::collection::vec(any::<u8>(), 0..4096),
        aadb in prop::collection::vec(any::<u8>(), 0..96),
        ctxb in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let c = Citadel::new();
        let (pk, sk) = c.generate_keypair();
        let (aad, ctx) = (Aad::raw(&aadb), Context::raw(&ctxb));
        let blob = c.seal(&pk, &pt, &aad, &ctx).expect("seal");
        let out = c.open(&sk, &blob, &aad, &ctx).expect("open");
        prop_assert_eq!(out, pt);
    }

    /// Guarantee: "any modification to ciphertext causes failure."
    /// Flip one bit anywhere in the blob — decryption MUST fail.
    #[test]
    fn single_bit_flip_always_fails(
        pt in prop::collection::vec(any::<u8>(), 1..1024),
        idx in any::<usize>(),
        bit in 0u32..8,
    ) {
        let c = Citadel::new();
        let (pk, sk) = c.generate_keypair();
        let (aad, ctx) = (Aad::empty(), Context::empty());
        let mut blob = c.seal(&pk, &pt, &aad, &ctx).unwrap();
        let i = idx % blob.len();
        blob[i] ^= 1u8 << bit;
        prop_assert!(
            c.open(&sk, &blob, &aad, &ctx).is_err(),
            "bit flip at byte {i} bit {bit} decrypted successfully"
        );
    }

    /// Guarantee: hybrid security / key binding — a different recipient key fails.
    #[test]
    fn wrong_key_fails(pt in prop::collection::vec(any::<u8>(), 0..1024)) {
        let c = Citadel::new();
        let (pk, _sk) = c.generate_keypair();
        let (_pk2, sk2) = c.generate_keypair();
        let (aad, ctx) = (Aad::empty(), Context::empty());
        let blob = c.seal(&pk, &pt, &aad, &ctx).unwrap();
        prop_assert!(c.open(&sk2, &blob, &aad, &ctx).is_err());
    }

    /// Guarantee: "wrong AAD causes decryption failure" (record-substitution defense).
    #[test]
    fn wrong_aad_fails(
        pt in prop::collection::vec(any::<u8>(), 0..1024),
        a1 in prop::collection::vec(any::<u8>(), 0..96),
        a2 in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        prop_assume!(a1 != a2);
        let c = Citadel::new();
        let (pk, sk) = c.generate_keypair();
        let ctx = Context::empty();
        let blob = c.seal(&pk, &pt, &Aad::raw(&a1), &ctx).unwrap();
        prop_assert!(c.open(&sk, &blob, &Aad::raw(&a2), &ctx).is_err());
    }

    /// Guarantee: "wrong context causes decryption failure" (KDF domain binding).
    #[test]
    fn wrong_context_fails(
        pt in prop::collection::vec(any::<u8>(), 0..1024),
        c1 in prop::collection::vec(any::<u8>(), 0..96),
        c2 in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        prop_assume!(c1 != c2);
        let c = Citadel::new();
        let (pk, sk) = c.generate_keypair();
        let aad = Aad::empty();
        let blob = c.seal(&pk, &pt, &aad, &Context::raw(&c1)).unwrap();
        prop_assert!(c.open(&sk, &blob, &aad, &Context::raw(&c2)).is_err());
    }

    /// Truncation must never open (no short-read acceptance).
    #[test]
    fn truncation_fails(
        pt in prop::collection::vec(any::<u8>(), 1..1024),
        cut in any::<usize>(),
    ) {
        let c = Citadel::new();
        let (pk, sk) = c.generate_keypair();
        let (aad, ctx) = (Aad::empty(), Context::empty());
        let blob = c.seal(&pk, &pt, &aad, &ctx).unwrap();
        let n = 1 + (cut % blob.len());
        if n == blob.len() { return Ok(()); }
        prop_assert!(c.open(&sk, &blob[..n], &aad, &ctx).is_err());
    }
}

/// Version confusion: a v2 blob whose magic is corrupted must NOT silently
/// downgrade-decode as v1; it must fail. And a real v1 blob must round-trip.
#[test]
fn no_silent_version_downgrade() {
    let c = Citadel::new();
    let (pk, sk) = c.generate_keypair();
    let (aad, ctx) = (Aad::raw(b"rec-1"), Context::raw(b"prod"));
    let pt = b"harvest-now-decrypt-later target";

    // Default seal is v2.
    let v2 = c.seal(&pk, pt, &aad, &ctx).unwrap();
    let info = inspect(&v2).expect("inspect v2");
    // Corrupt the leading magic byte; decode must not fall back to a v1 parse
    // that succeeds — it must error.
    let mut mangled = v2.clone();
    mangled[0] ^= 0xFF;
    assert!(
        c.open(&sk, &mangled, &aad, &ctx).is_err(),
        "corrupted-magic v2 blob decrypted; possible silent downgrade"
    );

    // v1 fixtures still decode (wire-format-stability guarantee).
    let v1 = c.seal_v1_compat(&pk, pt, &aad, &ctx).unwrap();
    let out = c.open(&sk, &v1, &aad, &ctx).expect("v1 open");
    assert_eq!(&out, pt);

    // A v1 and v2 sealing of identical inputs must be distinguishable, not aliased.
    assert_ne!(v1, v2, "v1 and v2 encodings collided");
    let _ = info;
}
