// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Packet 043 fips-build envelope tests through the PUBLIC SDK surface.
//!
//! On this build `ActiveBackend = AwsLcBackend`: `CitadelP384` runs the `0xA4` suite
//! with AWS-LC ML-KEM/ECDH/AEAD/KDF/hash underneath, and `Citadel` (`0xA3`) runs the
//! codec's AWS-LC hash/KDF/AEAD with its RustCrypto KEM arms (fips is `0xA4`-only by
//! PRD NG2). These tests pin that the public surface behaves identically to the
//! default build: roundtrips, key-reload roundtrips, and the security rejections.
//!
//! Cross-PROVIDER envelope interop (RustCrypto `0xA4` provider vs AWS-LC provider,
//! same keys) lives in `backend_awslc.rs` unit tests — the generic codec entrypoints
//! are crate-private by design. Frozen-vector byte-identity on this build is gate M3
//! (`--features kat,fips`, existing `v2_vector*` suites).
//!
//! Compiles empty without `--features fips`.

#![cfg(feature = "fips")]

use citadel_envelope::{Aad, Citadel, CitadelP384, Context};

#[test]
fn fips_build_a4_sdk_roundtrip() {
    let citadel = CitadelP384::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object", 7);
    let ctx = Context::for_application("fips-diff", "test");

    let sealed = citadel
        .seal(&pk, b"awslc envelope", &aad, &ctx)
        .expect("seal");
    let opened = citadel.open(&sk, &sealed, &aad, &ctx).expect("open");
    assert_eq!(opened, b"awslc envelope");
}

/// Packet 056: prove the fips AEAD runs the approved GCM IV **Scenario 2** path
/// (`RandomizedNonceKey`, module-generated nonce), not a fixed or caller-supplied IV.
/// Sealing the SAME (key, plaintext, aad, context) twice must yield different envelopes,
/// and specifically different nonces at `header[86..98]`, because the module draws a fresh
/// 96-bit nonce from its approved DRBG on every seal. Both must still open. This is the
/// runtime evidence that the External-IV mode found in packet 055 is gone.
#[test]
fn fips_seal_uses_module_generated_random_nonce() {
    let citadel = CitadelP384::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object", 7);
    let ctx = Context::for_application("fips-randnonce", "test");
    let pt = b"scenario-2 randnonce liveness";

    let e1 = citadel.seal(&pk, pt, &aad, &ctx).expect("seal 1");
    let e2 = citadel.seal(&pk, pt, &aad, &ctx).expect("seal 2");

    // Different envelopes overall, and — decisively — different nonces.
    assert_ne!(
        e1, e2,
        "two seals of the same input must differ (fresh module nonce)"
    );
    assert_ne!(
        e1[86..98],
        e2[86..98],
        "the module must generate a fresh random nonce each seal (Scenario 2)"
    );
    // Both still decrypt.
    assert_eq!(citadel.open(&sk, &e1, &aad, &ctx).expect("open 1"), pt);
    assert_eq!(citadel.open(&sk, &e2, &aad, &ctx).expect("open 2"), pt);
}

#[test]
fn fips_build_a3_sdk_roundtrip_unchanged() {
    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::for_storage("bucket", "object", 7);
    let ctx = Context::for_application("fips-diff", "test");

    let sealed = citadel
        .seal(&pk, b"a3 on fips build", &aad, &ctx)
        .expect("seal");
    let opened = citadel.open(&sk, &sealed, &aad, &ctx).expect("open");
    assert_eq!(opened, b"a3 on fips build");
}

#[test]
fn fips_build_reserialized_keys_roundtrip() {
    use citadel_envelope::{P384MlKem1024PublicKey, P384MlKem1024SecretKey};
    let citadel = CitadelP384::new();
    let (pk, sk) = citadel.generate_keypair();
    let pk = P384MlKem1024PublicKey::from_bytes(&pk.to_bytes()).expect("pk reload");
    let sk = P384MlKem1024SecretKey::from_bytes(&sk.to_bytes()).expect("sk reload");
    let aad = Aad::raw(b"reload");
    let ctx = Context::for_application("fips-diff", "reload");

    let sealed = citadel
        .seal(&pk, b"reloaded keys", &aad, &ctx)
        .expect("seal");
    let opened = citadel.open(&sk, &sealed, &aad, &ctx).expect("open");
    assert_eq!(opened, b"reloaded keys");
}

#[test]
fn fips_build_rejections_hold() {
    let citadel = CitadelP384::new();
    let (pk, sk) = citadel.generate_keypair();
    let aad = Aad::raw(b"aad-one");
    let ctx = Context::for_application("fips-diff", "reject");
    let sealed = citadel.seal(&pk, b"secret", &aad, &ctx).expect("seal");

    // Wrong AAD.
    assert!(citadel
        .open(&sk, &sealed, &Aad::raw(b"aad-two"), &ctx)
        .is_err());
    // Wrong context.
    assert!(citadel
        .open(
            &sk,
            &sealed,
            &aad,
            &Context::for_application("fips-diff", "other")
        )
        .is_err());
    // Wrong recipient.
    let (_pk2, sk2) = citadel.generate_keypair();
    assert!(citadel.open(&sk2, &sealed, &aad, &ctx).is_err());
    // Tampered suite byte (downgrade attempt).
    let mut tampered = sealed.clone();
    tampered[6] = 0xA3;
    assert!(citadel.open(&sk, &tampered, &aad, &ctx).is_err());
    // Truncation.
    assert!(citadel
        .open(&sk, &sealed[..sealed.len() - 1], &aad, &ctx)
        .is_err());
}

#[test]
fn fips_build_cross_suite_rejects() {
    let a3 = Citadel::new();
    let p4 = CitadelP384::new();
    let (pk3, _sk3) = a3.generate_keypair();
    let (_pk4, sk4) = p4.generate_keypair();
    let aad = Aad::raw(b"x");
    let ctx = Context::for_application("fips-diff", "cross");

    let env3 = a3.seal(&pk3, b"a3 envelope", &aad, &ctx).expect("seal a3");
    assert!(
        p4.open(&sk4, &env3, &aad, &ctx).is_err(),
        "a3 envelope must not open under an a4 key on the fips build"
    );
}
