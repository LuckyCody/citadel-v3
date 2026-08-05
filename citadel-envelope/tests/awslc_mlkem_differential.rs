// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Packet 039 differential gate: AWS-LC ML-KEM-1024 vs RustCrypto `ml-kem`.
//!
//! Compiles to an empty test binary unless `--features fips`. Four evidence classes:
//!
//! 1. **Bidirectional interop** (I2): keys from one implementation, encapsulation by
//!    the other, decapsulation by the first — shared secrets must agree, 100 rounds
//!    each direction. ML-KEM is standardized, so ANY mismatch is a defect, not noise.
//! 2. **Expanded-key hand-off** (I3): a RustCrypto seed-derived key exported in the
//!    FIPS 203 expanded encoding imports into AWS-LC and both sides decapsulate the
//!    same ciphertext identically.
//! 3. **ACVP decap replay on AWS-LC** (I4): the frozen NIST vectors' raw expanded dk +
//!    ciphertext go STRAIGHT into AWS-LC — no RustCrypto in the loop — and the shared
//!    secret must equal the vector's. Includes the implicit-rejection cases.
//! 4. **ACVP keygen ek/dk agreement on AWS-LC** (I4): encapsulating under each keygen
//!    vector's ek must decapsulate correctly under the imported vector dk — pinning
//!    that AWS-LC's import layout IS the standard FIPS 203 expanded encoding (ek
//!    marshal from an imported dk is unsupported by aws-lc-rs; measured, recorded).
//!
//! Deliberately NOT claimed: ACVP encap replay on AWS-LC (its module DRBG cannot be
//! seeded — API limit recorded in the packet TASK). Encap-side conformance evidence is
//! class 1 + the RustCrypto path's own deterministic ACVP encap tests.

#![cfg(feature = "fips")]
#![allow(deprecated)] // ml-kem expanded-key encoding, same as tests/acvp_mlkem1024.rs

use citadel_envelope::backend_awslc::AwsLcMlKem1024;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, KeyExport},
    ml_kem_1024::{
        Ciphertext as RcCiphertext, DecapsulationKey as RcDecapsulationKey,
        EncapsulationKey as RcEncapsulationKey,
    },
    ExpandedKeyEncoding, Seed,
};
use rand::RngCore;

const INTEROP_ROUNDS: usize = 100;
const HANDOFF_ROUNDS: usize = 25;

fn random_seed() -> [u8; 64] {
    let mut seed = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(serde::Deserialize)]
struct Vectors {
    source_commit: String,
    keygen: Vec<KeygenVector>,
    decap: Vec<DecapVector>,
}

#[derive(serde::Deserialize)]
struct KeygenVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    ek: String,
    dk: String,
}

#[derive(serde::Deserialize)]
struct DecapVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    dk: String,
    c: String,
    k: String,
}

fn vectors() -> Vectors {
    let vectors: Vectors =
        serde_json::from_str(include_str!("acvp_mlkem1024_vectors.json")).unwrap();
    assert_eq!(
        vectors.source_commit, "c924096a71e5d050742e31efa6846d1e2d6fb3bd",
        "frozen vector provenance changed"
    );
    vectors
}

/// Interop direction A: RustCrypto keys, AWS-LC encapsulates, RustCrypto decapsulates.
#[test]
fn interop_rustcrypto_keys_awslc_encap_rustcrypto_decap_100_rounds() {
    for round in 0..INTEROP_ROUNDS {
        let dk = RcDecapsulationKey::from_seed(Seed::from(random_seed()));
        let ek_bytes: [u8; 1568] = dk
            .encapsulation_key()
            .to_bytes()
            .as_slice()
            .try_into()
            .unwrap();

        let (ct, ss_awslc) = AwsLcMlKem1024::encapsulate(&ek_bytes).expect("awslc encapsulate");

        let ss_rustcrypto = dk.decapsulate(&RcCiphertext::from(ct));
        assert_eq!(
            &ss_awslc[..],
            ss_rustcrypto.as_slice(),
            "shared-secret mismatch, direction A, round {round}"
        );
    }
}

/// Interop direction B: AWS-LC keys, RustCrypto encapsulates, AWS-LC decapsulates.
#[test]
fn interop_awslc_keys_rustcrypto_encap_awslc_decap_100_rounds() {
    for round in 0..INTEROP_ROUNDS {
        let (ek_bytes, dk_bytes) = AwsLcMlKem1024::keygen().expect("awslc keygen");

        let ek = RcEncapsulationKey::new(&ek_bytes.into()).expect("awslc ek parses in rustcrypto");
        let (ct, ss_rustcrypto) = ek.encapsulate();

        let ss_awslc =
            AwsLcMlKem1024::decapsulate(&dk_bytes[..], ct.as_slice()).expect("awslc decapsulate");
        assert_eq!(
            ss_rustcrypto.as_slice(),
            &ss_awslc[..],
            "shared-secret mismatch, direction B, round {round}"
        );
    }
}

/// Expanded-key hand-off: one RustCrypto seed key, exported expanded, imported by
/// AWS-LC; both implementations must decapsulate the same ciphertext identically.
#[test]
fn expanded_key_handoff_rustcrypto_to_awslc_25_rounds() {
    for round in 0..HANDOFF_ROUNDS {
        let dk = RcDecapsulationKey::from_seed(Seed::from(random_seed()));
        let dk_expanded: [u8; 3168] = dk.to_expanded_bytes().as_slice().try_into().unwrap();
        let ek_bytes: [u8; 1568] = dk
            .encapsulation_key()
            .to_bytes()
            .as_slice()
            .try_into()
            .unwrap();

        let ek = RcEncapsulationKey::new(&ek_bytes.into()).unwrap();
        let (ct, ss_encap) = ek.encapsulate();
        let ct_array: [u8; 1568] = ct.as_slice().try_into().unwrap();

        let ss_rustcrypto = dk.decapsulate(&RcCiphertext::from(ct_array));
        let ss_awslc =
            AwsLcMlKem1024::decapsulate(&dk_expanded, ct.as_slice()).expect("awslc decapsulate");

        assert_eq!(
            ss_encap.as_slice(),
            ss_rustcrypto.as_slice(),
            "rustcrypto roundtrip, round {round}"
        );
        assert_eq!(
            ss_rustcrypto.as_slice(),
            &ss_awslc[..],
            "hand-off mismatch, round {round}"
        );
    }
}

/// ACVP decap vectors straight into AWS-LC — no RustCrypto in the loop.
#[test]
fn acvp_mlkem1024_decap_vectors_replay_on_awslc() {
    let vectors = vectors();
    assert_eq!(vectors.decap.len(), 10);
    for vector in vectors.decap {
        let dk = from_hex(&vector.dk);
        let ct = from_hex(&vector.c);
        let ss = AwsLcMlKem1024::decapsulate(&dk, &ct).expect("awslc decapsulate");
        assert_eq!(
            &ss[..],
            from_hex(&vector.k).as_slice(),
            "awslc decap shared secret tc{}",
            vector.tc_id
        );
    }
}

/// ACVP keygen vectors: the vector's ek and its imported dk must agree under AWS-LC.
///
/// aws-lc-rs cannot marshal an ek from an IMPORTED dk (generate-path only — measured,
/// recorded in the packet TASK), so import-layout correctness is proven the equivalent
/// way: RustCrypto encapsulates under the vector's ek; AWS-LC decapsulates under the
/// imported vector dk; the shared secrets must match for every keygen vector. A
/// misread import layout would corrupt the embedded ek/implicit-rejection material and
/// break the agreement.
#[test]
fn acvp_mlkem1024_keygen_vectors_ek_dk_agreement_on_awslc() {
    let vectors = vectors();
    assert_eq!(vectors.keygen.len(), 25);
    for vector in vectors.keygen {
        let ek_bytes: [u8; 1568] = from_hex(&vector.ek).try_into().unwrap();
        let dk = from_hex(&vector.dk);

        let ek = RcEncapsulationKey::new(&ek_bytes.into()).expect("vector ek parses");
        let (ct, ss_rustcrypto) = ek.encapsulate();

        let ss_awslc = AwsLcMlKem1024::decapsulate(&dk, ct.as_slice()).expect("awslc decapsulate");
        assert_eq!(
            ss_rustcrypto.as_slice(),
            &ss_awslc[..],
            "vector-ek / imported-dk disagreement under awslc, tc{}",
            vector.tc_id
        );
    }
}

/// Fail-closed length handling on the component boundary.
#[test]
fn component_rejects_wrong_lengths() {
    let (ek, dk) = AwsLcMlKem1024::keygen().expect("awslc keygen");
    let (ct, _ss) = AwsLcMlKem1024::encapsulate(&ek).expect("awslc encapsulate");

    assert!(AwsLcMlKem1024::encapsulate(&ek[..ek.len() - 1]).is_err());
    assert!(AwsLcMlKem1024::decapsulate(&dk[..], &ct[..ct.len() - 1]).is_err());
    assert!(AwsLcMlKem1024::decapsulate(&dk[..100], &ct).is_err());
}
