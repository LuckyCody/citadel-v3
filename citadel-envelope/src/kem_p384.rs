// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid KEM: P-384 + ML-KEM-1024 — suite `0xA4`.
//!
//! The CNSA 2.0 category-5 pairing. Same hybrid construction as suite `0xA3`
//! (`kem.rs`): security holds if *either* arm survives. Only the primitives differ.
//!
//! This lives in its own module rather than beside `HybridX25519MlKem768Provider`
//! because `kem.rs` is the frozen, formally-verified `0xA3` path. A new suite must not
//! be able to regress it by sharing an edit.
//!
//! Key serialization:
//!   PublicKey  = p384_pk_sec1[97] || mlkem_ek[1568]   (1665 bytes)
//!   SecretKey  = p384_sk[48]      || mlkem_seed[64]   (112 bytes)
//!
//! KEM ciphertext (on wire):
//!   p384_ephemeral_pk_sec1[97] || mlkem_ct[1568]      (1665 bytes)
//!
//! Combined shared secret (fed to KDF):
//!   p384_ecdh_x[48] || mlkem_ss[32]                   (80 bytes)
//!
//! Note the shared secret is 80 bytes here and 64 for `0xA3`. Nothing downstream cares:
//! packet 033 P2 made the combiner suite-generic, so `derive_key` takes a slice.

extern crate alloc;
use alloc::vec::Vec;

use ml_kem::{
    kem::{Decapsulate as MlKemDecapsulate, Encapsulate as MlKemEncapsulate, KeyExport},
    ml_kem_1024::{
        Ciphertext as MlKemCiphertext, DecapsulationKey as MlKemSecretKey,
        EncapsulationKey as MlKemPublicKey,
    },
    Seed,
};
use p384::{
    ecdh::{diffie_hellman, EphemeralSecret},
    elliptic_curve::{sec1::ToSec1Point, Generate},
    PublicKey as P384PublicKey, SecretKey as P384SecretKey,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{DecryptionError, EncodingError};
use crate::kem::KemProvider;

// ---------------------------------------------------------------------------
// Suite constants
// ---------------------------------------------------------------------------

/// Uncompressed SEC1 point: `0x04 || x[48] || y[48]`.
///
/// Decision D2 (`eem/033R_decisions_D2_D3_freeze.md`) chose uncompressed over
/// compressed. Compression saves 48 bytes and costs a modular square root over
/// attacker-supplied input on every single decode. Bandwidth is not the scarce resource.
pub const P384_POINT_BYTES: usize = 97;

/// SEC1 tag for an uncompressed point. See [`parse_p384_point`] for why this is checked
/// explicitly rather than left to the length.
const SEC1_TAG_UNCOMPRESSED: u8 = 0x04;

/// P-384 scalar width.
pub const P384_SCALAR_BYTES: usize = 48;

/// ML-KEM-1024 encapsulation key (FIPS 203: `384k + 32`, k = 4).
pub const MLKEM1024_EK_BYTES: usize = 1568;

/// ML-KEM-1024 ciphertext (FIPS 203: `32(du*k + dv)`, du = 11, dv = 5, k = 4).
pub const MLKEM1024_CT_BYTES: usize = 1568;

/// FIPS 203 `(d, z)` seed. Decision D3 stores this instead of the 3168-byte expanded
/// decapsulation key: it is the non-deprecated representation, and it makes a hybrid
/// secret key 112 bytes instead of 3216.
///
/// The cost is a key re-derivation per `open()`. That cost is **measured in P4**, not
/// assumed to be acceptable here.
pub const MLKEM_SEED_BYTES: usize = 64;

/// ECDH output is the x-coordinate only.
const P384_SHARED_BYTES: usize = 48;

/// ML-KEM shared key, all parameter sets.
const MLKEM_SHARED_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Hybrid public key: P-384 public key + ML-KEM-1024 encapsulation key.
///
/// A distinct type from `0xA3`'s [`crate::kem::PublicKey`], not a generic parameter over
/// it. The Tier 1 API freeze pins that type with concrete array sizes, so making it
/// generic would be a freeze violation; associated types on [`KemProvider`] are the only
/// permitted shape. A useful side effect is that a `0xA3` key cannot be passed to a
/// `0xA4` encapsulation — the compiler rejects it before any crypto runs.
#[derive(Clone)]
pub struct P384MlKem1024PublicKey {
    p384: P384PublicKey,
    mlkem: MlKemPublicKey,
}

/// Hybrid secret key: P-384 scalar + ML-KEM-1024 seed.
pub struct P384MlKem1024SecretKey {
    p384: P384SecretKey,
    /// D3: the 64-byte FIPS 203 seed, never the expanded key.
    mlkem_seed: Zeroizing<[u8; MLKEM_SEED_BYTES]>,
}

impl P384MlKem1024SecretKey {
    /// Rebuild the ML-KEM decapsulation key from the stored seed.
    ///
    /// `from_seed` is infallible, which is the whole reason D3 stores a seed: the
    /// deprecated expanded-key path returns `Result` and would put a failure mode on
    /// every `open()`.
    fn mlkem_key(&self) -> MlKemSecretKey {
        MlKemSecretKey::from_seed(Seed::from(*self.mlkem_seed))
    }
}

// ---------------------------------------------------------------------------
// SEC1 parsing
// ---------------------------------------------------------------------------

/// Parse an uncompressed SEC1 P-384 point, rejecting every other encoding.
///
/// The tag check is deliberately explicit and is **not** redundant with the length
/// check, even though it looks like it today:
///
/// - compressed (`0x02`/`0x03`) is 49 bytes — the length check rejects it;
/// - compact (`0x05`) is 49 bytes — likewise;
/// - identity (`0x00`) is 1 byte — likewise;
/// - **hybrid (`0x06`/`0x07`) is 97 bytes** — the same length as uncompressed. Only the
///   tag distinguishes it.
///
/// `sec1` 0.8.1 happens to reject hybrid tags in `Tag::from_u8`, so today this check
/// catches nothing the dependency would not. It is here because hybrid *is* a legal SEC1
/// encoding, a future `sec1` may add it, and on that day a length-only guard would
/// silently start accepting two distinct byte strings that decode to the same point.
/// That breaks the injectivity the recipient-binding hash in `wire_v2` depends on.
/// Pinning it costs one comparison per decode.
fn parse_p384_point(bytes: &[u8]) -> Option<P384PublicKey> {
    if bytes.len() != P384_POINT_BYTES || bytes[0] != SEC1_TAG_UNCOMPRESSED {
        return None;
    }
    // Validates the point is on the curve and not the identity.
    P384PublicKey::from_sec1_bytes(bytes).ok()
}

/// Serialize a P-384 public key as an uncompressed SEC1 point.
///
/// `to_sec1_point(false)` rather than the inherent `to_sec1_bytes()`: the latter encodes
/// according to `NistP384::COMPRESS_POINTS`, a constant owned by the `p384` crate that
/// happens to be `false` today. D2 is our decision, not theirs, so the `false` is stated
/// here. A dependency bump flipping that default would otherwise silently change every
/// public key's serialization -- and with it every recipient-binding hash.
fn encode_p384_point(pk: &P384PublicKey) -> Vec<u8> {
    pk.as_affine().to_sec1_point(false).to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// Hybrid P-384 + ML-KEM-1024 provider (suite `0xA4`).
pub struct HybridP384MlKem1024Provider;

impl KemProvider for HybridP384MlKem1024Provider {
    const SUITE_KEM: u8 = crate::wire::SUITE_KEM_HYBRID_P384_MLKEM1024;
    const KEM_CIPHERTEXT_BYTES: usize = P384_POINT_BYTES + MLKEM1024_CT_BYTES;
    const KEM_PUBLIC_KEY_BYTES: usize = P384_POINT_BYTES + MLKEM1024_EK_BYTES;
    const KEM_SECRET_KEY_BYTES: usize = P384_SCALAR_BYTES + MLKEM_SEED_BYTES;

    type PublicKey = P384MlKem1024PublicKey;
    type SecretKey = P384MlKem1024SecretKey;

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        // `generate()` draws from the ambient system RNG and panics only if the OS RNG
        // itself fails. `keygen()` returns no `Result` (Tier 1 frozen signature), and
        // this matches how `0xA3` keygen already behaves.
        let p384_sk = P384SecretKey::generate();
        let p384_pk = p384_sk.public_key();

        // Generate the seed directly rather than calling `generate()` and recovering it
        // with `to_seed()`. D3 requires that `to_seed()`'s `Option` never be
        // `.expect()`-ed; the cleanest way to honour that is to never be in a position
        // where it can return `None`.
        let mut seed = Zeroizing::new([0u8; MLKEM_SEED_BYTES]);
        let mut rng = OsRng;
        rng.fill_bytes(seed.as_mut());
        let mlkem_sk = MlKemSecretKey::from_seed(Seed::from(*seed));
        let mlkem_pk = mlkem_sk.encapsulation_key().clone();

        (
            P384MlKem1024PublicKey {
                p384: p384_pk,
                mlkem: mlkem_pk,
            },
            P384MlKem1024SecretKey {
                p384: p384_sk,
                mlkem_seed: seed,
            },
        )
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError> {
        let ephemeral = EphemeralSecret::try_generate().map_err(|_| EncodingError)?;
        let ephemeral_pk = P384PublicKey::from(&ephemeral);
        let p384_ss = ephemeral.diffie_hellman(&pk.p384);

        // No `was_contributory()` analogue is needed, and its absence is not an
        // oversight. X25519 needs one because Curve25519 has cofactor 8 and small-order
        // points. P-384 is a prime-order group with cofactor 1, and `parse_p384_point` /
        // `from_sec1_bytes` already reject the identity, so no valid public key can drive
        // the shared point to identity.
        let (mlkem_ct, mlkem_ss) = pk.mlkem.encapsulate();

        let mut shared = Zeroizing::new(Vec::with_capacity(P384_SHARED_BYTES + MLKEM_SHARED_BYTES));
        shared.extend_from_slice(p384_ss.raw_secret_bytes());
        shared.extend_from_slice(mlkem_ss.as_ref());

        let mut kem_ct = Vec::with_capacity(Self::KEM_CIPHERTEXT_BYTES);
        kem_ct.extend_from_slice(&encode_p384_point(&ephemeral_pk));
        kem_ct.extend_from_slice(mlkem_ct.as_ref());

        Ok((shared, kem_ct))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
        if ct.len() != Self::KEM_CIPHERTEXT_BYTES {
            return Err(DecryptionError);
        }

        let ephemeral_pk = parse_p384_point(&ct[..P384_POINT_BYTES]).ok_or(DecryptionError)?;
        let mlkem_ct_bytes: [u8; MLKEM1024_CT_BYTES] = ct[P384_POINT_BYTES..]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let mlkem_ct: MlKemCiphertext = mlkem_ct_bytes.into();

        let p384_ss = diffie_hellman(sk.p384.to_nonzero_scalar(), ephemeral_pk.as_affine());
        let mlkem_ss = sk.mlkem_key().decapsulate(&mlkem_ct);

        let mut shared = Zeroizing::new(Vec::with_capacity(P384_SHARED_BYTES + MLKEM_SHARED_BYTES));
        shared.extend_from_slice(p384_ss.raw_secret_bytes());
        shared.extend_from_slice(mlkem_ss.as_ref());

        Ok(shared)
    }

    fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::KEM_PUBLIC_KEY_BYTES);
        out.extend_from_slice(&encode_p384_point(&pk.p384));
        out.extend_from_slice(pk.mlkem.to_bytes().as_ref());
        out
    }

    fn public_key_of(sk: &Self::SecretKey) -> Self::PublicKey {
        P384MlKem1024PublicKey {
            p384: sk.p384.public_key(),
            mlkem: sk.mlkem_key().encapsulation_key().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type P = HybridP384MlKem1024Provider;

    /// The provider does the job at all. Everything else here is worthless if this
    /// fails, and the adversarial suite (swarm, P3c) assumes it passes.
    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (pk, sk) = P::keygen();
        let (ss_enc, ct) = P::encapsulate(&pk).expect("encapsulate");
        let ss_dec = P::decapsulate(&sk, &ct).expect("decapsulate");
        assert_eq!(&*ss_enc, &*ss_dec);
        assert_eq!(ss_enc.len(), P384_SHARED_BYTES + MLKEM_SHARED_BYTES);
    }

    /// A shared secret that agrees with *itself* proves nothing -- a provider returning
    /// a constant would pass the roundtrip test. Two keypairs must not agree.
    #[test]
    fn distinct_keys_do_not_agree() {
        let (pk_a, _sk_a) = P::keygen();
        let (_pk_b, sk_b) = P::keygen();
        let (ss_a, ct) = P::encapsulate(&pk_a).expect("encapsulate");
        // ML-KEM implicit rejection means decapsulation succeeds and yields a wrong
        // secret rather than erroring, so assert on the value, not on `is_err`.
        if let Ok(ss_wrong) = P::decapsulate(&sk_b, &ct) {
            assert_ne!(&*ss_wrong, &*ss_a);
        }
    }

    /// The wire sizes the SUITE_TABLE promises are the sizes actually produced. This is
    /// the other half of the deliberate literal/provider duplication in `wire.rs`.
    #[test]
    fn wire_sizes_match_suite_table() {
        let table = crate::wire::suite_params(P::SUITE_KEM).expect("0xA4 must be in SUITE_TABLE");
        let (pk, sk) = P::keygen();
        let (_ss, ct) = P::encapsulate(&pk).expect("encapsulate");

        assert_eq!(ct.len(), table.kem_ciphertext_bytes);
        assert_eq!(ct.len(), P::KEM_CIPHERTEXT_BYTES);
        assert_eq!(P::public_key_bytes(&pk).len(), table.kem_public_key_bytes);
        assert_eq!(
            P384_SCALAR_BYTES + sk.mlkem_seed.len(),
            table.kem_secret_key_bytes
        );
        assert_eq!(table.kem_ciphertext_bytes, 1665);
        assert_eq!(table.kem_secret_key_bytes, 112);
    }

    /// D2: only uncompressed SEC1 is accepted. Compressed is the reachable case today;
    /// see `parse_p384_point` for why the tag is checked rather than only the length.
    #[test]
    fn compressed_and_mistagged_points_are_rejected() {
        let (pk, _sk) = P::keygen();
        let uncompressed = encode_p384_point(&pk.p384);
        assert_eq!(uncompressed.len(), P384_POINT_BYTES);
        assert_eq!(uncompressed[0], SEC1_TAG_UNCOMPRESSED);
        assert!(parse_p384_point(&uncompressed).is_some());

        // Compressed form of the same point: valid SEC1, wrong length, must reject.
        let compressed = pk.p384.as_affine().to_sec1_point(true).to_bytes().to_vec();
        assert_eq!(compressed.len(), 49);
        assert!(parse_p384_point(&compressed).is_none());

        // Hybrid tags (0x06/0x07) are 97 bytes -- the length check cannot catch them.
        for tag in [0x06u8, 0x07, 0x00, 0x05, 0x02, 0x03] {
            let mut mistagged = uncompressed.clone();
            mistagged[0] = tag;
            assert!(
                parse_p384_point(&mistagged).is_none(),
                "tag {tag:#04x} must be rejected at 97 bytes"
            );
        }
    }

    /// A truncated or over-long ciphertext must fail closed, not panic on the slice.
    #[test]
    fn wrong_length_ciphertext_rejected() {
        let (pk, sk) = P::keygen();
        let (_ss, ct) = P::encapsulate(&pk).expect("encapsulate");

        assert!(P::decapsulate(&sk, &ct[..ct.len() - 1]).is_err());
        let mut long = ct.clone();
        long.push(0);
        assert!(P::decapsulate(&sk, &long).is_err());
        assert!(P::decapsulate(&sk, &[]).is_err());
    }
}
