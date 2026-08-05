// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! ML-KEM-1024 via AWS-LC — first component of the FIPS backend (packet 039).
//!
//! Compiled ONLY under `--features fips`. Grew in layers: the primitive components
//! (packets 039–042, below) and, since packet 043, the [`AwsLcBackend`] +
//! [`AwsLcHybridP384MlKem1024Provider`] fold at the end of this file —
//! [`crate::backend::ActiveBackend`] resolves HERE under `--features fips` (and to
//! RustCrypto otherwise). Selection lives in `backend.rs`; there is no other switch.
//!
//! Measured API constraints of `aws-lc-rs` 1.17.1 (packet-039 spike, recorded in the
//! packet TASK):
//! - keys import/export as the FIPS 203 **expanded** 3168-byte decapsulation key; there
//!   is no seed `(d,z)` import. The D3 seed-based `0xA4` secret-key format therefore
//!   needs a bridge decision at packet 043 before a full fips provider can exist.
//! - encapsulation randomness comes from the module's internal DRBG; there is no
//!   deterministic encapsulation. ACVP conformance on this path is proven via decap
//!   vectors + bidirectional interop with the ACVP-validated RustCrypto path
//!   (`tests/awslc_mlkem_differential.rs`).

extern crate alloc;
use alloc::vec::Vec;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, RandomizedNonceKey, UnboundKey, AES_256_GCM};
use aws_lc_rs::agreement as lc_agreement;
use aws_lc_rs::digest as lc_digest;
use aws_lc_rs::hkdf as lc_hkdf;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use zeroize::Zeroizing;

use crate::backend::{CryptoBackend, KemProvider};
use crate::error::{DecryptionError, EncodingError};
use crate::kem_p384::{P384MlKem1024PublicKey, P384MlKem1024SecretKey};

/// ML-KEM-1024 encapsulation key (FIPS 203).
pub const MLKEM1024_EK_BYTES: usize = 1568;
/// ML-KEM-1024 ciphertext (FIPS 203).
pub const MLKEM1024_CT_BYTES: usize = 1568;
/// ML-KEM-1024 expanded decapsulation key (FIPS 203) — the only key form AWS-LC
/// imports or exports.
pub const MLKEM1024_DK_EXPANDED_BYTES: usize = 3168;
/// ML-KEM shared secret, all parameter sets.
pub const MLKEM_SHARED_BYTES: usize = 32;

/// ML-KEM-1024 executed inside AWS-LC.
///
/// Byte-oriented on purpose: the seam's providers own typed keys; this component talks
/// in the standardized FIPS 203 encodings so the 043 provider can wrap it without
/// copying key material through additional representations.
pub struct AwsLcMlKem1024;

impl AwsLcMlKem1024 {
    /// Generate a keypair inside the AWS-LC module.
    ///
    /// Returns `(ek_bytes, expanded_dk_bytes)`. The secret half is `Zeroizing` so the
    /// exported copy is wiped when dropped; AWS-LC wipes its internal copy itself.
    pub fn keygen() -> Result<
        (
            [u8; MLKEM1024_EK_BYTES],
            Zeroizing<[u8; MLKEM1024_DK_EXPANDED_BYTES]>,
        ),
        EncodingError,
    > {
        let dk = DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| EncodingError)?;
        let ek = dk.encapsulation_key().map_err(|_| EncodingError)?;
        let ek_bytes = ek.key_bytes().map_err(|_| EncodingError)?;
        let dk_bytes = dk.key_bytes().map_err(|_| EncodingError)?;
        if ek_bytes.as_ref().len() != MLKEM1024_EK_BYTES
            || dk_bytes.as_ref().len() != MLKEM1024_DK_EXPANDED_BYTES
        {
            return Err(EncodingError);
        }
        let mut ek_out = [0u8; MLKEM1024_EK_BYTES];
        ek_out.copy_from_slice(ek_bytes.as_ref());
        let mut dk_out = Zeroizing::new([0u8; MLKEM1024_DK_EXPANDED_BYTES]);
        dk_out.copy_from_slice(dk_bytes.as_ref());
        Ok((ek_out, dk_out))
    }

    /// Encapsulate to a serialized encapsulation key. Randomness is the AWS-LC module's
    /// internal DRBG (no caller-supplied entropy, no deterministic mode).
    pub fn encapsulate(
        ek_bytes: &[u8],
    ) -> Result<
        (
            [u8; MLKEM1024_CT_BYTES],
            Zeroizing<[u8; MLKEM_SHARED_BYTES]>,
        ),
        EncodingError,
    > {
        if ek_bytes.len() != MLKEM1024_EK_BYTES {
            return Err(EncodingError);
        }
        let ek = EncapsulationKey::new(&ML_KEM_1024, ek_bytes).map_err(|_| EncodingError)?;
        let (ct, ss) = ek.encapsulate().map_err(|_| EncodingError)?;
        if ct.as_ref().len() != MLKEM1024_CT_BYTES || ss.as_ref().len() != MLKEM_SHARED_BYTES {
            return Err(EncodingError);
        }
        let mut ct_out = [0u8; MLKEM1024_CT_BYTES];
        ct_out.copy_from_slice(ct.as_ref());
        let mut ss_out = Zeroizing::new([0u8; MLKEM_SHARED_BYTES]);
        ss_out.copy_from_slice(ss.as_ref());
        Ok((ct_out, ss_out))
    }

    /// Decapsulate with an expanded (3168-byte) decapsulation key.
    ///
    /// Length checks fail closed BEFORE key material is touched, mirroring the
    /// [`crate::backend::KemProvider`] contract.
    pub fn decapsulate(
        dk_expanded: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<[u8; MLKEM_SHARED_BYTES]>, DecryptionError> {
        if dk_expanded.len() != MLKEM1024_DK_EXPANDED_BYTES || ct.len() != MLKEM1024_CT_BYTES {
            return Err(DecryptionError);
        }
        let dk = DecapsulationKey::new(&ML_KEM_1024, dk_expanded).map_err(|_| DecryptionError)?;
        let ss = dk
            .decapsulate(Ciphertext::from(ct))
            .map_err(|_| DecryptionError)?;
        if ss.as_ref().len() != MLKEM_SHARED_BYTES {
            return Err(DecryptionError);
        }
        let mut out = Zeroizing::new([0u8; MLKEM_SHARED_BYTES]);
        out.copy_from_slice(ss.as_ref());
        Ok(out)
    }
}

// Measured limitation (packet 039, recorded): `aws-lc-rs` 1.17.1 can derive/marshal an
// encapsulation key only from a GENERATED `DecapsulationKey` — on a key built via raw
// import (`DecapsulationKey::new`) the ek marshal fails. Consequence: a fips provider
// must persist the ek alongside the dk rather than re-deriving it (the `0xA4` public
// key already serializes the ek, so this costs nothing at 043). The differential suite
// proves import-layout correctness via vector-ek/imported-dk agreement instead.

/// AES-256-GCM tag length — identical constant to `wire_v2::TAG_LEN`; restated here so
/// the component has no dependency on the codec module.
const AEAD_TAG_BYTES: usize = 16;

/// AES-256-GCM executed inside AWS-LC (packet 040).
///
/// Signatures mirror `crate::aead::{aead_seal, aead_open}` exactly — the CryptoBackend
/// method shape — and the output format is the same `ciphertext || tag[16]`. AES-GCM
/// is fully deterministic given (key, nonce), so the differential gate for this
/// component is exact byte-identity against the RustCrypto path
/// (`tests/awslc_aead_differential.rs`), a stronger bar than the KEM's interop gate.
pub struct AwsLcAes256Gcm;

impl AwsLcAes256Gcm {
    /// **Production seal — approved GCM IV Scenario 2** (packet 056). The module GENERATES the
    /// 96-bit nonce internally via `RandomizedNonceKey` (`EVP_aead_aes_256_gcm_randnonce`,
    /// SP 800-38D §8.2.2) and returns `(nonce, ciphertext || tag)`. The caller never chooses
    /// the IV — that was the External-IV mode packet 055 found outside the approved scenarios.
    /// `seal_in_place_separate_tag` keeps the wire body byte-compatible with the RustCrypto
    /// path (`ct || tag`, nonce stored separately in `header[86..98]`), not the raw randnonce
    /// blob layout. This is the ONLY seal the production seam (`AwsLcBackend::aead_seal`) uses.
    pub fn seal_randnonce(
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), EncodingError> {
        let sealing_key = RandomizedNonceKey::new(&AES_256_GCM, key).map_err(|_| EncodingError)?;
        let mut in_out = Vec::with_capacity(plaintext.len() + AEAD_TAG_BYTES);
        in_out.extend_from_slice(plaintext);
        let (nonce, tag) = sealing_key
            .seal_in_place_separate_tag(Aad::from(aad), &mut in_out)
            .map_err(|_| EncodingError)?;
        in_out.extend_from_slice(tag.as_ref());
        let nonce_bytes: [u8; 12] = *nonce.as_ref();
        Ok((nonce_bytes, in_out))
    }

    /// **Test-only fixed-nonce seal** (NOT the production path). Retained so the ACVP/Wycheproof
    /// known-answer vectors and the RustCrypto-vs-AWS-LC byte-identity differential can exercise
    /// the AES-GCM *primitive* with a caller-chosen IV. The production seam never calls this;
    /// it is not a GCM IV scenario and makes no compliance claim — it only proves the primitive
    /// is correct against fixed-IV test vectors.
    pub fn seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncodingError> {
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| EncodingError)?;
        let sealing_key = LessSafeKey::new(unbound);
        let mut in_out = Vec::with_capacity(plaintext.len() + AEAD_TAG_BYTES);
        in_out.extend_from_slice(plaintext);
        sealing_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| EncodingError)?;
        Ok(in_out)
    }

    /// Open: verifies the tag, returns the plaintext. Fail-closed. Opening always takes an
    /// explicit nonce (read from `header[86..98]`); there is no IV-generation scenario for
    /// decryption, so this one path serves both production and the KAT/differential tests, and
    /// a fips build can decrypt any envelope produced by either backend.
    pub fn open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        if ciphertext.len() < AEAD_TAG_BYTES {
            return Err(DecryptionError);
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| DecryptionError)?;
        let opening_key = LessSafeKey::new(unbound);
        let mut in_out = ciphertext.to_vec();
        let plaintext_len = opening_key
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| DecryptionError)?
            .len();
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }
}

/// Hash functions executed inside AWS-LC (packet 041).
///
/// Shapes mirror `CryptoBackend::{sha256, sha3_256}`. SHA3-256 is exposed by
/// `aws-lc-rs` 1.17.1 (`digest::SHA3_256`); whether it executes in the FIPS-approved
/// mode of the validated module is a security-policy question answered with a citation
/// at packet 044/046 — availability here is an API fact, not an approval claim.
pub struct AwsLcHash;

impl AwsLcHash {
    /// SHA-256 one-shot digest.
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let digest = lc_digest::digest(&lc_digest::SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    /// SHA3-256 one-shot digest.
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        let digest = lc_digest::digest(&lc_digest::SHA3_256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
}

/// Uncompressed SEC1 P-384 point: `0x04 || x[48] || y[48]`.
const P384_POINT_BYTES: usize = 97;
/// SEC1 uncompressed tag — decision D2: the ONLY accepted encoding, enforced in our
/// code on every backend (injectivity of the recipient-binding hash must not depend
/// on which library parses the point).
const SEC1_TAG_UNCOMPRESSED: u8 = 0x04;
/// P-384 scalar width.
const P384_SCALAR_BYTES: usize = 48;
/// ECDH output: the x-coordinate only.
const P384_SHARED_BYTES: usize = 48;

/// P-384 ECDH executed inside AWS-LC (packet 042).
///
/// Mirrors the two classical arms of `kem_p384.rs`: the static-scalar arm
/// (decapsulate: `diffie_hellman(scalar, ephemeral_point)`) and the ephemeral arm
/// (encapsulate: generate, export uncompressed SEC1, agree with the recipient key).
/// D2 policy (uncompressed-only, tag-checked) is enforced HERE, before AWS-LC parses
/// anything — Wycheproof's compressed "valid" encodings are deliberately rejected.
pub struct AwsLcEcdhP384;

impl AwsLcEcdhP384 {
    fn check_point(peer_sec1: &[u8]) -> Result<(), ()> {
        if peer_sec1.len() != P384_POINT_BYTES || peer_sec1[0] != SEC1_TAG_UNCOMPRESSED {
            return Err(());
        }
        Ok(())
    }

    /// Static-scalar arm: `x = ECDH(scalar, peer_point)`. Fail-closed on lengths,
    /// tag, scalar range, and off-curve points (AWS-LC validates the point).
    pub fn ecdh(
        scalar: &[u8],
        peer_sec1: &[u8],
    ) -> Result<[u8; P384_SHARED_BYTES], DecryptionError> {
        if scalar.len() != P384_SCALAR_BYTES {
            return Err(DecryptionError);
        }
        Self::check_point(peer_sec1).map_err(|()| DecryptionError)?;
        let private = lc_agreement::PrivateKey::from_private_key(&lc_agreement::ECDH_P384, scalar)
            .map_err(|_| DecryptionError)?;
        let peer = lc_agreement::UnparsedPublicKey::new(&lc_agreement::ECDH_P384, peer_sec1);
        lc_agreement::agree(&private, peer, DecryptionError, |km| {
            if km.len() != P384_SHARED_BYTES {
                return Err(DecryptionError);
            }
            let mut out = [0u8; P384_SHARED_BYTES];
            out.copy_from_slice(km);
            Ok(out)
        })
    }

    /// Ephemeral arm: generate inside AWS-LC, return
    /// `(ephemeral_pub_sec1_uncompressed[97], x[48])`.
    pub fn ephemeral_ecdh(
        peer_sec1: &[u8],
    ) -> Result<([u8; P384_POINT_BYTES], Zeroizing<[u8; P384_SHARED_BYTES]>), EncodingError> {
        Self::check_point(peer_sec1).map_err(|()| EncodingError)?;
        let private = lc_agreement::PrivateKey::generate(&lc_agreement::ECDH_P384)
            .map_err(|_| EncodingError)?;
        let public = private.compute_public_key().map_err(|_| EncodingError)?;
        if public.as_ref().len() != P384_POINT_BYTES || public.as_ref()[0] != SEC1_TAG_UNCOMPRESSED
        {
            return Err(EncodingError);
        }
        let mut pub_out = [0u8; P384_POINT_BYTES];
        pub_out.copy_from_slice(public.as_ref());

        let peer = lc_agreement::UnparsedPublicKey::new(&lc_agreement::ECDH_P384, peer_sec1);
        let shared = lc_agreement::agree(&private, peer, EncodingError, |km| {
            if km.len() != P384_SHARED_BYTES {
                return Err(EncodingError);
            }
            let mut out = Zeroizing::new([0u8; P384_SHARED_BYTES]);
            out.copy_from_slice(km);
            Ok(out)
        })?;
        Ok((pub_out, shared))
    }
}

/// Arbitrary-length HKDF output size for `aws_lc_rs::hkdf`'s ring-style `KeyType`.
struct OkmLen(usize);

impl lc_hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA256 executed inside AWS-LC (packet 041).
///
/// Shape mirrors `CryptoBackend::hkdf_sha256` exactly: `salt: None` uses RFC 5869
/// zero-salt semantics (`Salt::none`), matching RustCrypto's `Hkdf::new(None, ikm)`.
pub struct AwsLcHkdfSha256;

impl AwsLcHkdfSha256 {
    /// Extract-then-expand; fills `okm`. Errors on an out-of-range requested length.
    pub fn derive(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), EncodingError> {
        let salt = match salt {
            Some(bytes) => lc_hkdf::Salt::new(lc_hkdf::HKDF_SHA256, bytes),
            None => lc_hkdf::Salt::none(lc_hkdf::HKDF_SHA256),
        };
        let prk = salt.extract(ikm);
        let info_parts = [info];
        let okm_material = prk
            .expand(&info_parts, OkmLen(okm.len()))
            .map_err(|_| EncodingError)?;
        okm_material.fill(okm).map_err(|_| EncodingError)
    }
}

// ---------------------------------------------------------------------------
// The 0xA4 hybrid provider on AWS-LC (packet 043)
// ---------------------------------------------------------------------------

/// Hybrid P-384 + ML-KEM-1024 provider executing inside AWS-LC (suite `0xA4`).
///
/// Reuses the RustCrypto provider's key types and serializations byte-for-byte
/// (`P384MlKem1024PublicKey`/`SecretKey`, 1665/112 bytes), so the SDK, FFI, and every
/// stored key work identically on both backends. Only the *operations* differ.
///
/// **Boundary caveat (decision recorded in packet 043, quoted at 046):** ML-KEM key
/// expansion from the stored D3 seed, and key GENERATION for both arms, use the
/// pure-Rust key schedule (`ml-kem`/`p384` crates) — AWS-LC exposes no seed import
/// (packet-039 finding) and no raw scalar export. All envelope cryptographic
/// OPERATIONS (ML-KEM encapsulate/decapsulate, P-384 ECDH, AEAD, KDF, hashes) execute
/// in AWS-LC. Claim language must never exceed this.
pub struct AwsLcHybridP384MlKem1024Provider;

impl AwsLcHybridP384MlKem1024Provider {
    /// Derive the FIPS 203 expanded dk from the stored D3 seed (RustCrypto key
    /// schedule — the documented bridge).
    #[allow(deprecated)]
    fn expanded_dk_from_seed(seed: &[u8; 64]) -> Zeroizing<[u8; MLKEM1024_DK_EXPANDED_BYTES]> {
        use ml_kem::{ExpandedKeyEncoding, Seed};
        let dk = ml_kem::ml_kem_1024::DecapsulationKey::from_seed(Seed::from(*seed));
        let mut out = Zeroizing::new([0u8; MLKEM1024_DK_EXPANDED_BYTES]);
        out.copy_from_slice(dk.to_expanded_bytes().as_ref());
        out
    }

    /// Derive the ML-KEM ek bytes from the stored D3 seed (RustCrypto key schedule).
    fn ek_from_seed(seed: &[u8; 64]) -> [u8; MLKEM1024_EK_BYTES] {
        use ml_kem::{kem::KeyExport, Seed};
        let dk = ml_kem::ml_kem_1024::DecapsulationKey::from_seed(Seed::from(*seed));
        let mut out = [0u8; MLKEM1024_EK_BYTES];
        out.copy_from_slice(dk.encapsulation_key().to_bytes().as_ref());
        out
    }
}

impl KemProvider for AwsLcHybridP384MlKem1024Provider {
    // Identical constants to the RustCrypto provider — same suite byte, same wire.
    const SUITE_KEM: u8 = crate::wire::SUITE_KEM_HYBRID_P384_MLKEM1024;
    const KEM_CIPHERTEXT_BYTES: usize = P384_POINT_BYTES + MLKEM1024_CT_BYTES;
    const KEM_PUBLIC_KEY_BYTES: usize = P384_POINT_BYTES + MLKEM1024_EK_BYTES;
    const KEM_SECRET_KEY_BYTES: usize = P384_SCALAR_BYTES + 64;

    type PublicKey = P384MlKem1024PublicKey;
    type SecretKey = P384MlKem1024SecretKey;

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        // Key GENERATION uses the pure-Rust schedule (boundary caveat above): the D3
        // 112-byte secret format requires the seed and raw scalar, which AWS-LC does
        // not expose. Assembled through the public validated constructors so both
        // arms are checked exactly as on the default backend.
        use p384::elliptic_curve::sec1::ToSec1Point;
        use p384::elliptic_curve::Generate;
        use rand_core::{OsRng, RngCore};

        let p384_sk = p384::SecretKey::generate();
        let mut seed = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(seed.as_mut());

        let mut sk_bytes = Zeroizing::new([0u8; 112]);
        sk_bytes[..48].copy_from_slice(p384_sk.to_bytes().as_slice());
        sk_bytes[48..].copy_from_slice(&*seed);
        let sk = P384MlKem1024SecretKey::from_bytes(&*sk_bytes)
            .expect("freshly generated key material must parse");

        let mut pk_bytes = [0u8; 1665];
        pk_bytes[..97].copy_from_slice(
            p384_sk
                .public_key()
                .as_affine()
                .to_sec1_point(false)
                .as_ref(),
        );
        pk_bytes[97..].copy_from_slice(&Self::ek_from_seed(&seed));
        let pk = P384MlKem1024PublicKey::from_bytes(&pk_bytes)
            .expect("freshly generated public material must parse");
        (pk, sk)
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError> {
        let pk_bytes = pk.to_bytes();
        let recipient_point = &pk_bytes[..P384_POINT_BYTES];
        let mlkem_ek = &pk_bytes[P384_POINT_BYTES..];

        // Both operations inside AWS-LC.
        let (eph_pub, x) = AwsLcEcdhP384::ephemeral_ecdh(recipient_point)?;
        let (mlkem_ct, mlkem_ss) = AwsLcMlKem1024::encapsulate(mlkem_ek)?;

        let mut shared = Zeroizing::new(Vec::with_capacity(P384_SHARED_BYTES + MLKEM_SHARED_BYTES));
        shared.extend_from_slice(&x[..]);
        shared.extend_from_slice(&mlkem_ss[..]);

        let mut kem_ct = Vec::with_capacity(Self::KEM_CIPHERTEXT_BYTES);
        kem_ct.extend_from_slice(&eph_pub);
        kem_ct.extend_from_slice(&mlkem_ct);
        Ok((shared, kem_ct))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
        if ct.len() != Self::KEM_CIPHERTEXT_BYTES {
            return Err(DecryptionError);
        }
        let sk_bytes = Zeroizing::new(sk.to_bytes());
        let scalar = &sk_bytes[..P384_SCALAR_BYTES];
        let mut seed = Zeroizing::new([0u8; 64]);
        seed.copy_from_slice(&sk_bytes[P384_SCALAR_BYTES..]);

        // ECDH inside AWS-LC (validates the ephemeral point: D2 tag + on-curve).
        let x = AwsLcEcdhP384::ecdh(scalar, &ct[..P384_POINT_BYTES])?;
        // ML-KEM decapsulation inside AWS-LC; dk expanded from the seed via the
        // documented RustCrypto key-schedule bridge.
        let dk = Self::expanded_dk_from_seed(&seed);
        let mlkem_ss = AwsLcMlKem1024::decapsulate(&dk[..], &ct[P384_POINT_BYTES..])?;

        let mut shared = Zeroizing::new(Vec::with_capacity(P384_SHARED_BYTES + MLKEM_SHARED_BYTES));
        shared.extend_from_slice(&x[..]);
        shared.extend_from_slice(&mlkem_ss[..]);
        Ok(shared)
    }

    fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8> {
        pk.to_bytes().to_vec()
    }

    fn public_key_of(sk: &Self::SecretKey) -> Self::PublicKey {
        let sk_bytes = Zeroizing::new(sk.to_bytes());
        let mut seed = Zeroizing::new([0u8; 64]);
        seed.copy_from_slice(&sk_bytes[P384_SCALAR_BYTES..]);

        // P-384 public derivation inside AWS-LC (raw scalar import + compute).
        let mut pk_bytes = [0u8; 1665];
        let private = lc_agreement::PrivateKey::from_private_key(
            &lc_agreement::ECDH_P384,
            &sk_bytes[..P384_SCALAR_BYTES],
        )
        .expect("stored scalar was validated at construction");
        let public = private
            .compute_public_key()
            .expect("public derivation from a valid scalar");
        pk_bytes[..97].copy_from_slice(public.as_ref());
        pk_bytes[97..].copy_from_slice(&Self::ek_from_seed(&seed));
        P384MlKem1024PublicKey::from_bytes(&pk_bytes).expect("derived public material must parse")
    }
}

// ---------------------------------------------------------------------------
// The backend (packet 043): CryptoBackend on AWS-LC
// ---------------------------------------------------------------------------

/// The AWS-LC backend — selected by `--features fips` at the `ActiveBackend` alias
/// (SEAM_DESIGN §3, now live).
///
/// `KemA3` stays the RustCrypto X25519 hybrid: the FIPS path is `0xA4`-only (PRD
/// NG2), and `0xA3` envelopes remain byte-identical on fips builds because the codec
/// routes hash/KDF/AEAD through this backend while the `0xA3` KEM arms are untouched
/// RustCrypto.
pub struct AwsLcBackend;

impl CryptoBackend for AwsLcBackend {
    type KemA3 = crate::kem::HybridX25519MlKem768Provider;
    type KemA4 = AwsLcHybridP384MlKem1024Provider;

    fn sha256(data: &[u8]) -> [u8; 32] {
        AwsLcHash::sha256(data)
    }

    fn sha3_256(data: &[u8]) -> [u8; 32] {
        AwsLcHash::sha3_256(data)
    }

    fn hkdf_sha256(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), EncodingError> {
        AwsLcHkdfSha256::derive(salt, ikm, info, okm)
    }

    fn aead_seal(
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), EncodingError> {
        AwsLcAes256Gcm::seal_randnonce(key, plaintext, aad)
    }

    fn aead_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        AwsLcAes256Gcm::open(key, nonce, ciphertext, aad)
    }
}

// ---------------------------------------------------------------------------
// FIPS module status surface (packet 044)
// ---------------------------------------------------------------------------

/// The AWS-LC FIPS module version this build pins, from the vendored
/// `aws-lc-fips-sys 0.13.11` headers (`AWSLC_VERSION_NUMBER_STRING`).
///
/// **Validation status (packet 051, 2026-08-04): this is the CMVP-VALIDATED build.**
/// `AWS-LC FIPS 3.1.0` is the exact module version on certificates **#5298**
/// (dynamic, validated 2026-06-03) and **#5314** (static, 2026-06-05), both active
/// through 2031. The pin was moved here from 3.4.0 *because* 3.4.0 is a later,
/// unvalidated build — validated is not the same as latest, and this trade accepts
/// fewer upstream fixes in exchange for a certificate.
///
/// **What this still does NOT license.** Citadel's operational environments
/// (Ubuntu/WSL2, Debian bookworm containers) are not among the certificate's tested
/// environments — Amazon Linux 2023 on Graviton4 `r8g.metal-24xl` and Intel Xeon
/// `c6i.metal` — and the policy records **"Vendor-Affirmed Operational Environments:
/// N/A for this module."** Per CMVP's porting statement, CMVP makes no statement
/// about operation outside the tested environments. So: validated *build*, ported
/// environment, disclosed. Never "FIPS validated product" or "FIPS compliant".
///
/// **This constant is the RECORDED pin; `fips_module_version_runtime()` verifies it
/// against the linked module at runtime** — see `pinned_module_version_matches_linked_module`.
/// Packet 054 made the guard real via `aws-lc-fips-sys`'s `OpenSSL_version` FFI, after 053
/// established that adopting `aws-lc-rs`'s own version API is impossible without losing this
/// pin: `fips_version()`/`awslc_version()` arrived in aws-lc-rs **1.17.2**, and every
/// aws-lc-rs version carrying them requires `aws-lc-fips-sys >= 0.13.16` (module **3.4.0**),
/// which is disjoint from the validated 0.13.11 (module **3.1.0**). Do not "adopt 1.17.3 to
/// make this real" — that forces 3.4.0. See work packets 053/054 and
/// `citadel/fips-backend/FIPS_MODE_STATUS.md`.
pub const FIPS_MODULE_VERSION: &str = "AWS-LC-FIPS 3.1.0";

/// Runtime assertion that the linked library IS the FIPS module and operational.
///
/// `Ok(())` means `FIPS_mode() == 1`, which can only be observed if the module's
/// constructor completed — and that constructor performs the integrity check
/// (HMAC over the module text; on mismatch the module "calls `exit` in an infinite
/// loop" per upstream FIPS.md) and the power-on self-tests. Reaching this assertion
/// alive with `Ok` is therefore evidence the self-tests passed; a corrupted module
/// never gets here (fail-closed). Surfaced for the 047 health endpoint.
pub fn fips_module_status() -> Result<(), &'static str> {
    aws_lc_rs::try_fips_mode()
}

/// Runtime assertion that the SP 800-90B CPU jitter entropy source is in use
/// (NIST entropy certificate #E77 per upstream FIPS.md).
pub fn fips_entropy_status() -> Result<(), &'static str> {
    aws_lc_rs::try_fips_cpu_jitter_entropy()
}

/// The version string of the AWS-LC FIPS module **actually linked** into this
/// process, read at runtime from the module via `OpenSSL_version` (e.g.
/// `"AWS-LC FIPS 3.1.0"`). This is the real probe behind
/// `pinned_module_version_matches_linked_module`: unlike the `FIPS_MODULE_VERSION`
/// constant, it fails to match if a `cargo update` drifts the module off the
/// CMVP-validated 0.13.11 / 3.1.0 build (packet 054; 053 explains why aws-lc-rs's
/// own `fips_version()` cannot be used without abandoning that pin).
///
/// `aws_lc_fips_sys::OpenSSL_version` is a real exported FFI function (robust across
/// the crate's prebuilt and bindgen-generated binding modes), unlike the
/// `OPENSSL_VERSION_TEXT` macro constant which bindgen may omit.
///
/// This is the **only** `unsafe` in the crate: it carries a scoped `#[allow(unsafe_code)]`
/// against the crate-wide `#![deny(unsafe_code)]`, justified below, because reading a C
/// string from the linked module is inherently an FFI operation. `core::ffi` is used
/// (not `std`) so the probe compiles under the crate's `no_std` configuration.
#[allow(unsafe_code)] // sole FFI in the crate; reads a static C version string, no writes
pub fn fips_module_version_runtime() -> &'static str {
    use core::ffi::{c_int, CStr};
    // `OpenSSL_version(OPENSSL_VERSION)` — OPENSSL_VERSION is the integer selector `0`;
    // written as a literal so the probe does not depend on bindgen emitting the macro
    // constant. AWS-LC returns a string such as "AWS-LC FIPS 3.1.0".
    const OPENSSL_VERSION_SELECTOR: c_int = 0;
    // SAFETY: `OpenSSL_version` returns a pointer to a static, NUL-terminated C string
    // owned by the linked module and valid for the entire process lifetime; we only read
    // it, never free or mutate it. The selector `0` (OPENSSL_VERSION) is always valid, and
    // AWS-LC's version string is ASCII, so `to_str` cannot fail in practice.
    let ptr = unsafe { aws_lc_fips_sys::OpenSSL_version(OPENSSL_VERSION_SELECTOR) };
    // SAFETY: as above — `ptr` is a valid, static, NUL-terminated C string.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("AWS-LC module version string must be valid UTF-8")
}

/// Cross-PROVIDER differentials (packet 043): the RustCrypto and AWS-LC `0xA4`
/// providers against each other through the crate-private generic codec — the
/// envelope-level half of the seam's "provider is the only thing that varies" claim.
/// Unit tests because `wire_v2::{seal, open}` are deliberately not public.
#[cfg(test)]
mod cross_provider_tests {
    use super::AwsLcHybridP384MlKem1024Provider as LcP4;
    use crate::backend::KemProvider;
    use crate::kem_p384::{
        HybridP384MlKem1024Provider as RcP4, P384MlKem1024PublicKey, P384MlKem1024SecretKey,
    };
    use crate::wire_v2;

    const ROUNDS: usize = 50;

    fn reload(
        pk: &P384MlKem1024PublicKey,
        sk: &P384MlKem1024SecretKey,
    ) -> (P384MlKem1024PublicKey, P384MlKem1024SecretKey) {
        (
            P384MlKem1024PublicKey::from_bytes(&pk.to_bytes()).expect("pk reload"),
            P384MlKem1024SecretKey::from_bytes(&sk.to_bytes()).expect("sk reload"),
        )
    }

    /// KEM-contract agreement in both key directions, same serialized keys.
    #[test]
    fn kem_level_cross_provider_agreement() {
        for round in 0..ROUNDS {
            let (pk, sk) = RcP4::keygen();
            let (pk_lc, _sk_lc) = reload(&pk, &sk);

            let (ss_enc, ct) = LcP4::encapsulate(&pk_lc).expect("awslc encapsulate");
            let ss_dec = RcP4::decapsulate(&sk, &ct).expect("rustcrypto decapsulate");
            assert_eq!(&*ss_enc, &*ss_dec, "rc-keys direction, round {round}");

            let (pk2, sk2) = LcP4::keygen();
            let (pk2_rc, sk2_rc) = reload(&pk2, &sk2);
            let (ss_enc2, ct2) = RcP4::encapsulate(&pk2_rc).expect("rustcrypto encapsulate");
            let ss_dec2 = LcP4::decapsulate(&sk2_rc, &ct2).expect("awslc decapsulate");
            assert_eq!(&*ss_enc2, &*ss_dec2, "lc-keys direction, round {round}");
        }
    }

    /// Full envelopes sealed under one provider open under the other, same keys.
    #[test]
    fn envelope_cross_provider_interop() {
        for round in 0..ROUNDS {
            let (pk, sk) = RcP4::keygen();
            let (pk_lc, sk_lc) = reload(&pk, &sk);
            let msg = alloc::format!("cross-provider envelope {round}");

            let env_rc =
                wire_v2::seal::<RcP4>(&pk, msg.as_bytes(), b"aad", b"ctx").expect("rc seal");
            let opened = wire_v2::open::<LcP4>(&sk_lc, &env_rc, b"aad", b"ctx")
                .expect("awslc provider opens rc-provider envelope");
            assert_eq!(opened, msg.as_bytes(), "rc->lc round {round}");

            let env_lc =
                wire_v2::seal::<LcP4>(&pk_lc, msg.as_bytes(), b"aad", b"ctx").expect("lc seal");
            let opened2 = wire_v2::open::<RcP4>(&sk, &env_lc, b"aad", b"ctx")
                .expect("rc provider opens awslc-provider envelope");
            assert_eq!(opened2, msg.as_bytes(), "lc->rc round {round}");

            assert_eq!(
                env_rc.len(),
                env_lc.len(),
                "wire sizes agree, round {round}"
            );
            assert_eq!(env_rc[6], 0xA4);
            assert_eq!(env_lc[6], 0xA4);
        }
    }
}
