// SPDX-License-Identifier: AGPL-3.0-or-later
//! ML-KEM-1024 via AWS-LC — first component of the FIPS backend (packet 039).
//!
//! Compiled ONLY under `--features fips`. This is the component layer: a thin, typed,
//! byte-oriented wrapper over `aws_lc_rs::kem` so later packets can slot it behind the
//! packet-037 seam. [`crate::backend::ActiveBackend`] still resolves to RustCrypto
//! unconditionally — the provider fold and the `fips` selection switch are packet 043.
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

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::agreement as lc_agreement;
use aws_lc_rs::digest as lc_digest;
use aws_lc_rs::hkdf as lc_hkdf;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use zeroize::Zeroizing;

use crate::error::{DecryptionError, EncodingError};

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
    /// Seal: returns `ciphertext || tag`. Fail-closed on any AWS-LC error.
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

    /// Open: verifies the tag, returns the plaintext. Fail-closed.
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
