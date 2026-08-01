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
