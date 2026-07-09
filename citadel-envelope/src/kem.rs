// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid KEM: X25519 + ML-KEM-768
//!
//! Combines classical ECDH (X25519) with post-quantum KEM (ML-KEM-768).
//! Security holds if *either* primitive remains secure (defense-in-depth).
//!
//! ML-KEM-768 provider: PQClean reference implementation via pqcrypto-mlkem.
//! Switched from libcrux-ml-kem 0.0.9 after dudect timing validation found
//! key-material-dependent timing in libcrux decapsulation. See
//! PROVIDER_DECISION_LOG.md.
//!
//! Key serialization:
//!   PublicKey  = x25519_pk[32] || mlkem_ek[1184]   (1216 bytes)
//!   SecretKey  = x25519_sk[32] || mlkem_dk[2400]   (2432 bytes)
//!
//! KEM ciphertext (on wire):
//!   x25519_ephemeral_pk[32] || mlkem_ct[1088]      (1120 bytes)
//!
//! Combined shared secret (fed to KDF):
//!   x25519_dh[32] || mlkem_ss[32]                  (64 bytes)

extern crate alloc;
use alloc::vec::Vec;

use pqcrypto_mlkem::mlkem768 as pq_mlkem;
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{DecryptionError, EncodingError};
use crate::wire::{
    KEM_CIPHERTEXT_BYTES, KEM_PUBLIC_KEY_BYTES, KEM_SECRET_KEY_BYTES, MLKEM_PUBLIC_KEY_BYTES,
    MLKEM_SECRET_KEY_BYTES, SHARED_SECRET_BYTES, X25519_KEY_BYTES,
};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Public key (hybrid)
// ---------------------------------------------------------------------------

/// Hybrid public key: X25519 public key + ML-KEM-768 encapsulation key.
#[derive(Clone)]
pub struct PublicKey {
    x25519: X25519PublicKey,
    mlkem_bytes: [u8; MLKEM_PUBLIC_KEY_BYTES],
}

impl PublicKey {
    pub(crate) fn from_parts_pq(x25519: X25519PublicKey, mlkem_pk: &pq_mlkem::PublicKey) -> Self {
        let mut mlkem_bytes = [0u8; MLKEM_PUBLIC_KEY_BYTES];
        mlkem_bytes.copy_from_slice(mlkem_pk.as_bytes());
        Self {
            x25519,
            mlkem_bytes,
        }
    }

    /// Serialize: x25519_pk[32] || mlkem_ek[1184]
    pub fn to_bytes(&self) -> [u8; KEM_PUBLIC_KEY_BYTES] {
        let mut out = [0u8; KEM_PUBLIC_KEY_BYTES];
        out[..X25519_KEY_BYTES].copy_from_slice(self.x25519.as_bytes());
        out[X25519_KEY_BYTES..].copy_from_slice(&self.mlkem_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecryptionError> {
        if bytes.len() != KEM_PUBLIC_KEY_BYTES {
            return Err(DecryptionError);
        }

        let x25519_bytes: [u8; X25519_KEY_BYTES] = bytes[..X25519_KEY_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let x25519 = X25519PublicKey::from(x25519_bytes);

        let mut mlkem_bytes = [0u8; MLKEM_PUBLIC_KEY_BYTES];
        mlkem_bytes.copy_from_slice(&bytes[X25519_KEY_BYTES..]);

        // Validate by attempting to parse
        pq_mlkem::PublicKey::from_bytes(&mlkem_bytes).map_err(|_| DecryptionError)?;

        Ok(Self {
            x25519,
            mlkem_bytes,
        })
    }

    pub(crate) fn x25519(&self) -> &X25519PublicKey {
        &self.x25519
    }

    pub(crate) fn mlkem_pk(&self) -> pq_mlkem::PublicKey {
        pq_mlkem::PublicKey::from_bytes(&self.mlkem_bytes).expect("validated at construction")
    }
}

// ---------------------------------------------------------------------------
// Secret key (hybrid)
// ---------------------------------------------------------------------------

/// Hybrid secret key: X25519 static secret + ML-KEM-768 decapsulation key.
///
/// Implements [`Drop`] to zeroize `mlkem_bytes` on destruction.
/// `x25519_dalek::StaticSecret` handles its own zeroization internally.
pub struct SecretKey {
    x25519: StaticSecret,
    mlkem_bytes: [u8; MLKEM_SECRET_KEY_BYTES],
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.mlkem_bytes.zeroize();
    }
}

impl SecretKey {
    pub(crate) fn from_parts_pq(x25519: StaticSecret, mlkem_sk: &pq_mlkem::SecretKey) -> Self {
        let mut mlkem_bytes = [0u8; MLKEM_SECRET_KEY_BYTES];
        mlkem_bytes.copy_from_slice(mlkem_sk.as_bytes());
        Self {
            x25519,
            mlkem_bytes,
        }
    }

    /// Serialize: x25519_sk[32] || mlkem_dk[2400]
    ///
    /// Returns a bare array. Callers storing this beyond immediate use
    /// should wrap in `Zeroizing::new(sk.to_bytes())`.
    pub fn to_bytes(&self) -> [u8; KEM_SECRET_KEY_BYTES] {
        let mut out = [0u8; KEM_SECRET_KEY_BYTES];
        out[..X25519_KEY_BYTES].copy_from_slice(&self.x25519.to_bytes());
        out[X25519_KEY_BYTES..].copy_from_slice(&self.mlkem_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecryptionError> {
        if bytes.len() != KEM_SECRET_KEY_BYTES {
            return Err(DecryptionError);
        }

        let mut x25519_bytes = Zeroizing::new([0u8; X25519_KEY_BYTES]);
        x25519_bytes.copy_from_slice(&bytes[..X25519_KEY_BYTES]);
        let x25519 = StaticSecret::from(*x25519_bytes);

        let mut mlkem_bytes = [0u8; MLKEM_SECRET_KEY_BYTES];
        mlkem_bytes.copy_from_slice(&bytes[X25519_KEY_BYTES..]);

        Ok(Self {
            x25519,
            mlkem_bytes,
        })
    }

    pub(crate) fn x25519(&self) -> &StaticSecret {
        &self.x25519
    }

    pub(crate) fn mlkem_sk(&self) -> pq_mlkem::SecretKey {
        pq_mlkem::SecretKey::from_bytes(&self.mlkem_bytes).expect("validated at construction")
    }
}

// ---------------------------------------------------------------------------
// Diagnostic helpers (used by timing benches)
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn diagnostic_x25519_decapsulate_only(
    sk: &SecretKey,
    ct: &[u8],
) -> Result<[u8; SHARED_SECRET_BYTES], DecryptionError> {
    if ct.len() != KEM_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let x25519_epk_bytes: [u8; X25519_KEY_BYTES] = ct[..X25519_KEY_BYTES]
        .try_into()
        .map_err(|_| DecryptionError)?;
    let x25519_epk = X25519PublicKey::from(x25519_epk_bytes);
    let x25519_ss = sk.x25519().diffie_hellman(&x25519_epk);

    let mut out = [0u8; SHARED_SECRET_BYTES];
    out.copy_from_slice(x25519_ss.as_bytes());
    Ok(out)
}

#[doc(hidden)]
pub fn diagnostic_mlkem_decapsulate_only(
    sk: &SecretKey,
    ct: &[u8],
) -> Result<[u8; SHARED_SECRET_BYTES], DecryptionError> {
    if ct.len() != KEM_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let mlkem_ct_bytes = &ct[X25519_KEY_BYTES..];
    let mlkem_ct = pq_mlkem::Ciphertext::from_bytes(mlkem_ct_bytes).map_err(|_| DecryptionError)?;
    let mlkem_ss = pq_mlkem::decapsulate(&mlkem_ct, &sk.mlkem_sk());

    let mut out = [0u8; SHARED_SECRET_BYTES];
    out.copy_from_slice(mlkem_ss.as_bytes());
    Ok(out)
}

#[doc(hidden)]
pub fn diagnostic_mlkem_decapsulate_from_key_bytes(
    sk_bytes: &[u8; KEM_SECRET_KEY_BYTES],
    ct: &[u8; KEM_CIPHERTEXT_BYTES],
) -> Result<[u8; SHARED_SECRET_BYTES], DecryptionError> {
    let mlkem_sk_bytes = &sk_bytes[X25519_KEY_BYTES..];
    let mlkem_ct_bytes = &ct[X25519_KEY_BYTES..];

    let mlkem_sk = pq_mlkem::SecretKey::from_bytes(mlkem_sk_bytes).map_err(|_| DecryptionError)?;
    let mlkem_ct = pq_mlkem::Ciphertext::from_bytes(mlkem_ct_bytes).map_err(|_| DecryptionError)?;
    let mlkem_ss = pq_mlkem::decapsulate(&mlkem_ct, &mlkem_sk);

    let mut out = [0u8; SHARED_SECRET_BYTES];
    out.copy_from_slice(mlkem_ss.as_bytes());
    Ok(out)
}

// ---------------------------------------------------------------------------
// KEM provider trait + hybrid implementation
// ---------------------------------------------------------------------------

pub trait KemProvider {
    fn keygen() -> (PublicKey, SecretKey);
    /// P011: Returns (Zeroizing<combined_shared_secret>, kem_ciphertext_bytes).
    /// Shared secret is wrapped in Zeroizing to ensure heap cleanup.
    fn encapsulate(pk: &PublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError>;
    /// P011: Returns Zeroizing<combined_shared_secret>.
    /// Shared secret is wrapped in Zeroizing to ensure heap cleanup.
    fn decapsulate(sk: &SecretKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptionError>;
}

/// Hybrid X25519 + ML-KEM-768 provider.
///
/// Combined shared secret = x25519_dh[32] || mlkem_ss[32] (64 bytes).
/// KEM ciphertext = x25519_ephemeral_pk[32] || mlkem_ct[1088] (1120 bytes).
pub struct HybridX25519MlKem768Provider;

impl KemProvider for HybridX25519MlKem768Provider {
    fn keygen() -> (PublicKey, SecretKey) {
        let x25519_sk = StaticSecret::random_from_rng(OsRng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        let (mlkem_pk, mlkem_sk) = pq_mlkem::keypair();

        (
            PublicKey::from_parts_pq(x25519_pk, &mlkem_pk),
            SecretKey::from_parts_pq(x25519_sk, &mlkem_sk),
        )
    }

    fn encapsulate(pk: &PublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError> {
        let x25519_eph = EphemeralSecret::random_from_rng(OsRng);
        let x25519_eph_pk = X25519PublicKey::from(&x25519_eph);
        let x25519_ss = x25519_eph.diffie_hellman(pk.x25519());

        let (mlkem_ss, mlkem_ct) = pq_mlkem::encapsulate(&pk.mlkem_pk());

        let mut combined_raw = Zeroizing::new([0u8; SHARED_SECRET_BYTES * 2]);
        combined_raw[..SHARED_SECRET_BYTES].copy_from_slice(x25519_ss.as_bytes());
        combined_raw[SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_bytes());
        let combined_ss = Zeroizing::new(combined_raw.to_vec());

        let mut kem_ct = Vec::with_capacity(KEM_CIPHERTEXT_BYTES);
        kem_ct.extend_from_slice(x25519_eph_pk.as_bytes());
        kem_ct.extend_from_slice(mlkem_ct.as_bytes());

        Ok((combined_ss, kem_ct))
    }

    fn decapsulate(sk: &SecretKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
        if ct.len() != KEM_CIPHERTEXT_BYTES {
            return Err(DecryptionError);
        }

        let x25519_epk_bytes: [u8; X25519_KEY_BYTES] = ct[..X25519_KEY_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let x25519_epk = X25519PublicKey::from(x25519_epk_bytes);

        let mlkem_ct_bytes = &ct[X25519_KEY_BYTES..];
        let mlkem_ct =
            pq_mlkem::Ciphertext::from_bytes(mlkem_ct_bytes).map_err(|_| DecryptionError)?;

        let x25519_ss = sk.x25519().diffie_hellman(&x25519_epk);
        let mlkem_ss = pq_mlkem::decapsulate(&mlkem_ct, &sk.mlkem_sk());

        let mut combined_raw = Zeroizing::new([0u8; SHARED_SECRET_BYTES * 2]);
        combined_raw[..SHARED_SECRET_BYTES].copy_from_slice(x25519_ss.as_bytes());
        combined_raw[SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_bytes());
        let combined_ss = Zeroizing::new(combined_raw.to_vec());

        Ok(combined_ss)
    }
}

// ---------------------------------------------------------------------------
// Backward-compatibility alias
// ---------------------------------------------------------------------------

/// Legacy alias — now backed by the hybrid provider.
pub type MlKem768Provider = HybridX25519MlKem768Provider;
