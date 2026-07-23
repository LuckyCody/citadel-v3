// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid KEM: X25519 + ML-KEM-768
//!
//! Combines classical ECDH (X25519) with post-quantum KEM (ML-KEM-768).
//! Security holds if *either* primitive remains secure (defense-in-depth).
//!
//! ML-KEM-768 provider: RustCrypto `ml-kem` 0.3.2.
//! Selected by the Packet 006 preregistered provider gate; see
//! PROVIDER_BAKEOFF_2026.md. Citadel v1 retains the legacy expanded private-key
//! encoding for compatibility while validating it at import.
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

#[cfg(feature = "kat")]
use ml_kem::Seed;
use ml_kem::{
    kem::{Decapsulate as MlKemDecapsulate, Encapsulate as MlKemEncapsulate, Kem, KeyExport},
    ml_kem_768::{
        Ciphertext as MlKemCiphertext, DecapsulationKey as MlKemSecretKey,
        EncapsulationKey as MlKemPublicKey,
    },
    MlKem768,
};
#[allow(deprecated)]
use ml_kem::{ml_kem_768::ExpandedDecapsulationKey, ExpandedKeyEncoding};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{DecryptionError, EncodingError};
use crate::wire::{
    KEM_CIPHERTEXT_BYTES, KEM_PUBLIC_KEY_BYTES, KEM_SECRET_KEY_BYTES, MLKEM_PUBLIC_KEY_BYTES,
    MLKEM_SECRET_KEY_BYTES, SHARED_SECRET_BYTES, X25519_KEY_BYTES,
};
use zeroize::Zeroizing;

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
    pub(crate) fn from_parts_mlkem(x25519: X25519PublicKey, mlkem_pk: &MlKemPublicKey) -> Self {
        let mut mlkem_bytes = [0u8; MLKEM_PUBLIC_KEY_BYTES];
        mlkem_bytes.copy_from_slice(mlkem_pk.to_bytes().as_ref());
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
        let encoded = mlkem_bytes.into();
        MlKemPublicKey::new(&encoded).map_err(|_| DecryptionError)?;

        Ok(Self {
            x25519,
            mlkem_bytes,
        })
    }

    pub(crate) fn x25519(&self) -> &X25519PublicKey {
        &self.x25519
    }

    pub(crate) fn mlkem_pk(&self) -> MlKemPublicKey {
        let encoded = self.mlkem_bytes.into();
        MlKemPublicKey::new(&encoded).expect("validated at construction")
    }
}

// ---------------------------------------------------------------------------
// Secret key (hybrid)
// ---------------------------------------------------------------------------

/// Hybrid secret key: X25519 static secret + ML-KEM-768 decapsulation key.
///
/// Both halves zeroize on destruction via their own types: the `ml-kem` crate's
/// `MlKemSecretKey` clears its material when the zeroize feature is enabled (the
/// pinned configuration), and `x25519_dalek::StaticSecret` handles its own
/// zeroization internally. This type therefore needs no explicit `Drop` impl.
pub struct SecretKey {
    x25519: StaticSecret,
    mlkem: MlKemSecretKey,
}

impl SecretKey {
    #[allow(deprecated)]
    pub(crate) fn from_parts_mlkem(x25519: StaticSecret, mlkem: MlKemSecretKey) -> Self {
        Self { x25519, mlkem }
    }

    /// Serialize: x25519_sk[32] || mlkem_dk[2400]
    ///
    /// Returns a bare array. Callers storing this beyond immediate use
    /// should wrap in `Zeroizing::new(sk.to_bytes())`.
    pub fn to_bytes(&self) -> [u8; KEM_SECRET_KEY_BYTES] {
        let mut out = [0u8; KEM_SECRET_KEY_BYTES];
        out[..X25519_KEY_BYTES].copy_from_slice(&self.x25519.to_bytes());
        #[allow(deprecated)]
        out[X25519_KEY_BYTES..].copy_from_slice(self.mlkem.to_expanded_bytes().as_ref());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecryptionError> {
        if bytes.len() != KEM_SECRET_KEY_BYTES {
            return Err(DecryptionError);
        }

        let mut x25519_bytes = Zeroizing::new([0u8; X25519_KEY_BYTES]);
        x25519_bytes.copy_from_slice(&bytes[..X25519_KEY_BYTES]);
        let x25519 = StaticSecret::from(*x25519_bytes);

        let mut mlkem_bytes = Zeroizing::new([0u8; MLKEM_SECRET_KEY_BYTES]);
        mlkem_bytes.copy_from_slice(&bytes[X25519_KEY_BYTES..]);

        // V1 compatibility retains the legacy expanded 2400-byte key encoding.
        // Validate it now rather than deferring malformed-key detection until use.
        #[allow(deprecated)]
        {
            let encoded: ExpandedDecapsulationKey = (*mlkem_bytes).into();
            let mlkem =
                MlKemSecretKey::from_expanded_bytes(&encoded).map_err(|_| DecryptionError)?;
            Ok(Self { x25519, mlkem })
        }
    }

    pub(crate) fn x25519(&self) -> &StaticSecret {
        &self.x25519
    }

    #[allow(deprecated)]
    pub(crate) fn mlkem_sk(&self) -> &MlKemSecretKey {
        &self.mlkem
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        let x25519 = X25519PublicKey::from(&self.x25519);
        PublicKey::from_parts_mlkem(x25519, self.mlkem.encapsulation_key())
    }
}

// ---------------------------------------------------------------------------
// Diagnostic helpers (used by timing benches ONLY)
//
// Feature-gated behind `timing-diagnostics` so they are NOT compiled into
// default/production builds (020-R hardening). These return raw intermediate KEM
// material for timing isolation and deliberately SKIP production checks (e.g. the
// X25519 contributory guard) — never call them outside a benchmark.
// ---------------------------------------------------------------------------

/// TIMING-DIAGNOSTIC ONLY. Returns the raw X25519 shared secret WITHOUT the
/// `was_contributory()` guard that production encapsulate/decapsulate enforce.
/// Not for production use; feature-gated out of default builds.
#[doc(hidden)]
#[cfg(feature = "timing-diagnostics")]
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
#[cfg(feature = "timing-diagnostics")]
pub fn diagnostic_mlkem_decapsulate_only(
    sk: &SecretKey,
    ct: &[u8],
) -> Result<[u8; SHARED_SECRET_BYTES], DecryptionError> {
    if ct.len() != KEM_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let mlkem_ct_bytes = &ct[X25519_KEY_BYTES..];
    let mlkem_ct_array: [u8; 1088] = mlkem_ct_bytes.try_into().map_err(|_| DecryptionError)?;
    let mlkem_ct: MlKemCiphertext = mlkem_ct_array.into();
    let mlkem_ss = sk.mlkem_sk().decapsulate(&mlkem_ct);

    let mut out = [0u8; SHARED_SECRET_BYTES];
    out.copy_from_slice(mlkem_ss.as_ref());
    Ok(out)
}

#[doc(hidden)]
#[cfg(feature = "timing-diagnostics")]
pub fn diagnostic_mlkem_decapsulate_from_key_bytes(
    sk_bytes: &[u8; KEM_SECRET_KEY_BYTES],
    ct: &[u8; KEM_CIPHERTEXT_BYTES],
) -> Result<[u8; SHARED_SECRET_BYTES], DecryptionError> {
    let mlkem_sk_bytes = &sk_bytes[X25519_KEY_BYTES..];
    let mlkem_ct_bytes = &ct[X25519_KEY_BYTES..];

    let mlkem_sk_array: [u8; MLKEM_SECRET_KEY_BYTES] =
        mlkem_sk_bytes.try_into().map_err(|_| DecryptionError)?;
    let mlkem_ct_array: [u8; 1088] = mlkem_ct_bytes.try_into().map_err(|_| DecryptionError)?;
    #[allow(deprecated)]
    let mlkem_sk =
        MlKemSecretKey::from_expanded_bytes(&mlkem_sk_array.into()).map_err(|_| DecryptionError)?;
    let mlkem_ct: MlKemCiphertext = mlkem_ct_array.into();
    let mlkem_ss = mlkem_sk.decapsulate(&mlkem_ct);

    let mut out = [0u8; SHARED_SECRET_BYTES];
    out.copy_from_slice(mlkem_ss.as_ref());
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

#[cfg(feature = "kat")]
impl HybridX25519MlKem768Provider {
    /// Deterministic FIPS 203 key generation for checked-in vectors only.
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn kat_mlkem_keygen(d: [u8; 32], z: [u8; 32]) -> ([u8; 1184], [u8; 2400]) {
        let mut seed_bytes = [0u8; 64];
        seed_bytes[..32].copy_from_slice(&d);
        seed_bytes[32..].copy_from_slice(&z);
        let dk = MlKemSecretKey::from_seed(Seed::from(seed_bytes));
        let ek = dk.encapsulation_key();
        let mut ek_out = [0u8; 1184];
        let mut dk_out = [0u8; 2400];
        ek_out.copy_from_slice(ek.to_bytes().as_ref());
        dk_out.copy_from_slice(dk.to_expanded_bytes().as_ref());
        (ek_out, dk_out)
    }

    /// Deterministic FIPS 203 encapsulation for checked-in vectors only.
    #[doc(hidden)]
    pub fn kat_mlkem_encapsulate(
        ek: &[u8; 1184],
        m: [u8; 32],
    ) -> Result<([u8; 1088], [u8; 32]), EncodingError> {
        let ek = MlKemPublicKey::new(&(*ek).into()).map_err(|_| EncodingError)?;
        let (ct, ss) = ek.encapsulate_deterministic(&m.into());
        let mut ct_out = [0u8; 1088];
        let mut ss_out = [0u8; 32];
        ct_out.copy_from_slice(ct.as_ref());
        ss_out.copy_from_slice(ss.as_ref());
        Ok((ct_out, ss_out))
    }

    /// FIPS 203 decapsulation for checked-in vectors, including implicit rejection.
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn kat_mlkem_decapsulate(
        dk: &[u8; 2400],
        ct: &[u8; 1088],
    ) -> Result<[u8; 32], DecryptionError> {
        let dk = MlKemSecretKey::from_expanded_bytes(&(*dk).into()).map_err(|_| DecryptionError)?;
        let ct: MlKemCiphertext = (*ct).into();
        let ss = dk.decapsulate(&ct);
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_ref());
        Ok(out)
    }

    /// Deterministic complete hybrid keypair for envelope-v2 vectors only.
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn kat_hybrid_keygen(
        x25519_secret: [u8; 32],
        d: [u8; 32],
        z: [u8; 32],
    ) -> (PublicKey, SecretKey) {
        let x25519 = StaticSecret::from(x25519_secret);
        let x25519_public = X25519PublicKey::from(&x25519);
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);
        let mlkem = MlKemSecretKey::from_seed(Seed::from(seed));
        let public = PublicKey::from_parts_mlkem(x25519_public, mlkem.encapsulation_key());
        (public, SecretKey::from_parts_mlkem(x25519, mlkem))
    }

    /// Deterministic complete hybrid encapsulation for envelope-v2 vectors only.
    #[doc(hidden)]
    pub fn kat_hybrid_encapsulate(
        pk: &PublicKey,
        x25519_ephemeral_secret: [u8; 32],
        m: [u8; 32],
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError> {
        let ephemeral = StaticSecret::from(x25519_ephemeral_secret);
        let ephemeral_public = X25519PublicKey::from(&ephemeral);
        let x25519_ss = ephemeral.diffie_hellman(pk.x25519());
        if !x25519_ss.was_contributory() {
            return Err(EncodingError);
        }
        let (mlkem_ct, mlkem_ss) = pk.mlkem_pk().encapsulate_deterministic(&m.into());

        let mut shared = Zeroizing::new(Vec::with_capacity(64));
        shared.extend_from_slice(x25519_ss.as_bytes());
        shared.extend_from_slice(mlkem_ss.as_ref());
        let mut kem_ct = Vec::with_capacity(KEM_CIPHERTEXT_BYTES);
        kem_ct.extend_from_slice(ephemeral_public.as_bytes());
        kem_ct.extend_from_slice(mlkem_ct.as_ref());
        Ok((shared, kem_ct))
    }
}

impl KemProvider for HybridX25519MlKem768Provider {
    fn keygen() -> (PublicKey, SecretKey) {
        let x25519_sk = StaticSecret::random_from_rng(OsRng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        let (mlkem_sk, mlkem_pk) = MlKem768::generate_keypair();

        (
            PublicKey::from_parts_mlkem(x25519_pk, &mlkem_pk),
            SecretKey::from_parts_mlkem(x25519_sk, mlkem_sk),
        )
    }

    fn encapsulate(pk: &PublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError> {
        let x25519_eph = EphemeralSecret::random_from_rng(OsRng);
        let x25519_eph_pk = X25519PublicKey::from(&x25519_eph);
        let x25519_ss = x25519_eph.diffie_hellman(pk.x25519());
        if !x25519_ss.was_contributory() {
            return Err(EncodingError);
        }

        let (mlkem_ct, mlkem_ss) = pk.mlkem_pk().encapsulate();

        let mut combined_raw = Zeroizing::new([0u8; SHARED_SECRET_BYTES * 2]);
        combined_raw[..SHARED_SECRET_BYTES].copy_from_slice(x25519_ss.as_bytes());
        combined_raw[SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_ref());
        let combined_ss = Zeroizing::new(combined_raw.to_vec());

        let mut kem_ct = Vec::with_capacity(KEM_CIPHERTEXT_BYTES);
        kem_ct.extend_from_slice(x25519_eph_pk.as_bytes());
        kem_ct.extend_from_slice(mlkem_ct.as_ref());

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
        let mlkem_ct_array: [u8; 1088] = mlkem_ct_bytes.try_into().map_err(|_| DecryptionError)?;
        let mlkem_ct: MlKemCiphertext = mlkem_ct_array.into();

        let x25519_ss = sk.x25519().diffie_hellman(&x25519_epk);
        if !x25519_ss.was_contributory() {
            return Err(DecryptionError);
        }
        let mlkem_ss = sk.mlkem_sk().decapsulate(&mlkem_ct);

        let mut combined_raw = Zeroizing::new([0u8; SHARED_SECRET_BYTES * 2]);
        combined_raw[..SHARED_SECRET_BYTES].copy_from_slice(x25519_ss.as_bytes());
        combined_raw[SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_ref());
        let combined_ss = Zeroizing::new(combined_raw.to_vec());

        Ok(combined_ss)
    }
}

// ---------------------------------------------------------------------------
// Backward-compatibility alias
// ---------------------------------------------------------------------------

/// Legacy alias — now backed by the hybrid provider.
pub type MlKem768Provider = HybridX25519MlKem768Provider;

// ---------------------------------------------------------------------------
// Curve25519 low-order / non-contributory rejection (empirical, real code path)
//
// The formal combiner proof abstracts X25519 as a prime-order group and cannot model
// Curve25519's cofactor / low-order points. These unit tests instead prove the SHIPPED
// decapsulate path rejects them: feeding any low-order encoded input as the X25519
// ephemeral yields the all-zero (identity) shared secret, which `was_contributory()`
// must reject BEFORE the ML-KEM secret is combined — isolating the guard from AEAD.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod low_order_x25519_tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex");
        }
        out
    }

    /// The standard libsodium ref10 Curve25519 low-order encoded-input blacklist
    /// (little-endian, top-bit-masked comparison): five canonical u-values — 0, 1, the
    /// two order-8 points, and p-1 — plus two non-canonical aliases, p (≡0) and p+1
    /// (≡1). Any of these as the peer key drives the (cofactor-8-clamped) scalar mult
    /// to the identity → all-zero shared secret. Because X25519 masks the u-coordinate's
    /// most significant bit (RFC 7748 §5), the high-bit twin of every entry is covered
    /// too; the direct KEM tests below confirm rejection of all seven.
    const LOW_ORDER_POINTS: &[&str] = &[
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    #[test]
    fn decapsulate_rejects_low_order_x25519_points() {
        let (pk, sk) = HybridX25519MlKem768Provider::keygen();
        // A real encapsulation gives a well-formed ML-KEM ct portion and correct length;
        // we then splice a low-order point into the X25519 ephemeral slot.
        let (_ss, mut kem_ct) = HybridX25519MlKem768Provider::encapsulate(&pk).unwrap();
        assert_eq!(kem_ct.len(), KEM_CIPHERTEXT_BYTES);

        // Positive control: the unmodified ciphertext decapsulates.
        assert!(
            HybridX25519MlKem768Provider::decapsulate(&sk, &kem_ct).is_ok(),
            "valid ciphertext must decapsulate"
        );

        for hexp in LOW_ORDER_POINTS {
            kem_ct[..X25519_KEY_BYTES].copy_from_slice(&hex32(hexp));
            assert!(
                HybridX25519MlKem768Provider::decapsulate(&sk, &kem_ct).is_err(),
                "decapsulate must reject non-contributory low-order X25519 point {hexp}"
            );
        }
    }

    #[test]
    fn encapsulate_rejects_low_order_recipient_key() {
        // A recipient public key that is a low-order point must also be rejected by
        // encapsulate's contributory check.
        let (_pk, sk) = HybridX25519MlKem768Provider::keygen();
        let mlkem_pk = sk.public_key().mlkem_pk();
        for hexp in LOW_ORDER_POINTS {
            let x25519_pk = X25519PublicKey::from(hex32(hexp));
            let bad_pk = PublicKey::from_parts_mlkem(x25519_pk, &mlkem_pk);
            assert!(
                HybridX25519MlKem768Provider::encapsulate(&bad_pk).is_err(),
                "encapsulate must reject low-order recipient X25519 key {hexp}"
            );
        }
    }
}
