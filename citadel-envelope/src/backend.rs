// SPDX-License-Identifier: AGPL-3.0-or-later
//! Crypto-provider seam (packet 037).
//!
//! One compile-time [`CryptoBackend`] seam abstracts every FIPS-coverable primitive the
//! envelope uses — the KEM suites (via [`KemProvider`], folded under the backend as
//! associated types), AEAD, KDF, and hashing. The default backend is today's RustCrypto
//! stack with **zero behavior change**: every method body is the code `wire_v2.rs` called
//! directly before this module existed, only moved. A later `fips` build supplies an
//! AWS-LC implementation at the [`ActiveBackend`] selection point without touching the
//! codec, wire format, or public API.
//!
//! ECDH is deliberately absent from the method list: the classical arm of each hybrid
//! suite (X25519 for `0xA3`, P-384 for `0xA4`) lives inside that suite's [`KemProvider`]
//! implementation, so a backend swaps ECDH by supplying its own provider types — the
//! packet-033 "provider is the only thing that varies" principle. Signing (ML-DSA-65)
//! lives in `citadel-signer` and gets its parallel seam in packet 045.
//!
//! No runtime dispatch, by construction: associated functions and associated types make
//! `dyn CryptoBackend` impossible, so the backend is a build property that cannot be
//! switched — or silently downgraded — at runtime. See
//! `citadel/fips-backend/SEAM_DESIGN.md` (factory repo) for the full design note.

extern crate alloc;
use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::error::{DecryptionError, EncodingError};

// ---------------------------------------------------------------------------
// KEM provider trait (moved verbatim from kem.rs; kem.rs re-exports it)
// ---------------------------------------------------------------------------

/// A hybrid KEM suite: one classical arm, one post-quantum arm, one combined secret.
///
/// Packet 033 P2 made this trait suite-generic via **associated types plus associated
/// consts**. That shape is not a style preference — `API_FREEZE.md` Tier 1 freezes
/// `PublicKey::to_bytes -> [u8; 1216]` and `SecretKey::to_bytes -> [u8; 2432]`
/// concretely, so parameterizing the key types themselves (`PublicKey<P>`) would
/// change the identity of a frozen type and require the breaking-change process.
/// Associated types let each suite own distinct key types while the `0xA3` suite's
/// resolve to exactly the frozen ones. Associated consts keep every size on the trait
/// without rippling `typenum` generics through the crate.
/// See `eem/033R_decisions_D2_D3_freeze.md` (Constraint A).
///
/// Implementors must uphold:
/// - `encapsulate` returns a `kem_ct` of exactly `KEM_CIPHERTEXT_BYTES`;
/// - `decapsulate` rejects any `ct` whose length is not `KEM_CIPHERTEXT_BYTES`
///   **before** touching key material;
/// - the combined secret is the concatenation of the arms, so that compromise of
///   either arm alone leaves the KDF input unpredictable.
pub trait KemProvider {
    /// Suite identifier written to CTD2 header byte 6. Globally unique per suite.
    const SUITE_KEM: u8;
    /// Exact on-wire length of `kem_ct` for this suite.
    const KEM_CIPHERTEXT_BYTES: usize;
    /// Exact serialized length of this suite's public key.
    const KEM_PUBLIC_KEY_BYTES: usize;
    /// Exact serialized length of this suite's secret key.
    const KEM_SECRET_KEY_BYTES: usize;

    /// This suite's public key type. Distinct per suite — never shared across suites,
    /// so a key from one suite cannot be passed to another's `encapsulate`.
    type PublicKey;
    /// This suite's secret key type. Distinct per suite for the same reason.
    type SecretKey;

    fn keygen() -> (Self::PublicKey, Self::SecretKey);
    /// P011: Returns (Zeroizing<combined_shared_secret>, kem_ciphertext_bytes).
    /// Shared secret is wrapped in Zeroizing to ensure heap cleanup.
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError>;
    /// P011: Returns Zeroizing<combined_shared_secret>.
    /// Shared secret is wrapped in Zeroizing to ensure heap cleanup.
    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptionError>;

    /// Canonical serialization of a public key. The envelope hashes this to bind a
    /// ciphertext to its recipient; the hash construction stays in `wire_v2` because
    /// it is part of the wire spec, not the suite.
    fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8>;

    /// Recover the public key from a secret key, for the recipient-binding check on
    /// open. Suite-local because key layout is suite-local.
    fn public_key_of(sk: &Self::SecretKey) -> Self::PublicKey;
}

// ---------------------------------------------------------------------------
// The generalized seam
// ---------------------------------------------------------------------------

/// The compile-time crypto-backend seam (packet 037).
///
/// Everything the v2 codec needs from a crypto library, behind associated functions so
/// selection is monomorphized at build time. Implementors must be drop-in
/// byte-compatible: ML-KEM, AES-256-GCM, HKDF-SHA256, SHA-2/SHA-3, X25519, and P-384
/// ECDH are all standardized, so two correct backends produce identical wire bytes —
/// the differential gate in packets 039+ enforces exactly that.
pub trait CryptoBackend {
    /// Suite `0xA3` (X25519 + ML-KEM-768) provider under this backend.
    type KemA3: KemProvider;
    /// Suite `0xA4` (P-384 + ML-KEM-1024) provider under this backend.
    type KemA4: KemProvider;

    /// SHA-256. Used by the v2 KDF to derive the HKDF extract salt.
    fn sha256(data: &[u8]) -> [u8; 32];

    /// SHA3-256. Used for the recipient-key and context binding hashes.
    fn sha3_256(data: &[u8]) -> [u8; 32];

    /// HKDF-SHA256 extract-then-expand. Fills `okm`; errors only on an invalid
    /// requested length (per RFC 5869 the expand bound).
    fn hkdf_sha256(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), EncodingError>;

    /// Fresh AEAD nonce from the backend's randomness source.
    fn aead_nonce() -> Result<[u8; 12], EncodingError>;

    /// AES-256-GCM seal: returns `ciphertext || tag`.
    fn aead_seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncodingError>;

    /// AES-256-GCM open: verifies the tag, returns the plaintext.
    fn aead_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptionError>;
}

// ---------------------------------------------------------------------------
// Default backend: RustCrypto (pure Rust, non-FIPS)
// ---------------------------------------------------------------------------

/// The default backend — today's RustCrypto stack, bodies unchanged.
///
/// AEAD delegates to `crate::aead` rather than duplicating the AES-GCM bodies here:
/// that module carries the audited key-lifecycle handling (`kdf.rs` KEY_LIFECYCLE
/// note) and stays the single home of the `aes_gcm::` calls, below the seam.
// On the fips graph nothing references this type (ActiveBackend points at AWS-LC);
// it is deliberately still compiled so a single-feature build cannot silently rot
// the other backend.
#[cfg_attr(feature = "fips", allow(dead_code))]
pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    type KemA3 = crate::kem::HybridX25519MlKem768Provider;
    type KemA4 = crate::kem_p384::HybridP384MlKem1024Provider;

    fn sha256(data: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(data);
        digest.into()
    }

    fn sha3_256(data: &[u8]) -> [u8; 32] {
        let digest = Sha3_256::digest(data);
        digest.into()
    }

    fn hkdf_sha256(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), EncodingError> {
        let hkdf = Hkdf::<Sha256>::new(salt, ikm);
        hkdf.expand(info, okm).map_err(|_| EncodingError)
    }

    fn aead_nonce() -> Result<[u8; 12], EncodingError> {
        crate::aead::nonce()
    }

    fn aead_seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncodingError> {
        crate::aead::aead_seal(key, nonce, plaintext, aad)
    }

    fn aead_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        crate::aead::aead_open(key, nonce, ciphertext, aad)
    }
}

// ---------------------------------------------------------------------------
// Backend selection point
// ---------------------------------------------------------------------------

/// The compile-time backend selection point — the `fips` feature switch declared by
/// packet 037 (SEAM_DESIGN §3) and made live by packet 043. Default builds compile
/// zero AWS-LC code; `--features fips` routes every seam method — and the `0xA4`
/// suite provider — through AWS-LC (`backend_awslc.rs`). No runtime branch exists on
/// either arm.
#[cfg(not(feature = "fips"))]
pub(crate) type ActiveBackend = RustCryptoBackend;

/// See the non-fips arm above. `KemA3` remains RustCrypto on this arm too — the FIPS
/// path is `0xA4`-only (PRD NG2); `0xA3` stays byte-identical on both backends.
#[cfg(feature = "fips")]
pub(crate) type ActiveBackend = crate::backend_awslc::AwsLcBackend;
