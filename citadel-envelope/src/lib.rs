// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Citadel SDK
//!
//! Hybrid post-quantum encryption for long-lived data.
//!
//! ## Quick Start (V1 API — unchanged)
//!
//! ```rust
//! use citadel_envelope::{Citadel, Aad, Context};
//!
//! let citadel = Citadel::new();
//! let (pk, sk) = citadel.generate_keypair();
//!
//! let aad = Aad::for_storage("bucket", "object-id", 1);
//! let ctx = Context::for_application("myapp", "prod");
//!
//! let ciphertext = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();
//! let plaintext = citadel.open(&sk, &ciphertext, &aad, &ctx).unwrap();
//!
//! assert_eq!(plaintext, b"secret");
//! ```
//!
//! ## Legacy V2 streaming (explicit compatibility feature)
//!
//! Enable `legacy-stream-v2` only while migrating V2 streams. New integrations
//! must use [`stream_v3`].
//!
//! ```ignore
//! use citadel_envelope::{Citadel, Aad, Context};
//! use citadel_envelope::stream::{StreamEncryptor, StreamDecryptor};
//!
//! let cit = Citadel::new();
//! let (pk, sk) = cit.generate_keypair();
//! let aad = Aad::raw(b"my-file");
//! let ctx = Context::for_application("myapp", "prod");
//!
//! let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
//! let header = enc.header().to_vec();
//! let chunk = enc.encrypt_chunk(b"hello streaming", true, &aad).unwrap();
//!
//! let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
//! let (plaintext, done) = dec.decrypt_chunk(&chunk, &aad).unwrap();
//! assert!(done);
//! assert_eq!(plaintext, b"hello streaming");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc(html_root_url = "https://docs.rs/citadel-envelope/0.2.0")]

extern crate alloc;

mod aead;
mod backend;
/// AWS-LC-backed primitive components for the FIPS backend (packet 039+).
/// Component layer only — `backend::ActiveBackend` still resolves to RustCrypto
/// unconditionally until the provider fold in packet 043.
#[cfg(feature = "fips")]
#[doc(hidden)]
pub mod backend_awslc;
mod error;
mod kdf;
mod kem;
mod kem_p384;
mod wire_v2;

#[doc(hidden)]
pub mod wire;

#[doc(hidden)]
pub mod aad;
#[doc(hidden)]
pub mod envelope;

/// Compatibility-only V2 streaming API.
#[cfg(feature = "legacy-stream-v2")]
#[deprecated(note = "legacy V2 stream; migrate to stream_v3")]
pub mod stream;

/// V3 streaming (CTDL magic, stream_id, header_tag, HKDF nonces, final_tag).
pub mod stream_v3;

mod sdk;

pub use sdk::{
    inspect, Aad, CiphertextInfo, Citadel, CitadelP384, Context, OpenError, PublicKey, SealError,
    SecretKey, ENVELOPE_VERSION, MIN_CIPHERTEXT_BYTES, MIN_ENVELOPE_V2_BYTES, PROTOCOL_VERSION,
    VERSION,
};

// Packet 037: the engines resolve their suite providers through the crypto-backend
// seam. `ActiveBackend` is RustCrypto, so both aliases denote exactly the types they
// always did — the indirection is the point, not a change.
pub(crate) type CitadelEngine =
    crate::kem_engine::Citadel<<backend::ActiveBackend as backend::CryptoBackend>::KemA3>;

/// Engine instantiation for the additive `0xA4` (P-384 + ML-KEM-1024) suite.
/// Parallel to [`CitadelEngine`]; the frozen `0xA3` engine is unchanged.
pub(crate) type CitadelP384Engine =
    crate::kem_engine::Citadel<<backend::ActiveBackend as backend::CryptoBackend>::KemA4>;

#[doc(hidden)]
#[cfg(feature = "timing-diagnostics")]
pub mod timing_diagnostics {
    use alloc::vec::Vec;
    use zeroize::Zeroizing;

    use crate::error::{DecryptionError, EncodingError};
    use crate::kem::{
        diagnostic_mlkem_decapsulate_from_key_bytes, diagnostic_mlkem_decapsulate_only,
        diagnostic_x25519_decapsulate_only, HybridX25519MlKem768Provider, KemProvider, PublicKey,
        SecretKey,
    };
    use crate::kem_p384::{
        diagnostic_p384_ecdh_only, HybridP384MlKem1024Provider, P384MlKem1024PublicKey,
        P384MlKem1024SecretKey,
    };
    use crate::{aead, kdf, wire, wire_v2};

    /// Build `0xA4` KEM material for timing fixtures (parallel to `hybrid_encapsulate`).
    pub fn p384_encapsulate(
        pk: &P384MlKem1024PublicKey,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError> {
        HybridP384MlKem1024Provider::encapsulate(pk)
    }

    /// The isolated P-384 ECDH step of `0xA4` decapsulation — the new classical primitive.
    /// Returns the 48-byte x-coordinate.
    pub fn p384_ecdh_only(
        sk: &P384MlKem1024SecretKey,
        kem_ct: &[u8],
    ) -> Result<[u8; 48], DecryptionError> {
        diagnostic_p384_ecdh_only(sk, kem_ct)
    }

    pub fn hybrid_decapsulate(
        sk: &SecretKey,
        kem_ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
        HybridX25519MlKem768Provider::decapsulate(sk, kem_ct)
    }

    /// Construct KEM material directly for timing-fixture setup.
    ///
    /// Timing benches must not seal a current CTD2 envelope and then parse it
    /// with the historical CTD1 decoder merely to recover this material.
    pub fn hybrid_encapsulate(
        pk: &PublicKey,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), EncodingError> {
        HybridX25519MlKem768Provider::encapsulate(pk)
    }

    /// Return the KEM byte range after strictly decoding a current CTD2 envelope.
    pub fn current_envelope_kem_range(
        ciphertext: &[u8],
    ) -> Result<core::ops::Range<usize>, DecryptionError> {
        let parts = wire_v2::decode(ciphertext)?;
        let start = parts.kem_ciphertext.as_ptr() as usize - ciphertext.as_ptr() as usize;
        Ok(start..start + parts.kem_ciphertext.len())
    }

    pub fn x25519_decapsulate_only(
        sk: &SecretKey,
        kem_ct: &[u8],
    ) -> Result<[u8; 32], DecryptionError> {
        diagnostic_x25519_decapsulate_only(sk, kem_ct)
    }

    pub fn mlkem_decapsulate_only(
        sk: &SecretKey,
        kem_ct: &[u8],
    ) -> Result<[u8; 32], DecryptionError> {
        diagnostic_mlkem_decapsulate_only(sk, kem_ct)
    }

    pub fn mlkem_decapsulate_from_key_bytes(
        sk_bytes: &[u8; wire::KEM_SECRET_KEY_BYTES],
        kem_ct: &[u8; wire::KEM_CIPHERTEXT_BYTES],
    ) -> Result<[u8; 32], DecryptionError> {
        diagnostic_mlkem_decapsulate_from_key_bytes(sk_bytes, kem_ct)
    }

    pub fn ct_hash(kem_ct: &[u8]) -> [u8; 32] {
        kdf::ct_hash(kem_ct)
    }

    pub fn derive_key(
        shared_secret: &[u8],
        ct_hash: &[u8; 32],
        context: &[u8],
    ) -> Result<[u8; 32], EncodingError> {
        kdf::derive_key(shared_secret, ct_hash, context)
    }

    pub fn aead_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        aead::aead_open(key, nonce, ciphertext, aad)
    }

    pub fn aead_seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncodingError> {
        aead::aead_seal(key, nonce, plaintext, aad)
    }
}

#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use Citadel instead")]
pub type CitadelMlKem768 = CitadelEngine;

#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use Citadel instead")]
pub type CitadelHybrid = CitadelEngine;

mod kem_engine {
    use alloc::vec::Vec;
    use zeroize::Zeroizing;

    use crate::error::{DecryptionError, EncodingError};
    use crate::kem::KemProvider;
    use crate::{aead, kdf, wire, wire_v2};

    pub struct Citadel<K: KemProvider> {
        _marker: core::marker::PhantomData<K>,
    }

    impl<K: KemProvider> Default for Citadel<K> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: KemProvider> Citadel<K> {
        pub fn new() -> Self {
            Self {
                _marker: core::marker::PhantomData,
            }
        }

        pub fn keygen(&self) -> (K::PublicKey, K::SecretKey) {
            K::keygen()
        }

        pub fn encrypt(
            &self,
            pk: &K::PublicKey,
            plaintext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, EncodingError> {
            wire_v2::seal::<K>(pk, plaintext, aad, context)
        }

        pub fn decrypt(
            &self,
            sk: &K::SecretKey,
            ciphertext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, DecryptionError> {
            if ciphertext.starts_with(wire_v2::MAGIC) {
                return wire_v2::open::<K>(sk, ciphertext, aad, context);
            }
            let parts = wire::decode_wire(ciphertext)?;
            let ss_raw = K::decapsulate(sk, parts.kem_ciphertext)?;
            // P018: ss_raw is already Zeroizing<Vec<u8>> from P011 fix
            let shared_secret = ss_raw;
            let ct_hash = kdf::ct_hash(parts.kem_ciphertext);
            let aes_key = Zeroizing::new(
                kdf::derive_key(&shared_secret, &ct_hash, context).map_err(|_| DecryptionError)?,
            );
            aead::aead_open(&aes_key, parts.nonce, parts.aead_ciphertext, aad)
        }

        #[cfg(feature = "legacy-envelope-v1")]
        pub fn encrypt_v1_compat(
            &self,
            pk: &K::PublicKey,
            plaintext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, EncodingError> {
            let (shared_secret, kem_ct) = K::encapsulate(pk)?;
            let ct_hash = kdf::ct_hash(&kem_ct);
            let aes_key = Zeroizing::new(kdf::derive_key(&shared_secret, &ct_hash, context)?);
            let nonce = aead::nonce()?;
            let aead_ct = aead::aead_seal(&aes_key, &nonce, plaintext, aad)?;
            wire::encode_wire(&kem_ct, &nonce, &aead_ct)
        }

        #[inline]
        pub fn seal(
            &self,
            pk: &K::PublicKey,
            plaintext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, EncodingError> {
            self.encrypt(pk, plaintext, aad, context)
        }

        #[inline]
        pub fn open(
            &self,
            sk: &K::SecretKey,
            ciphertext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, DecryptionError> {
            self.decrypt(sk, ciphertext, aad, context)
        }
    }
}

#[doc(hidden)]
pub use aad::MsgId16;
#[doc(hidden)]
pub use envelope::Envelope;
#[doc(hidden)]
pub use error::{DecryptionError, EncodingError};
#[doc(hidden)]
pub use kem::{HybridX25519MlKem768Provider, KemProvider, MlKem768Provider};
pub use kem_p384::{
    HybridP384MlKem1024Provider, P384MlKem1024PublicKey, P384MlKem1024SecretKey,
    P384_MLKEM1024_PUBLIC_KEY_BYTES, P384_MLKEM1024_SECRET_KEY_BYTES,
};

/// Deterministic envelope-v2 construction for checked-in vectors only.
/// This module is absent from default production builds.
#[cfg(feature = "kat")]
#[doc(hidden)]
pub mod v2_test_vectors {
    use alloc::vec::Vec;

    use crate::error::{DecryptionError, EncodingError};
    use crate::kem::{HybridX25519MlKem768Provider, PublicKey, SecretKey};

    pub type DeterministicEnvelope = (PublicKey, SecretKey, Vec<u8>, Vec<u8>, Vec<u8>);

    pub type DeterministicEnvelopeA4 = (
        crate::kem_p384::P384MlKem1024PublicKey,
        crate::kem_p384::P384MlKem1024SecretKey,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );

    #[allow(clippy::too_many_arguments)]
    pub fn deterministic_envelope(
        recipient_x25519_secret: [u8; 32],
        mlkem_d: [u8; 32],
        mlkem_z: [u8; 32],
        ephemeral_x25519_secret: [u8; 32],
        mlkem_m: [u8; 32],
        nonce: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<DeterministicEnvelope, EncodingError> {
        let (pk, sk) = HybridX25519MlKem768Provider::kat_hybrid_keygen(
            recipient_x25519_secret,
            mlkem_d,
            mlkem_z,
        );
        let (shared_secret, kem_ct) = HybridX25519MlKem768Provider::kat_hybrid_encapsulate(
            &pk,
            ephemeral_x25519_secret,
            mlkem_m,
        )?;
        let envelope = crate::wire_v2::seal_with_material::<HybridX25519MlKem768Provider>(
            &pk,
            plaintext,
            aad,
            context,
            &shared_secret,
            &kem_ct,
            &nonce,
        )?;
        Ok((pk, sk, shared_secret.to_vec(), kem_ct, envelope))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn deterministic_envelope_a4(
        recipient_p384_scalar: [u8; 48],
        mlkem_d: [u8; 32],
        mlkem_z: [u8; 32],
        ephemeral_p384_scalar: [u8; 48],
        mlkem_m: [u8; 32],
        nonce: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<DeterministicEnvelopeA4, EncodingError> {
        let (pk, sk) = crate::kem_p384::HybridP384MlKem1024Provider::kat_hybrid_keygen(
            recipient_p384_scalar,
            mlkem_d,
            mlkem_z,
        );
        let (shared_secret, kem_ct) =
            crate::kem_p384::HybridP384MlKem1024Provider::kat_hybrid_encapsulate(
                &pk,
                ephemeral_p384_scalar,
                mlkem_m,
            )?;
        let envelope =
            crate::wire_v2::seal_with_material::<crate::kem_p384::HybridP384MlKem1024Provider>(
                &pk,
                plaintext,
                aad,
                context,
                &shared_secret,
                &kem_ct,
                &nonce,
            )?;
        Ok((pk, sk, shared_secret.to_vec(), kem_ct, envelope))
    }

    pub fn open_a4(
        sk: &crate::kem_p384::P384MlKem1024SecretKey,
        ciphertext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        crate::wire_v2::open::<crate::kem_p384::HybridP384MlKem1024Provider>(
            sk, ciphertext, aad, context,
        )
    }
}
