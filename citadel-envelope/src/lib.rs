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
mod error;
mod kdf;
mod kem;
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
    inspect, Aad, CiphertextInfo, Citadel, Context, OpenError, PublicKey, SealError, SecretKey,
    ENVELOPE_VERSION, MIN_CIPHERTEXT_BYTES, MIN_ENVELOPE_V2_BYTES, PROTOCOL_VERSION, VERSION,
};

pub(crate) type CitadelEngine =
    crate::kem_engine::Citadel<crate::kem::HybridX25519MlKem768Provider>;

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
    use crate::{aead, kdf, wire, wire_v2};

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

/// Deterministic envelope-v2 construction for checked-in vectors only.
/// This module is absent from default production builds.
#[cfg(feature = "kat")]
#[doc(hidden)]
pub mod v2_test_vectors {
    use alloc::vec::Vec;

    use crate::error::EncodingError;
    use crate::kem::{HybridX25519MlKem768Provider, PublicKey, SecretKey};

    pub type DeterministicEnvelope = (PublicKey, SecretKey, Vec<u8>, Vec<u8>, Vec<u8>);

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
}
