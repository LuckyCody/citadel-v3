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
//! ## Streaming (V2 API — new in 0.2.0)
//!
//! ```rust
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

#[doc(hidden)]
pub mod wire;

#[doc(hidden)]
pub mod aad;
#[doc(hidden)]
pub mod envelope;

/// Streaming authenticated encryption (V2 — new in 0.2.0).
pub mod stream;

/// V3 streaming (CTDL magic, stream_id, header_tag, HKDF nonces, final_tag).
pub mod stream_v3;

mod sdk;

pub use sdk::{
    inspect, Aad, CiphertextInfo, Citadel, Context, OpenError, PublicKey, SealError, SecretKey,
    MIN_CIPHERTEXT_BYTES, PROTOCOL_VERSION, VERSION,
};

pub(crate) type CitadelEngine =
    crate::kem_engine::Citadel<crate::kem::HybridX25519MlKem768Provider>;

#[doc(hidden)]
pub mod timing_diagnostics {
    use alloc::vec::Vec;
    use zeroize::Zeroizing;

    use crate::error::{DecryptionError, EncodingError};
    use crate::kem::{
        diagnostic_mlkem_decapsulate_from_key_bytes, diagnostic_mlkem_decapsulate_only,
        diagnostic_x25519_decapsulate_only, HybridX25519MlKem768Provider, KemProvider, SecretKey,
    };
    use crate::{aead, kdf, wire};

    pub fn hybrid_decapsulate(
        sk: &SecretKey,
        kem_ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
        HybridX25519MlKem768Provider::decapsulate(sk, kem_ct)
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
    use crate::kem::{KemProvider, PublicKey, SecretKey};
    use crate::{aead, kdf, wire};

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

        pub fn keygen(&self) -> (PublicKey, SecretKey) {
            K::keygen()
        }

        pub fn encrypt(
            &self,
            pk: &PublicKey,
            plaintext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, EncodingError> {
            let (ss_raw, kem_ct) = K::encapsulate(pk)?;
            // P018: ss_raw is already Zeroizing<Vec<u8>> from P011 fix
            let shared_secret = ss_raw;
            let ct_hash = kdf::ct_hash(&kem_ct);
            let aes_key = Zeroizing::new(kdf::derive_key(&shared_secret, &ct_hash, context)?);
            let nonce = aead::nonce()?;
            let aead_ct = aead::aead_seal(&aes_key, &nonce, plaintext, aad)?;
            wire::encode_wire(&kem_ct, &nonce, &aead_ct)
        }

        pub fn decrypt(
            &self,
            sk: &SecretKey,
            ciphertext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, DecryptionError> {
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

        #[inline]
        pub fn seal(
            &self,
            pk: &PublicKey,
            plaintext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, EncodingError> {
            self.encrypt(pk, plaintext, aad, context)
        }

        #[inline]
        pub fn open(
            &self,
            sk: &SecretKey,
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
