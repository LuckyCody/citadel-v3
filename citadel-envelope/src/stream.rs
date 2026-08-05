// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Streaming authenticated encryption (V2 — P046).
//!
//! Enables encryption of large or streaming payloads without loading the entire
//! plaintext into memory at once. Each chunk is independently authenticated and
//! bound to its sequence position and the stream session — preventing reordering,
//! truncation, and chunk-substitution attacks.
//!
//! # Wire format
//!
//! ```text
//! Stream header (1126 bytes):
//!   version[1]=0x02 | suite_kem[1]=0xA3 | suite_aead[1]=0xB1 | flags[1]=0x01
//!   kem_ct_len[2]=1120 | kem_ct[1120]
//!   (KEM establishes stream key — no AEAD ciphertext in header)
//!
//! Per chunk:
//!   chunk_index[4] (u32 BE, 1-based)
//!   is_final[1]    (0x00 = more chunks, 0x01 = last chunk)
//!   nonce[12]      (random per chunk)
//!   aead_ct[N+16]  (plaintext encrypted + 16-byte GCM tag)
//! ```
//!
//! # Security properties
//!
//! - **Chunk-key derivation**: each chunk uses a unique AES-256 key derived from
//!   the stream key via HKDF-SHA256 with `info = "citadel-stream-chunk-v2|{index}|{is_final}"`.
//!   A chunk encrypted for position N cannot be transplanted to position M.
//!
//! - **Sequence enforcement**: `StreamDecryptor` rejects chunks with unexpected
//!   `chunk_index`, preventing reordering.
//!
//! - **Truncation prevention**: the decryptor requires the chunk with `is_final=1`
//!   to signal end-of-stream. A stream truncated before the final chunk is detected.
//!
//! - **AAD binding**: user-supplied AAD is mixed into every chunk's authenticated
//!   data alongside the stream metadata. Wrong AAD on any chunk causes rejection.
//!
//! # Example
//!
//! ```
//! use citadel_envelope::{Citadel, Aad, Context};
//! use citadel_envelope::stream::{StreamEncryptor, StreamDecryptor};
//!
//! let cit = Citadel::new();
//! let (pk, sk) = cit.generate_keypair();
//! let aad = Aad::raw(b"file-path=/sensitive/data.txt");
//! let ctx = Context::for_application("myapp", "prod");
//!
//! // Encrypt
//! let mut enc = StreamEncryptor::new(&pk, &aad, &ctx).unwrap();
//! let header = enc.header().to_vec();
//! let chunk1 = enc.encrypt_chunk(b"first chunk of data", false, &aad).unwrap();
//! let chunk2 = enc.encrypt_chunk(b"last chunk", true, &aad).unwrap();
//!
//! // Decrypt
//! let mut dec = StreamDecryptor::from_header(&sk, &header, &aad, &ctx).unwrap();
//! let (pt1, done1) = dec.decrypt_chunk(&chunk1, &aad).unwrap();
//! assert!(!done1);
//! let (pt2, done2) = dec.decrypt_chunk(&chunk2, &aad).unwrap();
//! assert!(done2);
//! assert_eq!(pt1, b"first chunk of data");
//! assert_eq!(pt2, b"last chunk");
//! ```

extern crate alloc;
use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead;
use crate::error::{DecryptionError, EncodingError};
use crate::kdf;
use crate::kem::{HybridX25519MlKem768Provider, KemProvider, PublicKey, SecretKey};
use crate::sdk::{Aad, Context};
use crate::wire;

// ---------------------------------------------------------------------------
// Internal stream key derivation
// ---------------------------------------------------------------------------

/// Derive a per-chunk AES-256 key.
///
/// `info = "citadel-stream-chunk-v2|{index:4 bytes BE}|{is_final:1 byte}"`
///
/// Binding `is_final` into the info ensures that a "non-final" chunk cannot
/// be substituted for the "final" chunk at the same index.
fn derive_chunk_key(
    stream_key: &[u8; 32],
    index: u32,
    is_final: bool,
) -> Result<[u8; 32], EncodingError> {
    let mut info = Vec::with_capacity(24 + 4 + 1);
    info.extend_from_slice(b"citadel-stream-chunk-v2|");
    info.extend_from_slice(&index.to_be_bytes());
    info.push(if is_final { 0x01 } else { 0x00 });

    let hk = Hkdf::<Sha256>::new(None, stream_key);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).map_err(|_| EncodingError)?;
    Ok(key)
}

/// Build the per-chunk additional authenticated data.
///
/// Mixes stream metadata (index, is_final) with user-supplied AAD so that:
/// - A chunk cannot be reused at a different position.
/// - A chunk cannot be decrypted with different user AAD.
fn make_chunk_aad(user_aad: &Aad, index: u32, is_final: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"citadel-stream-v2|");
    out.extend_from_slice(&index.to_be_bytes());
    out.push(if is_final { 0x01 } else { 0x00 });
    out.push(b'|');
    out.extend_from_slice(user_aad.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// StreamEncryptor
// ---------------------------------------------------------------------------

/// Encrypts data as a sequence of authenticated chunks.
///
/// Create with [`StreamEncryptor::new`], retrieve the stream header with
/// [`header`], then call [`encrypt_chunk`] for each piece of data.
/// The final chunk MUST pass `is_final = true`.
pub struct StreamEncryptor {
    stream_key: Zeroizing<[u8; 32]>,
    header: Vec<u8>,
    /// Next chunk index to write (1-based: first chunk is index 1).
    next_index: u32,
    /// Whether `encrypt_chunk` with `is_final=true` has been called.
    finalized: bool,
}

impl StreamEncryptor {
    /// Initialize a new stream, running the KEM encapsulation to establish
    /// the stream key.
    ///
    /// The caller must transmit `header()` to the recipient before any chunks.
    pub fn new(pk: &PublicKey, _aad: &Aad, context: &Context) -> Result<Self, EncodingError> {
        // KEM encapsulation: establishes shared stream key.
        let (ss_raw, kem_ct) = HybridX25519MlKem768Provider::encapsulate(pk)?;
        // P018: ss_raw is already Zeroizing<Vec<u8>> from P011 fix
        let shared_secret = ss_raw;

        // Derive stream key using the same KDF as V1, with stream context.
        let ct_hash = kdf::ct_hash(&kem_ct);
        let stream_key_bytes = kdf::derive_key(&shared_secret, &ct_hash, context.as_bytes())?;
        let stream_key = Zeroizing::new(stream_key_bytes);

        // Encode stream header (KEM ciphertext only — no AEAD here).
        let header = wire::encode_stream_header(&kem_ct)?;

        Ok(Self {
            stream_key,
            header,
            next_index: 1,
            finalized: false,
        })
    }

    /// The stream header bytes. Transmit this to the recipient before any chunks.
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// Encrypt one chunk of plaintext.
    ///
    /// - `plaintext`: data to encrypt. May be empty (allowed for the final chunk).
    /// - `is_final`: set `true` on the last chunk of the stream.
    ///
    /// # Errors
    ///
    /// Returns `EncodingError` if the stream has already been finalized or if
    /// RNG/AEAD fails.
    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
        aad: &Aad,
    ) -> Result<Vec<u8>, EncodingError> {
        if self.finalized {
            return Err(EncodingError); // Cannot write after final chunk.
        }

        let index = self.next_index;
        let chunk_key = derive_chunk_key(&self.stream_key, index, is_final)?;
        let nonce = aead::nonce()?;
        let chunk_aad = make_chunk_aad(aad, index, is_final);
        let ct = aead::aead_seal(&chunk_key, &nonce, plaintext, &chunk_aad)?;

        self.next_index = self.next_index.checked_add(1).ok_or(EncodingError)?; // Overflow: more than 2^32-1 chunks.

        if is_final {
            self.finalized = true;
        }

        // Encode: chunk_index[4] || is_final[1] || nonce[12] || aead_ct[...]
        let mut out = Vec::with_capacity(wire::STREAM_CHUNK_HEADER_BYTES + ct.len());
        out.extend_from_slice(&index.to_be_bytes());
        out.push(if is_final { 0x01 } else { 0x00 });
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Whether the stream has been finalized (final chunk sent).
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Number of chunks encrypted so far.
    pub fn chunk_count(&self) -> u32 {
        self.next_index.saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// StreamDecryptor
// ---------------------------------------------------------------------------

/// Decrypts a sequence of authenticated chunks from a stream.
///
/// Create with [`StreamDecryptor::from_header`] using the header bytes from
/// the encryptor, then call [`decrypt_chunk`] for each received chunk.
pub struct StreamDecryptor {
    stream_key: Zeroizing<[u8; 32]>,
    /// Next expected chunk index (1-based).
    expected_index: u32,
    /// Whether the final chunk has been received.
    done: bool,
}

impl StreamDecryptor {
    /// Initialize a decryptor from a stream header.
    ///
    /// Runs KEM decapsulation to recover the stream key.
    pub fn from_header(
        sk: &SecretKey,
        header: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Self, DecryptionError> {
        let parts = wire::decode_stream_header(header)?;

        let ss_raw = HybridX25519MlKem768Provider::decapsulate(sk, parts.kem_ciphertext)?;
        // P018: ss_raw is already Zeroizing<Vec<u8>> from P011 fix
        let shared_secret = ss_raw;

        let ct_hash = kdf::ct_hash(parts.kem_ciphertext);
        let stream_key_bytes = kdf::derive_key(&shared_secret, &ct_hash, context.as_bytes())
            .map_err(|_| DecryptionError)?;
        let stream_key = Zeroizing::new(stream_key_bytes);

        // AAD is validated per-chunk, not here (it's included in chunk_aad).
        let _ = aad;

        Ok(Self {
            stream_key,
            expected_index: 1,
            done: false,
        })
    }

    /// Decrypt one chunk.
    ///
    /// Returns `(plaintext, is_final)`.
    ///
    /// # Errors
    ///
    /// Returns `DecryptionError` if:
    /// - The chunk header is malformed (too short).
    /// - The chunk index does not match the expected sequence position.
    /// - The stream has already been finalized.
    /// - AEAD authentication fails (wrong key, wrong AAD, tampering).
    pub fn decrypt_chunk(
        &mut self,
        chunk_data: &[u8],
        aad: &Aad,
    ) -> Result<(Vec<u8>, bool), DecryptionError> {
        if self.done {
            return Err(DecryptionError); // Cannot read past final chunk.
        }

        if chunk_data.len() < wire::STREAM_MIN_CHUNK_BYTES {
            return Err(DecryptionError);
        }

        // Parse chunk header.
        let chunk_index =
            u32::from_be_bytes(chunk_data[..4].try_into().map_err(|_| DecryptionError)?);
        let is_final = match chunk_data[4] {
            0x00 => false,
            0x01 => true,
            _ => return Err(DecryptionError), // Unknown is_final byte.
        };
        let nonce: &[u8; 12] = chunk_data[5..17].try_into().map_err(|_| DecryptionError)?;
        let aead_ct = &chunk_data[17..];

        // Enforce strict sequential ordering — prevents reordering attacks.
        if chunk_index != self.expected_index {
            return Err(DecryptionError);
        }

        let chunk_key = derive_chunk_key(&self.stream_key, chunk_index, is_final)
            .map_err(|_| DecryptionError)?;
        let chunk_aad = make_chunk_aad(aad, chunk_index, is_final);

        let plaintext = aead::aead_open(&chunk_key, nonce, aead_ct, &chunk_aad)?;

        self.expected_index = self.expected_index.checked_add(1).ok_or(DecryptionError)?;

        if is_final {
            self.done = true;
        }

        Ok((plaintext, is_final))
    }

    /// Whether the final chunk has been received.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Number of chunks successfully decrypted so far.
    pub fn chunk_count(&self) -> u32 {
        self.expected_index.saturating_sub(1)
    }
}
