// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Citadel V3 streaming authenticated encryption.
//!
//! Improvements over V2 (`stream.rs`):
//!
//! | Feature | V2 | V3 |
//! |---------|----|----|
//! | Magic bytes | none | `b"CTDL"` |
//! | Stream ID | none | 16-byte random per-stream |
//! | Header authenticated | no | yes (`header_tag`) |
//! | Chunk nonce | per-chunk random | HKDF-derived from base_nonce + seq |
//! | Chunk sequence | u32 | u64 (no overflow on huge streams) |
//! | Final tag over stream | no | yes (HMAC-SHA256 of stream_id + chunk count) |
//!
//! V2 `stream.rs` is unchanged; both are available. Use V3 for new production streams.
//!
//! # Wire format
//!
//! ```text
//! Stream header (1162 bytes):
//!   magic[4]     = b"CTDL"
//!   version[1]   = 0x03
//!   flags[1]     = 0x00
//!   suite_kem[1] = 0xA3 (X25519+ML-KEM-768)
//!   suite_aead[1]= 0xB1 (AES-256-GCM)
//!   stream_id[16]= random identifier
//!   kem_ct_len[2]= 1120
//!   kem_ct[1120]
//!   header_tag[16]= AES-256-GCM tag over all preceding bytes
//!
//! Per chunk:
//!   seq[8]       = u64 BE, 0-based
//!   is_final[1]  = 0x00 / 0x01
//!   aead_ct[N+16]= plaintext + GCM tag
//!   nonce = HKDF(stream_key, "citadel-v3-nonce|{seq:8BE}")[0..12]
//!
//! Final tag (appended after last chunk):
//!   final_tag[32]= HMAC-SHA256(final_key, stream_id || total_chunks[8BE])
//! ```

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead;
use crate::error::{DecryptionError, EncodingError};
use crate::kdf;
extern crate alloc;
use crate::kem::{HybridX25519MlKem768Provider, KemProvider, PublicKey, SecretKey};
use crate::wire::{KEM_CIPHERTEXT_BYTES, SUITE_AEAD_AES256GCM, SUITE_KEM_HYBRID_X25519_MLKEM768};
use crate::{Aad, Context};
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

pub const STREAM_V3_MAGIC: &[u8; 4] = b"CTDL";
pub const STREAM_V3_VERSION: u8 = 0x03;
pub const STREAM_V3_FLAGS: u8 = 0x00;
pub const STREAM_V3_SUITE_KEM: u8 = SUITE_KEM_HYBRID_X25519_MLKEM768;
pub const STREAM_V3_SUITE_AEAD: u8 = SUITE_AEAD_AES256GCM;

/// Stream header: magic[4] + version[1] + flags[1] + suite_kem[1] + suite_aead[1]
///                + stream_id[16] + kem_ct_len[2] + kem_ct[1120] + header_tag[16]
pub const STREAM_V3_HEADER_BYTES: usize = 4 + 1 + 1 + 1 + 1 + 16 + 2 + 1120 + 16; // 1162

/// Per-chunk overhead: seq[8] + is_final[1] = 9 bytes header + 16 bytes GCM tag.
pub const STREAM_V3_CHUNK_HEADER_BYTES: usize = 8 + 1; // 9
pub const STREAM_V3_CHUNK_MIN_BYTES: usize = STREAM_V3_CHUNK_HEADER_BYTES + 16; // 25

/// Final tag: HMAC-SHA256 = 32 bytes.
pub const STREAM_V3_FINAL_TAG_BYTES: usize = 32;

#[allow(unused_imports)]
use hmac::digest::MacError;
type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Key derivation for V3 streams
// ---------------------------------------------------------------------------

/// Derive the stream key from KEM shared secret.
fn derive_stream_key(
    shared_secret: &[u8],
    kem_ct: &[u8],
    stream_id: &[u8; 16],
    context: &Context,
) -> Result<Zeroizing<[u8; 32]>, EncodingError> {
    let ct_hash = kdf::ct_hash(kem_ct);
    // Extend context with stream_id for domain separation across streams.
    let mut extended_ctx = Vec::with_capacity(context.as_bytes().len() + 16 + 4);
    extended_ctx.extend_from_slice(b"v3:");
    extended_ctx.extend_from_slice(stream_id);
    extended_ctx.extend_from_slice(b"|");
    extended_ctx.extend_from_slice(context.as_bytes());
    let key = kdf::derive_key(shared_secret, &ct_hash, &extended_ctx)?;
    Ok(Zeroizing::new(key))
}

/// Derive the header authentication key.
fn derive_header_key(stream_key: &[u8; 32]) -> Result<[u8; 32], EncodingError> {
    let hk = Hkdf::<Sha256>::new(None, stream_key);
    let mut key = [0u8; 32];
    hk.expand(b"citadel-v3-header-key", &mut key)
        .map_err(|_| EncodingError)?;
    Ok(key)
}

/// Derive the final-tag HMAC key.
fn derive_final_key(stream_key: &[u8; 32]) -> Result<[u8; 32], EncodingError> {
    let hk = Hkdf::<Sha256>::new(None, stream_key);
    let mut key = [0u8; 32];
    hk.expand(b"citadel-v3-final-key", &mut key)
        .map_err(|_| EncodingError)?;
    Ok(key)
}

/// Derive the chunk-specific nonce from stream_key + sequence number.
fn derive_chunk_nonce(stream_key: &[u8; 32], seq: u64) -> Result<[u8; 12], EncodingError> {
    let hk = Hkdf::<Sha256>::new(None, stream_key);
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"citadel-v3-nonce|");
    info.extend_from_slice(&seq.to_be_bytes());
    let mut out = [0u8; 12];
    hk.expand(&info, &mut out).map_err(|_| EncodingError)?;
    Ok(out)
}

/// Per-chunk AAD: `b"citadel-v3-chunk|" || stream_id[16] || seq[8] || is_final[1]`
fn make_chunk_aad(stream_id: &[u8; 16], seq: u64, is_final: bool, user_aad: &Aad) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"citadel-v3-chunk|");
    out.extend_from_slice(stream_id);
    out.extend_from_slice(&seq.to_be_bytes());
    out.push(if is_final { 0x01 } else { 0x00 });
    out.push(b'|');
    out.extend_from_slice(user_aad.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// StreamV3Encryptor
// ---------------------------------------------------------------------------

/// V3 streaming encryptor.
///
/// Produces a self-describing stream with authenticated header, per-chunk HKDF nonces,
/// and a final HMAC tag covering the entire stream.
pub struct StreamV3Encryptor {
    stream_key: Zeroizing<[u8; 32]>,
    final_key: Zeroizing<[u8; 32]>,
    stream_id: [u8; 16],
    header: Vec<u8>,
    next_seq: u64,
    finalized: bool,
}

impl StreamV3Encryptor {
    /// Initialize a new V3 stream.
    pub fn new(pk: &PublicKey, aad: &Aad, context: &Context) -> Result<Self, EncodingError> {
        // KEM encapsulation.
        let (ss_raw, kem_ct) = HybridX25519MlKem768Provider::encapsulate(pk)?;
        // P018: ss_raw is already Zeroizing<Vec<u8>> from P011 fix
        let shared_secret = ss_raw;

        // Generate stream_id.
        let mut stream_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut stream_id);

        // Derive stream key.
        let stream_key = derive_stream_key(&shared_secret[..], &kem_ct, &stream_id, context)?;

        // Derive header key and final key.
        let header_key = derive_header_key(&stream_key)?;
        let final_key = Zeroizing::new(derive_final_key(&stream_key)?);

        // Build header (everything before header_tag).
        let mut pre_header = Vec::with_capacity(STREAM_V3_HEADER_BYTES - 16);
        pre_header.extend_from_slice(STREAM_V3_MAGIC);
        pre_header.push(STREAM_V3_VERSION);
        pre_header.push(STREAM_V3_FLAGS);
        pre_header.push(STREAM_V3_SUITE_KEM);
        pre_header.push(STREAM_V3_SUITE_AEAD);
        pre_header.extend_from_slice(&stream_id);
        pre_header.extend_from_slice(&(KEM_CIPHERTEXT_BYTES as u16).to_be_bytes());
        pre_header.extend_from_slice(&kem_ct);

        // Authenticate header with AES-256-GCM (empty plaintext, header bytes as AAD).
        let header_tag = aead::aead_seal(&header_key, &[0u8; 12], b"", &pre_header)?;

        let mut header = pre_header;
        header.extend_from_slice(&header_tag);

        debug_assert_eq!(header.len(), STREAM_V3_HEADER_BYTES);

        // AAD is bound per-chunk, not in the header.
        let _ = aad;

        Ok(Self {
            stream_key,
            final_key,
            stream_id,
            header,
            next_seq: 0,
            finalized: false,
        })
    }

    /// The stream header bytes. Send to the recipient before any chunks.
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// The stream's unique identifier.
    pub fn stream_id(&self) -> &[u8; 16] {
        &self.stream_id
    }

    /// Encrypt one chunk.
    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
        aad: &Aad,
    ) -> Result<Vec<u8>, EncodingError> {
        if self.finalized {
            return Err(EncodingError);
        }

        let seq = self.next_seq;
        let nonce = derive_chunk_nonce(&self.stream_key, seq)?;
        let chunk_aad = make_chunk_aad(&self.stream_id, seq, is_final, aad);
        let ct = aead::aead_seal(&self.stream_key, &nonce, plaintext, &chunk_aad)?;

        self.next_seq = self.next_seq.checked_add(1).ok_or(EncodingError)?;
        if is_final {
            self.finalized = true;
        }

        // Encode: seq[8] || is_final[1] || aead_ct[...]
        let mut out = Vec::with_capacity(9 + ct.len());
        out.extend_from_slice(&seq.to_be_bytes());
        out.push(if is_final { 0x01 } else { 0x00 });
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Generate the final tag covering the entire stream.
    ///
    /// Call after the last chunk (`is_final = true`). The receiver validates this
    /// tag after decrypting all chunks.
    ///
    /// `final_tag = HMAC-SHA256(final_key, stream_id || total_chunks[8BE])`
    pub fn final_tag(&self) -> Result<Vec<u8>, EncodingError> {
        if !self.finalized {
            return Err(EncodingError); // Must finalize stream first.
        }
        let mut mac = HmacSha256::new_from_slice(&*self.final_key).map_err(|_| EncodingError)?;
        mac.update(&self.stream_id);
        mac.update(&self.next_seq.to_be_bytes()); // total chunks encrypted
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    pub fn chunk_count(&self) -> u64 {
        self.next_seq
    }
}

// ---------------------------------------------------------------------------
// StreamV3Decryptor
// ---------------------------------------------------------------------------

/// V3 streaming decryptor.
///
/// TRUNCATION SAFETY: after the last chunk you MUST finalize with
/// [`StreamV3Decryptor::finish`] (or [`StreamV3Decryptor::verify_final_tag`]).
/// Decrypting chunks without finalizing accepts a truncated stream — the final
/// tag binds the total chunk count, so only finalization detects a dropped tail.
/// Prefer the high-level [`decrypt_stream_v3`], which finalizes for you.
#[must_use = "a StreamV3Decryptor must be finalized (finish/verify_final_tag) or a truncated stream is silently accepted"]
pub struct StreamV3Decryptor {
    stream_key: Zeroizing<[u8; 32]>,
    final_key: Zeroizing<[u8; 32]>,
    stream_id: [u8; 16],
    expected_seq: u64,
    done: bool,
}

/// Parsed V3 stream header fields.
#[derive(Debug)]
pub struct StreamV3Header {
    pub version: u8,
    pub suite_kem: u8,
    pub suite_aead: u8,
    pub stream_id: [u8; 16],
}

impl StreamV3Decryptor {
    /// Parse and validate the V3 stream header, then initialize a decryptor.
    pub fn from_header(
        sk: &SecretKey,
        header: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<(Self, StreamV3Header), DecryptionError> {
        if header.len() < STREAM_V3_HEADER_BYTES {
            return Err(DecryptionError);
        }

        // Validate magic.
        if &header[..4] != STREAM_V3_MAGIC {
            return Err(DecryptionError);
        }
        let version = header[4];
        if version != STREAM_V3_VERSION {
            return Err(DecryptionError);
        }

        // P012: Validate flags (must be zero - reserved for future use)
        let flags = header[5];
        if flags != STREAM_V3_FLAGS {
            return Err(DecryptionError);
        }

        // P012: Validate KEM suite (must match fixed suite - no downgrade)
        let suite_kem = header[6];
        if suite_kem != STREAM_V3_SUITE_KEM {
            return Err(DecryptionError);
        }

        // P012: Validate AEAD suite (must match fixed suite - no downgrade)
        let suite_aead = header[7];
        if suite_aead != STREAM_V3_SUITE_AEAD {
            return Err(DecryptionError);
        }

        let mut stream_id = [0u8; 16];
        stream_id.copy_from_slice(&header[8..24]);

        let kem_ct_len = u16::from_be_bytes([header[24], header[25]]) as usize;
        if kem_ct_len != KEM_CIPHERTEXT_BYTES {
            return Err(DecryptionError);
        }

        let kem_ct = &header[26..26 + KEM_CIPHERTEXT_BYTES]; // [26..1146]
        let pre_header = &header[..STREAM_V3_HEADER_BYTES - 16]; // everything before header_tag
        let header_tag = &header[STREAM_V3_HEADER_BYTES - 16..STREAM_V3_HEADER_BYTES];

        // KEM decapsulation.
        let ss_raw = HybridX25519MlKem768Provider::decapsulate(sk, kem_ct)?;
        // P018: ss_raw is already Zeroizing<Vec<u8>> from P011 fix
        let shared_secret = ss_raw;

        // Derive stream key.
        let stream_key = derive_stream_key(&shared_secret, kem_ct, &stream_id, context)
            .map_err(|_| DecryptionError)?;

        // Verify header authentication tag.
        let header_key = derive_header_key(&stream_key).map_err(|_| DecryptionError)?;
        let expected_tag = aead::aead_seal(&header_key, &[0u8; 12], b"", pre_header)
            .map_err(|_| DecryptionError)?;

        // P013: Constant-time comparison to prevent timing oracle attacks
        use subtle::ConstantTimeEq;
        let tags_match: bool = expected_tag.ct_eq(header_tag).into();
        if !tags_match {
            return Err(DecryptionError);
        }

        let final_key = Zeroizing::new(derive_final_key(&stream_key).map_err(|_| DecryptionError)?);

        let _ = aad; // AAD is validated per-chunk

        Ok((
            Self {
                stream_key,
                final_key,
                stream_id,
                expected_seq: 0,
                done: false,
            },
            StreamV3Header {
                version,
                suite_kem,
                suite_aead,
                stream_id,
            },
        ))
    }

    /// Decrypt one chunk.
    pub fn decrypt_chunk(
        &mut self,
        chunk_data: &[u8],
        aad: &Aad,
    ) -> Result<(Vec<u8>, bool), DecryptionError> {
        if self.done {
            return Err(DecryptionError);
        }
        if chunk_data.len() < STREAM_V3_CHUNK_MIN_BYTES {
            return Err(DecryptionError);
        }

        let seq = u64::from_be_bytes(chunk_data[..8].try_into().map_err(|_| DecryptionError)?);
        let is_final = match chunk_data[8] {
            0x00 => false,
            0x01 => true,
            _ => return Err(DecryptionError),
        };
        let ct = &chunk_data[9..];

        // Enforce strict sequential ordering.
        if seq != self.expected_seq {
            return Err(DecryptionError);
        }

        let nonce = derive_chunk_nonce(&self.stream_key, seq).map_err(|_| DecryptionError)?;
        let chunk_aad = make_chunk_aad(&self.stream_id, seq, is_final, aad);
        let plaintext = aead::aead_open(&self.stream_key, &nonce, ct, &chunk_aad)?;

        self.expected_seq = self.expected_seq.checked_add(1).ok_or(DecryptionError)?;
        if is_final {
            self.done = true;
        }

        Ok((plaintext, is_final))
    }

    /// Verify the final tag after decrypting all chunks.
    ///
    /// Must be called after receiving `is_final = true` from `decrypt_chunk`.
    /// Returns `Err(DecryptionError)` if the tag doesn't match (stream was truncated
    /// or the chunk count was tampered). Prefer [`Self::finish`], which consumes the
    /// decryptor so the terminal check cannot be forgotten.
    pub fn verify_final_tag(&self, final_tag: &[u8]) -> Result<(), DecryptionError> {
        if !self.done {
            return Err(DecryptionError); // Can't verify until all chunks received.
        }
        let mut mac = HmacSha256::new_from_slice(&*self.final_key).map_err(|_| DecryptionError)?;
        mac.update(&self.stream_id);
        mac.update(&self.expected_seq.to_be_bytes());
        mac.verify_slice(final_tag).map_err(|_| DecryptionError)
    }

    /// Consume the decryptor and verify the final tag — the truncation-safe terminal.
    ///
    /// Because it takes `self` by value, the decryptor cannot be used afterwards and
    /// the finalization cannot be silently skipped. Returns `Err` if the final chunk
    /// was never received (truncated stream) or the tag does not match.
    pub fn finish(self, final_tag: &[u8]) -> Result<(), DecryptionError> {
        self.verify_final_tag(final_tag)
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn chunks_received(&self) -> u64 {
        self.expected_seq
    }
}

// NOTE: a Drop-based "was this finalized?" guard was considered and REJECTED: on any
// error path the decryptor is dropped un-finalized (e.g. decrypt_stream_v3 returning
// Err on a detected truncation), which is indistinguishable from the footgun, so the
// guard turned legitimate Err returns into panics. Truncation safety is enforced by
// the high-level decrypt_stream_v3 (mandatory finish) and encouraged by the consuming
// finish() + #[must_use]; there is intentionally no Drop guard. (022-R judge finding.)

// ---------------------------------------------------------------------------
// High-level, truncation-safe stream API (recommended)
//
// These one-call helpers wrap the chunk API and make finalization MANDATORY, so an
// integrator cannot accidentally accept a truncated stream (the H1 footgun). Use
// these unless you specifically need incremental chunk-by-chunk streaming.
// ---------------------------------------------------------------------------

/// Output of [`encrypt_stream_v3`]: the stream `header`, the ordered chunk `frames`,
/// and the `final_tag`. Transmit all three; the recipient feeds them to
/// [`decrypt_stream_v3`].
pub struct EncryptedStreamV3 {
    pub header: Vec<u8>,
    pub frames: Vec<Vec<u8>>,
    pub final_tag: Vec<u8>,
}

/// Encrypt a complete message as a V3 stream in one call.
///
/// Encrypts `plaintext_chunks` in order (marking the last one final) and returns the
/// header, ordered chunk frames, and final tag as an [`EncryptedStreamV3`]. Requires
/// ≥1 chunk.
pub fn encrypt_stream_v3(
    pk: &PublicKey,
    plaintext_chunks: &[&[u8]],
    aad: &Aad,
    context: &Context,
) -> Result<EncryptedStreamV3, EncodingError> {
    if plaintext_chunks.is_empty() {
        return Err(EncodingError);
    }
    let mut enc = StreamV3Encryptor::new(pk, aad, context)?;
    let header = enc.header().to_vec();
    let last = plaintext_chunks.len() - 1;
    let mut frames = Vec::with_capacity(plaintext_chunks.len());
    for (i, pt) in plaintext_chunks.iter().enumerate() {
        frames.push(enc.encrypt_chunk(pt, i == last, aad)?);
    }
    let final_tag = enc.final_tag()?;
    Ok(EncryptedStreamV3 {
        header,
        frames,
        final_tag,
    })
}

/// Decrypt a complete V3 stream in one call, ENFORCING truncation safety.
///
/// Requires the full ordered set of chunk frames and the `final_tag`. Returns `Err`
/// if any chunk fails to authenticate, the final chunk is missing (truncation), a
/// non-final chunk appears last or any chunk appears after the final one, or the
/// count-binding final tag does not verify. Returns the concatenated plaintext.
pub fn decrypt_stream_v3(
    sk: &SecretKey,
    header: &[u8],
    chunks: &[&[u8]],
    final_tag: &[u8],
    aad: &Aad,
    context: &Context,
) -> Result<Vec<u8>, DecryptionError> {
    if chunks.is_empty() {
        return Err(DecryptionError);
    }
    let (mut dec, _hdr) = StreamV3Decryptor::from_header(sk, header, aad, context)?;
    let last = chunks.len() - 1;
    let mut out = Vec::new();
    for (i, frame) in chunks.iter().enumerate() {
        let (pt, is_final) = dec.decrypt_chunk(frame, aad)?;
        out.extend_from_slice(&pt);
        // The final flag must be set on exactly the last supplied chunk — this
        // rejects a truncated tail (last chunk not final) and a chunk after final.
        if is_final != (i == last) {
            return Err(DecryptionError);
        }
    }
    // Mandatory terminal check: consumes `dec` and verifies the count-binding final
    // tag, so truncation cannot slip through even if the loop above is bypassed.
    dec.finish(final_tag)?;
    Ok(out)
}
