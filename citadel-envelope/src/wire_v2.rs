// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict non-streaming envelope v2 codec.

extern crate alloc;

use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::aead;
use crate::error::{DecryptionError, EncodingError};
use crate::kem::KemProvider;
use crate::wire::KEM_CIPHERTEXT_BYTES;

pub const MAGIC: &[u8; 4] = b"CTD2";
pub const VERSION: u8 = 2;
pub const FLAGS: u8 = 0;
pub const SUITE_KEM: u8 = 0xA3;
pub const SUITE_KDF: u8 = 0xC1;
pub const SUITE_AEAD: u8 = 0xB1;
pub const HEADER_LEN: usize = 98;
pub const TAG_LEN: usize = 16;
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + KEM_CIPHERTEXT_BYTES + TAG_LEN;
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;
pub const MAX_AAD_LEN: usize = 64 * 1024;
pub const MAX_CONTEXT_LEN: usize = 4 * 1024;

const KDF_LABEL: &[u8] = b"citadel-envelope-v2/kdf\0";
const AAD_LABEL: &[u8] = b"citadel-envelope-v2/aad\0";
const EXTRACT_SALT_LABEL: &[u8] = b"citadel-envelope-v2/extract-salt";

pub struct Parts<'a> {
    pub header: &'a [u8],
    pub kem_ciphertext: &'a [u8],
    pub nonce: &'a [u8; 12],
    pub aead_ciphertext: &'a [u8],
    pub recipient_key_hash: &'a [u8; 32],
    pub plaintext_len: usize,
}

fn push_u16(out: &mut Vec<u8>, value: usize) -> Result<(), EncodingError> {
    let value = u16::try_from(value).map_err(|_| EncodingError)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: usize) -> Result<(), EncodingError> {
    let value = u32::try_from(value).map_err(|_| EncodingError)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// SHA3-256 over the suite's canonical public-key serialization.
///
/// The hash construction belongs to the wire spec, so it stays here; only the
/// serialization is delegated to the suite. For `0xA3` this is byte-for-byte what it
/// always was — `K::public_key_bytes` returns the same 1216 bytes `to_bytes()` did.
pub fn public_key_hash<K: KemProvider>(pk: &K::PublicKey) -> [u8; 32] {
    let digest = Sha3_256::digest(K::public_key_bytes(pk));
    digest.into()
}

pub fn context_hash(context: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(context);
    digest.into()
}

pub fn encode_header(
    plaintext_len: usize,
    recipient_hash: &[u8; 32],
    context_hash: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<[u8; HEADER_LEN], EncodingError> {
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(EncodingError);
    }
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = FLAGS;
    header[6] = SUITE_KEM;
    header[7] = SUITE_KDF;
    header[8] = SUITE_AEAD;
    header[9] = 0;
    header[10..12].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    header[12..14].copy_from_slice(&(KEM_CIPHERTEXT_BYTES as u16).to_be_bytes());
    header[14..22].copy_from_slice(&(plaintext_len as u64).to_be_bytes());
    header[22..54].copy_from_slice(recipient_hash);
    header[54..86].copy_from_slice(context_hash);
    header[86..98].copy_from_slice(nonce);
    Ok(header)
}

pub fn kdf_transcript(
    header: &[u8],
    kem_ct: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    let mut out = Vec::with_capacity(
        KDF_LABEL.len() + 2 + header.len() + 2 + kem_ct.len() + 4 + context.len(),
    );
    out.extend_from_slice(KDF_LABEL);
    push_u16(&mut out, header.len())?;
    out.extend_from_slice(header);
    push_u16(&mut out, kem_ct.len())?;
    out.extend_from_slice(kem_ct);
    push_u32(&mut out, context.len())?;
    out.extend_from_slice(context);
    Ok(out)
}

pub fn associated_data(
    header: &[u8],
    kem_ct: &[u8],
    context: &[u8],
    caller_aad: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    let mut out = Vec::with_capacity(
        AAD_LABEL.len()
            + 2
            + header.len()
            + 2
            + kem_ct.len()
            + 4
            + context.len()
            + 4
            + caller_aad.len(),
    );
    out.extend_from_slice(AAD_LABEL);
    push_u16(&mut out, header.len())?;
    out.extend_from_slice(header);
    push_u16(&mut out, kem_ct.len())?;
    out.extend_from_slice(kem_ct);
    push_u32(&mut out, context.len())?;
    out.extend_from_slice(context);
    push_u32(&mut out, caller_aad.len())?;
    out.extend_from_slice(caller_aad);
    Ok(out)
}

pub fn derive_key(shared_secret: &[u8], transcript: &[u8]) -> Result<[u8; 32], EncodingError> {
    let salt = Sha256::digest(EXTRACT_SALT_LABEL);
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(transcript, &mut key)
        .map_err(|_| EncodingError)?;
    Ok(key)
}

pub fn encode(
    header: &[u8; HEADER_LEN],
    kem_ct: &[u8],
    aead_ct: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    if kem_ct.len() != KEM_CIPHERTEXT_BYTES || aead_ct.len() < TAG_LEN {
        return Err(EncodingError);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + kem_ct.len() + aead_ct.len());
    out.extend_from_slice(header);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(aead_ct);
    Ok(out)
}

pub fn decode(data: &[u8]) -> Result<Parts<'_>, DecryptionError> {
    if data.len() < MIN_ENVELOPE_LEN {
        return Err(DecryptionError);
    }
    let header = data.get(..HEADER_LEN).ok_or(DecryptionError)?;
    if &header[..4] != MAGIC
        || header[4] != VERSION
        || header[5] != FLAGS
        || header[6] != SUITE_KEM
        || header[7] != SUITE_KDF
        || header[8] != SUITE_AEAD
        || header[9] != 0
        || u16::from_be_bytes([header[10], header[11]]) as usize != HEADER_LEN
        || u16::from_be_bytes([header[12], header[13]]) as usize != KEM_CIPHERTEXT_BYTES
    {
        return Err(DecryptionError);
    }

    let encoded_len = u64::from_be_bytes(header[14..22].try_into().map_err(|_| DecryptionError)?);
    let plaintext_len = usize::try_from(encoded_len).map_err(|_| DecryptionError)?;
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(DecryptionError);
    }
    let expected_len = MIN_ENVELOPE_LEN
        .checked_add(plaintext_len)
        .ok_or(DecryptionError)?;
    if data.len() != expected_len {
        return Err(DecryptionError);
    }

    let kem_start = HEADER_LEN;
    let kem_end = kem_start + KEM_CIPHERTEXT_BYTES;
    let nonce: &[u8; 12] = header[86..98].try_into().map_err(|_| DecryptionError)?;
    let recipient_key_hash = header[22..54].try_into().map_err(|_| DecryptionError)?;
    Ok(Parts {
        header,
        kem_ciphertext: &data[kem_start..kem_end],
        nonce,
        aead_ciphertext: &data[kem_end..],
        recipient_key_hash,
        plaintext_len,
    })
}

pub fn seal<K: KemProvider>(
    pk: &K::PublicKey,
    plaintext: &[u8],
    aad: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN
        || aad.len() > MAX_AAD_LEN
        || context.len() > MAX_CONTEXT_LEN
    {
        return Err(EncodingError);
    }
    let (shared_secret, kem_ct) = K::encapsulate(pk)?;
    let nonce = aead::nonce()?;
    seal_with_material::<K>(pk, plaintext, aad, context, &shared_secret, &kem_ct, &nonce)
}

pub(crate) fn seal_with_material<K: KemProvider>(
    pk: &K::PublicKey,
    plaintext: &[u8],
    aad: &[u8],
    context: &[u8],
    shared_secret: &[u8],
    kem_ct: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, EncodingError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN
        || aad.len() > MAX_AAD_LEN
        || context.len() > MAX_CONTEXT_LEN
    {
        return Err(EncodingError);
    }
    let header = encode_header(
        plaintext.len(),
        &public_key_hash::<K>(pk),
        &context_hash(context),
        nonce,
    )?;
    let transcript = kdf_transcript(&header, kem_ct, context)?;
    let key = Zeroizing::new(derive_key(shared_secret, &transcript)?);
    let bound_aad = associated_data(&header, kem_ct, context, aad)?;
    let aead_ct = aead::aead_seal(&key, nonce, plaintext, &bound_aad)?;
    encode(&header, kem_ct, &aead_ct)
}

pub fn open<K: KemProvider>(
    sk: &K::SecretKey,
    ciphertext: &[u8],
    aad: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if aad.len() > MAX_AAD_LEN || context.len() > MAX_CONTEXT_LEN {
        return Err(DecryptionError);
    }
    let parts = decode(ciphertext)?;
    let supplied_context_hash: &[u8; 32] = parts.header[54..86]
        .try_into()
        .map_err(|_| DecryptionError)?;
    if !bool::from(supplied_context_hash.ct_eq(&context_hash(context))) {
        return Err(DecryptionError);
    }
    let shared_secret = K::decapsulate(sk, parts.kem_ciphertext)?;
    let transcript =
        kdf_transcript(parts.header, parts.kem_ciphertext, context).map_err(|_| DecryptionError)?;
    let key = Zeroizing::new(derive_key(&shared_secret, &transcript).map_err(|_| DecryptionError)?);
    let bound_aad = associated_data(parts.header, parts.kem_ciphertext, context, aad)
        .map_err(|_| DecryptionError)?;
    let plaintext = aead::aead_open(&key, parts.nonce, parts.aead_ciphertext, &bound_aad)?;
    if plaintext.len() != parts.plaintext_len {
        return Err(DecryptionError);
    }
    let expected_recipient = public_key_hash::<K>(&K::public_key_of(sk));
    if !bool::from(parts.recipient_key_hash.ct_eq(&expected_recipient)) {
        return Err(DecryptionError);
    }
    Ok(plaintext)
}
