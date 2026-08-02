// SPDX-License-Identifier: AGPL-3.0-or-later
//! AEAD: AES-256-GCM

extern crate alloc;
use alloc::vec::Vec;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use getrandom::getrandom;

use crate::error::{DecryptionError, EncodingError};

/// Generate a random 12-byte nonce. Used during encryption only.
// On the fips graph the caller (RustCryptoBackend) is compiled but unreachable, so
// this goes dead there; kept compiled on both graphs deliberately (packet 043).
#[cfg_attr(feature = "fips", allow(dead_code))]
pub fn nonce() -> Result<[u8; 12], EncodingError> {
    let mut n = [0u8; 12];
    getrandom(&mut n).map_err(|_| EncodingError)?;
    Ok(n)
}

/// AEAD seal (encrypt path). Returns EncodingError on failure.
pub fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncodingError)?;
    let n = Nonce::from(*nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher.encrypt(&n, payload).map_err(|_| EncodingError)
}

/// AEAD open (decrypt path). Returns DecryptionError on failure.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| DecryptionError)?;
    let n = Nonce::from(*nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher.decrypt(&n, payload).map_err(|_| DecryptionError)
}
