// SPDX-License-Identifier: AGPL-3.0-or-later
//! KDF (v1 structured)
//!
//! info = PROTOCOL_ID || b"|aes|" || ct_hash || context
//! key  = HKDF-SHA256(shared_secret, salt=None, info=info, len=32)
//!
//! KEY_LIFECYCLE — secret-in-memory handling for the AEAD/KDF stack.
//!
//! Closed (drop-based, panic-safe) via enabled `zeroize` features (see Cargo.toml):
//! - AES round-key schedule: `aes` is `ZeroizeOnDrop`, so the schedule expanded from
//!   the derived key is wiped when the `Aes256Gcm` cipher drops.
//! - GHASH keyed state: `polyval` has `impl Drop` that zeroizes, and `aes-gcm`'s own
//!   `zeroize` wipes the transient GHASH construction key. The retained `H` state is
//!   therefore wiped on cipher drop.
//!
//! Accepted residual (audited, bounded, no library API to close):
//! - HKDF PRK: `Hkdf::<Sha256>::new` extracts a pseudorandom key from the shared
//!   secret and holds it inside the `hk` value below. The `hkdf` 0.12 crate has no
//!   `zeroize` feature or zeroize-on-drop, so that PRK lingers in this stack frame
//!   until overwritten by reuse. It is a one-way function of an already-`Zeroizing`
//!   shared secret and lives only for this call. Closing it would require forking or
//!   replacing the `hkdf` crate.
//!
//! The derived key itself is returned bare and MUST be wrapped in `Zeroizing` by the
//! caller (the engine does: see `kem_engine::decrypt`).

extern crate alloc;
use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

use crate::error::EncodingError;
use crate::wire::PROTOCOL_ID;

pub fn ct_hash(kem_ct: &[u8]) -> [u8; 32] {
    let h = Sha3_256::digest(kem_ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

pub fn derive_key(
    shared_secret: &[u8],
    ct_hash: &[u8; 32],
    context: &[u8],
) -> Result<[u8; 32], EncodingError> {
    let mut info = Vec::with_capacity(PROTOCOL_ID.len() + 5 + 32 + context.len());
    info.extend_from_slice(PROTOCOL_ID);
    info.extend_from_slice(b"|aes|");
    info.extend_from_slice(ct_hash);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).map_err(|_| EncodingError)?;
    Ok(out)
}
