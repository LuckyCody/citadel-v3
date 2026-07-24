// SPDX-License-Identifier: AGPL-3.0-or-later
//! KDF (v1 structured)
//!
//! info = PROTOCOL_ID || b"|aes|" || ct_hash || context
//! key  = HKDF-SHA256(shared_secret, salt=None, info=info, len=32)
//!
//! KEY_LIFECYCLE — accepted residuals (audited, bounded, no library API to close).
//!
//! - HKDF PRK: `Hkdf::<Sha256>::new` extracts a pseudorandom key from the shared
//!   secret and holds it inside the `hk` value below. The `hkdf` crate exposes no
//!   zeroize-on-drop, so that PRK lingers in this stack frame until overwritten by
//!   reuse. It is a one-way function of an already-`Zeroizing` shared secret and
//!   lives only for this call.
//! - AES round-key schedule: `Aes256Gcm` expands the derived (`Zeroizing`) key into
//!   a round-key schedule that `aes-gcm` does not wipe on drop. Bounded to one
//!   seal/open call over a key that is itself zeroized. The `zeroize` feature we
//!   enable wipes the transient GHASH key; the round keys would need a direct `aes`
//!   dependency to reach and were judged not worth a new dependency.
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
