// SPDX-License-Identifier: AGPL-3.0-or-later
//! KDF (v1 structured)
//!
//! info = PROTOCOL_ID || b"|aes|" || ct_hash || context
//! key  = HKDF-SHA256(shared_secret, salt=None, info=info, len=32)
//!
//! KEY_LIFECYCLE — secret-in-memory handling for the AEAD/KDF stack.
//!
//! Closed (drop-based, panic-safe) via enabled `zeroize` features (see Cargo.toml):
//! - AES round-key schedule: `aes` 0.8.4 implements `Drop` + `ZeroizeOnDrop` on ALL
//!   compiled backends, including the x86_64 `autodetect` wrapper (its `Drop` calls
//!   `ManuallyDrop::drop` on the inner backend). So the schedule expanded from the
//!   derived key — the reversible material from which the key could be recovered — is
//!   wiped when the `Aes256Gcm` cipher drops, on unwind too. Verified 029-R Q2.
//!
//! Accepted residuals (audited, bounded, no library API to close):
//! - GHASH `H` retained state on x86_64/x86: `polyval` 0.6.2's `autodetect` backend
//!   (selected on x86) stores its active backend in a `ManuallyDrop` union and
//!   implements NO `Drop`, so the backend's own zeroizing destructor never runs — the
//!   retained `H`-derived Polyval key material is not wiped on cipher drop for this
//!   target (029-R Q2/Q5). `aes-gcm`'s and `ghash`'s `zeroize` still wipe the
//!   transient construction copies; only the retained accumulator key lingers.
//!   SEVERITY (corrected 030-R R2 — do NOT treat as low): this is a GCM tag-FORGERY
//!   primitive, not a harmless value. Citadel envelopes are DETERMINISTICALLY
//!   re-openable — the KEM ciphertext is preserved, so `open()` re-derives the SAME
//!   AES-GCM key `K` and reuses the stored nonce on every open of a given envelope
//!   (see `wire_v2::open`); `K` is NOT single-use. An attacker who reads this residual
//!   from freed memory AND has the envelope's own `(AAD, ct, tag)` can recover the tag
//!   mask `E_K(J0)` for that `(K, nonce)` and forge valid tags for modified
//!   ciphertexts; a recipient re-opening the modified envelope re-derives the same `K`
//!   and accepts the forgery — an authenticity break for that envelope. It does NOT
//!   reveal `K` (one-way) and does not touch other envelopes (distinct nonces/keys).
//!   Sole mitigation is the memory-disclosure precondition; the residual's marginal
//!   risk is that `H` persists AFTER `K`/plaintext are zeroized, widening the window.
//!   Disposition: CLOSE, do not accept as low-severity. Upstream ALREADY fixed this
//!   in `polyval` 0.7.3 (restructured: a top-level `impl Drop` calling
//!   `zeroize::zeroize_flat_type`, no `ManuallyDrop` union). The clean close is to
//!   upgrade `aes-gcm` 0.10 -> 0.11 (pulls `ghash` 0.6 -> `polyval` 0.7.3), keeping
//!   CLMUL and adding no fork — pending owner go-ahead (semver-major AEAD bump, needs
//!   KAT re-validation). In the deployed API a fail-closed replay store may also block
//!   the modified-envelope replay, but the library must not rely on that. Already
//!   wiped today on aarch64+PMULL / force-soft builds.
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
