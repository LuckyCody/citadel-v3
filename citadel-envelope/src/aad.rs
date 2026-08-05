// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! AAD + Context conventions (locked) for internal service use.
//!
//! Goals:
//! - deterministic encoding (language-agnostic)
//! - binds sender/recipient/route
//! - includes anti-replay fields (ts/seq/msg_id)
//! - separates environments/purposes via context
//!
//! Context (bytes):
//!   b"citadel|ctx|v1|" + u16_be(len(env)) + env + u16_be(len(purpose)) + purpose
//!
//!   Length-prefixed (not a bare `|`-delimiter) so that no combination of env/purpose
//!   byte content can collide: env="a", purpose="b|c" and env="a|b", purpose="c" would
//!   otherwise concatenate to the same bytes and derive the same key across two
//!   logically distinct contexts.
//!
//! AAD (bytes):
//!   b"citadel|aad|v1" || TLV(sender) || TLV(recipient) || TLV(route) || TLV(ts_ms) || TLV(seq) || TLV(msg_id_16)
//!
//! TLV:
//!   T: u8
//!   L: u16 big-endian
//!   V: bytes

extern crate alloc;

use alloc::vec::Vec;

use crate::error::EncodingError;

// -------------------------
// Public types / constants
// -------------------------

pub type MsgId16 = [u8; 16];

pub const CONTEXT_PREFIX: &[u8] = b"citadel|ctx|v1|";
pub const AAD_PREFIX: &[u8] = b"citadel|aad|v1";

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum AadTlvType {
    SenderId = 0x01,
    RecipientId = 0x02,
    Route = 0x03,
    TimestampUnixMs = 0x04, // u64 BE
    Sequence = 0x05,        // u64 BE
    MsgId16 = 0x06,         // 16 bytes
}

/// Build the canonical context:
/// `b"citadel|ctx|v1|" + u16_be(len(env)) + env + u16_be(len(purpose)) + purpose`
///
/// Length-prefixed rather than `|`-delimited: a bare delimiter allows
/// env="a", purpose="b|c" to collide with env="a|b", purpose="c" (identical bytes,
/// same derived key, cross-context confusion). Truncates at u16::MAX bytes per field
/// rather than erroring — env/purpose are short caller-controlled labels, not
/// untrusted-length data, and a hard error here would be a new panic-shaped surface
/// for what should be a pure byte-builder.
pub fn build_context(env: &str, purpose: &str) -> Vec<u8> {
    // We intentionally do NOT validate allowed env/purpose strings here.
    // Enforce allowed values at the call site if desired.
    let env_b = &env.as_bytes()[..env.len().min(u16::MAX as usize)];
    let purpose_b = &purpose.as_bytes()[..purpose.len().min(u16::MAX as usize)];

    let mut out = Vec::with_capacity(CONTEXT_PREFIX.len() + 2 + env_b.len() + 2 + purpose_b.len());
    out.extend_from_slice(CONTEXT_PREFIX);
    out.extend_from_slice(&(env_b.len() as u16).to_be_bytes());
    out.extend_from_slice(env_b);
    out.extend_from_slice(&(purpose_b.len() as u16).to_be_bytes());
    out.extend_from_slice(purpose_b);
    out
}

/// Build canonical AAD with locked fields.
///
/// Requirements (policy-level):
/// - sender/recipient/route must be stable identifiers
/// - ts_ms should be current time in ms
/// - seq can be 0 if you don't have a channel sequence
/// - msg_id MUST be unique (per sender) for replay cache / dedupe
#[allow(clippy::too_many_arguments)]
pub fn build_aad(
    sender_id: &str,
    recipient_id: &str,
    route: &str,
    ts_unix_ms: u64,
    seq: u64,
    msg_id: MsgId16,
) -> Result<Vec<u8>, EncodingError> {
    let s = sender_id.as_bytes();
    let r = recipient_id.as_bytes();
    let rt = route.as_bytes();

    // prefix + 6 TLVs, sizes conservative
    let mut out = Vec::with_capacity(
        AAD_PREFIX.len()
            + tlv_size(s.len())
            + tlv_size(r.len())
            + tlv_size(rt.len())
            + tlv_size(8)
            + tlv_size(8)
            + tlv_size(16),
    );

    out.extend_from_slice(AAD_PREFIX);

    push_tlv(&mut out, AadTlvType::SenderId, s)?;
    push_tlv(&mut out, AadTlvType::RecipientId, r)?;
    push_tlv(&mut out, AadTlvType::Route, rt)?;

    let ts = ts_unix_ms.to_be_bytes();
    push_tlv(&mut out, AadTlvType::TimestampUnixMs, &ts)?;

    let sq = seq.to_be_bytes();
    push_tlv(&mut out, AadTlvType::Sequence, &sq)?;

    push_tlv(&mut out, AadTlvType::MsgId16, &msg_id)?;

    Ok(out)
}

/// Generate a random 16-byte message id.
///
/// This is for internal convenience; you can also supply your own msg_id.
/// Uniqueness is the responsibility of the caller's replay/dedupe policy.
pub fn generate_msg_id() -> Result<MsgId16, EncodingError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|_| EncodingError)?;
    Ok(id)
}

// -------------------------
// Internal helpers
// -------------------------

#[inline]
fn tlv_size(v_len: usize) -> usize {
    // T (1) + L (2) + V (v_len)
    1 + 2 + v_len
}

#[inline]
fn push_tlv(out: &mut Vec<u8>, t: AadTlvType, v: &[u8]) -> Result<(), EncodingError> {
    // Length must fit u16
    if v.len() > u16::MAX as usize {
        return Err(EncodingError);
    }
    out.push(t as u8);
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Before the length-prefix fix, build_context("prod", "email|notify") and
    /// build_context("prod|email", "notify") produced byte-identical output — the
    /// sole domain-separation input to the KDF — meaning two different tenant
    /// contexts could derive the same AES key. Verifies that no longer holds.
    #[test]
    fn context_delimiter_collision_is_closed() {
        let a = build_context("prod", "email|notify");
        let b = build_context("prod|email", "notify");
        assert_ne!(
            a, b,
            "different (env, purpose) pairs must not collide to the same context bytes"
        );
    }

    #[test]
    fn context_round_trips_distinct_for_normal_inputs() {
        let a = build_context("production", "user-data-encryption");
        let b = build_context("production", "audit-log-encryption");
        assert_ne!(a, b);
        assert!(a.starts_with(CONTEXT_PREFIX));
    }
}
