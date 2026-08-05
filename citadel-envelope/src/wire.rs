// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Wire format (v1 structured)
//!
//! Format (v1):
//!   version[1] || suite_kem[1] || suite_aead[1] || flags[1] || kem_ct_len[2]
//!   || kem_ct[1120] || nonce[12] || aead_ct[16+]
//!
//! kem_ct = x25519_ephemeral_pk[32] || mlkem768_ciphertext[1088]

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{DecryptionError, EncodingError};

/// Protocol identifier for KDF domain separation (v1 structured)
pub const PROTOCOL_ID: &[u8] = b"citadel-env-v1";

/// Version byte for v1
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Suite identifiers (on-wire)
pub const SUITE_KEM_HYBRID_X25519_MLKEM768: u8 = 0xA3;
pub const SUITE_AEAD_AES256GCM: u8 = 0xB1;

/// CNSA-aligned hybrid: P-384 ECDH + ML-KEM-1024. Implemented by
/// [`crate::kem_p384::HybridP384MlKem1024Provider`] and present in [`SUITE_TABLE`] as of
/// packet 033 P3c — the row and the provider landed in the same commit, so no build has
/// ever advertised this suite without the code to open it.
pub const SUITE_KEM_HYBRID_P384_MLKEM1024: u8 = 0xA4;

/// Reserved: X25519 + ML-KEM-1024. Recorded now so `0xA4` can never be retro-fitted to
/// a different pairing. Absent from [`SUITE_TABLE`] — reserved must **reject**.
pub const SUITE_KEM_RESERVED_X25519_MLKEM1024: u8 = 0xA5;

/// Reserved: pure ML-KEM-1024, no classical arm (a degenerate table row, not a third
/// codebase). Absent from [`SUITE_TABLE`] — reserved must **reject**.
pub const SUITE_KEM_RESERVED_PURE_MLKEM1024: u8 = 0xA6;

/// Flags (reserved for future use)
pub const FLAGS_V1: u8 = 0x00;

// ---------------------------------------------------------------------------
// Component sizes
// ---------------------------------------------------------------------------

/// X25519 public key / ephemeral key size
pub const X25519_KEY_BYTES: usize = 32;

/// ML-KEM-768 component sizes
pub const MLKEM_CIPHERTEXT_BYTES: usize = 1088;
pub const MLKEM_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM_SECRET_KEY_BYTES: usize = 2400;

// ---------------------------------------------------------------------------
// Hybrid aggregate sizes
// ---------------------------------------------------------------------------

/// Hybrid KEM ciphertext: x25519_ephemeral_pk[32] || mlkem_ct[1088]
pub const KEM_CIPHERTEXT_BYTES: usize = X25519_KEY_BYTES + MLKEM_CIPHERTEXT_BYTES; // 1120

/// Hybrid public key: x25519_pk[32] || mlkem_ek[1184]
pub const KEM_PUBLIC_KEY_BYTES: usize = X25519_KEY_BYTES + MLKEM_PUBLIC_KEY_BYTES; // 1216

/// Hybrid secret key: x25519_sk[32] || mlkem_dk[2400]
pub const KEM_SECRET_KEY_BYTES: usize = X25519_KEY_BYTES + MLKEM_SECRET_KEY_BYTES; // 2432

/// Per-KEM shared secret size (each produces 32 bytes)
pub const SHARED_SECRET_BYTES: usize = 32;

pub const NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;
pub const AES_KEY_BYTES: usize = 32;

/// Header size: version + suite_kem + suite_aead + flags + kem_ct_len(u16)
pub const HEADER_BYTES: usize = 1 + 1 + 1 + 1 + 2; // 6

/// Minimum ciphertext size: header + kem_ct + nonce + tag
pub const MIN_CIPHERTEXT_BYTES: usize =
    HEADER_BYTES + KEM_CIPHERTEXT_BYTES + NONCE_BYTES + AEAD_TAG_BYTES; // 1154

/// Byte offset of the AES-GCM nonce within a V1 ciphertext blob.
/// = HEADER_BYTES + KEM_CIPHERTEXT_BYTES
/// Exported so keystore and other consumers do not hard-code 1126.
pub const NONCE_OFFSET: usize = HEADER_BYTES + KEM_CIPHERTEXT_BYTES; // 1126

/// Byte offset of the first AEAD ciphertext byte (immediately after nonce).
pub const AEAD_CT_OFFSET: usize = NONCE_OFFSET + NONCE_BYTES; // 1138

// ---------------------------------------------------------------------------
// Compatibility aliases (keep older imports compiling)
// ---------------------------------------------------------------------------
pub const VERSION: u8 = PROTOCOL_VERSION;
pub const KEM_CT_BYTES: usize = KEM_CIPHERTEXT_BYTES;
pub const KEM_PK_BYTES: usize = KEM_PUBLIC_KEY_BYTES;
pub const KEM_SK_BYTES: usize = KEM_SECRET_KEY_BYTES;

// ---------------------------------------------------------------------------
// Suite table (packet 033)
// ---------------------------------------------------------------------------

/// Per-suite lengths resolved from the on-wire `suite_kem` byte.
///
/// One table, one lookup. The alternative — parallel per-suite constant modules —
/// drifts: a hardening fix lands in one arm and not its twin, and an auditor reviews
/// both. A table also makes a classical-arm-free suite a degenerate row rather than a
/// third codebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteParams {
    pub suite_kem: u8,
    pub kem_ciphertext_bytes: usize,
    pub kem_public_key_bytes: usize,
    pub kem_secret_key_bytes: usize,
}

/// Every suite this build can actually encrypt and decrypt.
///
/// **Membership is the definition of "supported."** A suite identifier that has been
/// reserved but has no provider (`0xA5`, `0xA6`) is absent, so [`suite_params`] returns
/// `None` and the decoder fails closed. Adding a row without a working provider would
/// make the decoder accept envelopes nothing can open.
///
/// The `0xA4` lengths below are written as literals on purpose, **not** derived from
/// `HybridP384MlKem1024Provider`'s associated consts. `encode_header` cross-checks
/// `suite.kem_ciphertext_bytes` against `K::KEM_CIPHERTEXT_BYTES`; if this table simply
/// referenced the provider, that check would compare a value to itself and could never
/// fail. The duplication *is* the check — two independent statements of the FIPS 203 and
/// SEC1 sizes, so an edit to one and not the other is caught at the first encode.
const SUITE_TABLE: &[SuiteParams] = &[
    SuiteParams {
        suite_kem: SUITE_KEM_HYBRID_X25519_MLKEM768,
        kem_ciphertext_bytes: KEM_CIPHERTEXT_BYTES,
        kem_public_key_bytes: KEM_PUBLIC_KEY_BYTES,
        kem_secret_key_bytes: KEM_SECRET_KEY_BYTES,
    },
    SuiteParams {
        suite_kem: SUITE_KEM_HYBRID_P384_MLKEM1024,
        // p384 uncompressed SEC1 point (97) + ML-KEM-1024 ciphertext (1568)
        kem_ciphertext_bytes: 1665,
        // p384 uncompressed SEC1 point (97) + ML-KEM-1024 encapsulation key (1568)
        kem_public_key_bytes: 1665,
        // p384 scalar (48) + FIPS 203 (d, z) seed (64) -- D3, not the 3168-byte
        // expanded decapsulation key
        kem_secret_key_bytes: 112,
    },
];

/// Resolve a `suite_kem` byte to its lengths, or `None` if this build does not
/// support it. Callers must treat `None` as a hard reject, never as a default.
pub const fn suite_params(suite_kem: u8) -> Option<SuiteParams> {
    let mut i = 0;
    while i < SUITE_TABLE.len() {
        if SUITE_TABLE[i].suite_kem == suite_kem {
            return Some(SUITE_TABLE[i]);
        }
        i += 1;
    }
    None
}

const fn min_kem_ciphertext_bytes() -> usize {
    let mut min = usize::MAX;
    let mut i = 0;
    while i < SUITE_TABLE.len() {
        if SUITE_TABLE[i].kem_ciphertext_bytes < min {
            min = SUITE_TABLE[i].kem_ciphertext_bytes;
        }
        i += 1;
    }
    min
}

/// Smallest `kem_ct` any supported suite can produce.
///
/// Derived from the table rather than written down, so a future row cannot silently
/// invalidate a length guard that someone forgot to update. This is the only value
/// safe to use in a bounds check taken *before* the suite byte has been resolved.
pub const MIN_KEM_CIPHERTEXT_BYTES: usize = min_kem_ciphertext_bytes();

/// Borrowed view of a parsed ciphertext.
#[derive(Debug, Clone, Copy)]
pub struct WireComponents<'a> {
    pub version: u8,
    pub suite_kem: u8,
    pub suite_aead: u8,
    pub flags: u8,
    pub kem_ct_len: u16,
    pub kem_ciphertext: &'a [u8; KEM_CIPHERTEXT_BYTES],
    pub nonce: &'a [u8; NONCE_BYTES],
    pub aead_ciphertext: &'a [u8],
}

/// Validate that `c` uses the only currently supported V1 suite combination.
///
/// Separated from [`decode_wire_raw`] so that future callers can route to different
/// [`crate::kem::KemProvider`] implementations before rejecting unknown suites.
/// All existing callers go through [`decode_wire`] which calls both functions.
pub fn check_v1_suites(c: &WireComponents<'_>) -> Result<(), DecryptionError> {
    if c.suite_kem != SUITE_KEM_HYBRID_X25519_MLKEM768 || c.suite_aead != SUITE_AEAD_AES256GCM {
        return Err(DecryptionError);
    }
    Ok(())
}

/// Parse and structurally validate a V1 wire ciphertext **without** rejecting
/// unrecognised suite bytes.
///
/// Returns `WireComponents` containing the raw `suite_kem` and `suite_aead` bytes
/// so the caller can dispatch to an appropriate [`crate::kem::KemProvider`].
/// Use [`decode_wire`] instead when you require exactly the X25519+ML-KEM-768 /
/// AES-256-GCM combination.
///
/// # Algorithm agility path
///
/// Future support for ML-KEM-1024 (`suite_kem = 0xA4`) or ChaCha20-Poly1305
/// (`suite_aead = 0xB2`) works as follows:
/// 1. Call `decode_wire_raw` to parse the envelope.
/// 2. Match on `c.suite_kem` / `c.suite_aead`.
/// 3. Route to the appropriate `KemProvider::decapsulate` implementation.
/// 4. The KDF and AEAD layers remain unchanged (HKDF-SHA256 + provider-specific AEAD).
pub fn decode_wire_raw(data: &[u8]) -> Result<WireComponents<'_>, DecryptionError> {
    if data.len() < MIN_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let version = data[0];
    let suite_kem = data[1];
    let suite_aead = data[2];
    let flags = data[3];
    let kem_ct_len = u16::from_be_bytes([data[4], data[5]]);

    // Structural checks (version, flags, KEM ciphertext length) are always enforced.
    // Suite bytes are returned to the caller for dispatch — not validated here.
    if version != PROTOCOL_VERSION {
        return Err(DecryptionError);
    }
    if flags != FLAGS_V1 {
        return Err(DecryptionError);
    }
    if kem_ct_len as usize != KEM_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let kem_start = HEADER_BYTES;
    let kem_end = kem_start + KEM_CIPHERTEXT_BYTES;
    let nonce_start = kem_end;
    let nonce_end = nonce_start + NONCE_BYTES;

    let kem_ciphertext: &[u8; KEM_CIPHERTEXT_BYTES] = data[kem_start..kem_end]
        .try_into()
        .map_err(|_| DecryptionError)?;

    let nonce: &[u8; NONCE_BYTES] = data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| DecryptionError)?;

    let aead_ciphertext = &data[nonce_end..];
    if aead_ciphertext.len() < AEAD_TAG_BYTES {
        return Err(DecryptionError);
    }

    Ok(WireComponents {
        version,
        suite_kem,
        suite_aead,
        flags,
        kem_ct_len,
        kem_ciphertext,
        nonce,
        aead_ciphertext,
    })
}

/// Parse, structurally validate, and **suite-validate** a V1 wire ciphertext.
///
/// Requires exactly `suite_kem = 0xA3` (X25519+ML-KEM-768) and
/// `suite_aead = 0xB1` (AES-256-GCM). Returns [`DecryptionError`] for any
/// other combination.
///
/// For a parser that accepts unknown suite bytes and returns them for caller
/// dispatch, use [`decode_wire_raw`] + [`check_v1_suites`].
pub fn decode_wire(data: &[u8]) -> Result<WireComponents<'_>, DecryptionError> {
    let c = decode_wire_raw(data)?;
    check_v1_suites(&c)?;
    Ok(c)
}

/// Return the authenticated nonce field from a non-streaming v1 or v2 envelope.
///
/// Adjacent components must use this helper instead of freezing a
/// version-specific byte offset into replay or audit logic.
pub fn envelope_nonce(data: &[u8]) -> Result<&[u8; NONCE_BYTES], DecryptionError> {
    if data.starts_with(crate::wire_v2::MAGIC) {
        return Ok(crate::wire_v2::decode(data)?.nonce);
    }
    Ok(decode_wire(data)?.nonce)
}

pub fn encode_wire(
    kem_ct: &[u8],
    nonce: &[u8; NONCE_BYTES],
    aead_ct: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    if kem_ct.len() != KEM_CIPHERTEXT_BYTES {
        return Err(EncodingError);
    }
    if aead_ct.len() < AEAD_TAG_BYTES {
        return Err(EncodingError);
    }

    let mut out =
        Vec::with_capacity(HEADER_BYTES + KEM_CIPHERTEXT_BYTES + NONCE_BYTES + aead_ct.len());

    out.push(PROTOCOL_VERSION);
    out.push(SUITE_KEM_HYBRID_X25519_MLKEM768);
    out.push(SUITE_AEAD_AES256GCM);
    out.push(FLAGS_V1);
    out.extend_from_slice(&(KEM_CIPHERTEXT_BYTES as u16).to_be_bytes());

    out.extend_from_slice(kem_ct);
    out.extend_from_slice(nonce);
    out.extend_from_slice(aead_ct);

    Ok(out)
}

// ---------------------------------------------------------------------------
// Stream wire format (V2 — P046)
// ---------------------------------------------------------------------------

/// Version byte for v2 streaming ciphertext.
pub const STREAM_VERSION: u8 = 0x02;

/// Flags byte indicating streaming mode.
pub const FLAGS_STREAM: u8 = 0x01;

/// Stream header size: version + suite_kem + suite_aead + flags + kem_ct_len + kem_ct.
/// No AEAD in the header — KEM output establishes the stream key only.
pub const STREAM_HEADER_BYTES: usize = HEADER_BYTES + KEM_CIPHERTEXT_BYTES; // 1126

/// Per-chunk overhead: chunk_index[4] + is_final[1] + nonce[12] = 17 bytes.
pub const STREAM_CHUNK_HEADER_BYTES: usize = 4 + 1 + NONCE_BYTES; // 17

/// Minimum chunk size including AEAD tag.
pub const STREAM_MIN_CHUNK_BYTES: usize = STREAM_CHUNK_HEADER_BYTES + AEAD_TAG_BYTES; // 33

/// Borrowed view of a parsed stream header.
#[derive(Debug, Clone, Copy)]
pub struct StreamHeader<'a> {
    pub version: u8,
    pub suite_kem: u8,
    pub suite_aead: u8,
    pub flags: u8,
    pub kem_ciphertext: &'a [u8; KEM_CIPHERTEXT_BYTES],
}

/// Encode a stream header (version=0x02, flags=STREAM).
///
/// Writes the KEM ciphertext without any AEAD ciphertext.
/// The stream key is derived from the KEM shared secret by the caller.
pub fn encode_stream_header(kem_ct: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if kem_ct.len() != KEM_CIPHERTEXT_BYTES {
        return Err(EncodingError);
    }

    let mut out = Vec::with_capacity(STREAM_HEADER_BYTES);
    out.push(STREAM_VERSION);
    out.push(SUITE_KEM_HYBRID_X25519_MLKEM768);
    out.push(SUITE_AEAD_AES256GCM);
    out.push(FLAGS_STREAM);
    out.extend_from_slice(&(KEM_CIPHERTEXT_BYTES as u16).to_be_bytes());
    out.extend_from_slice(kem_ct);

    debug_assert_eq!(out.len(), STREAM_HEADER_BYTES);
    Ok(out)
}

/// Decode and validate a stream header from bytes.
///
/// Returns `DecryptionError` if the buffer is too short, the version is not
/// `STREAM_VERSION` (0x02), or the suite bytes do not match expectations.
pub fn decode_stream_header(data: &[u8]) -> Result<StreamHeader<'_>, DecryptionError> {
    if data.len() < STREAM_HEADER_BYTES {
        return Err(DecryptionError);
    }

    let version = data[0];
    let suite_kem = data[1];
    let suite_aead = data[2];
    let flags = data[3];
    let kem_ct_len = u16::from_be_bytes([data[4], data[5]]);

    if version != STREAM_VERSION {
        return Err(DecryptionError);
    }
    if suite_kem != SUITE_KEM_HYBRID_X25519_MLKEM768 || suite_aead != SUITE_AEAD_AES256GCM {
        return Err(DecryptionError);
    }
    if flags != FLAGS_STREAM {
        return Err(DecryptionError);
    }
    if kem_ct_len as usize != KEM_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let kem_ciphertext: &[u8; KEM_CIPHERTEXT_BYTES] = data[HEADER_BYTES..STREAM_HEADER_BYTES]
        .try_into()
        .map_err(|_| DecryptionError)?;

    Ok(StreamHeader {
        version,
        suite_kem,
        suite_aead,
        flags,
        kem_ciphertext,
    })
}
