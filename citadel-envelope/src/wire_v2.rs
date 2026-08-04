// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict non-streaming envelope v2 codec.

extern crate alloc;

use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::backend::{ActiveBackend, CryptoBackend};
use crate::error::{DecryptionError, EncodingError};
use crate::kem::KemProvider;
use crate::wire::KEM_CIPHERTEXT_BYTES;

pub const MAGIC: &[u8; 4] = b"CTD2";
pub const VERSION: u8 = 2;
pub const FLAGS: u8 = 0;
// The KEM suite byte is no longer a constant here. It is owned by `wire::SUITE_TABLE`
// and read from the provider (`K::SUITE_KEM`) — a second copy in this module is the
// drift the table exists to prevent.
pub const SUITE_KDF: u8 = 0xC1;
pub const SUITE_AEAD: u8 = 0xB1;
pub const HEADER_LEN: usize = 98;
pub const TAG_LEN: usize = 16;
/// AES-GCM nonce length. The nonce occupies the trailing `header[86..98]`.
pub const NONCE_LEN: usize = 12;
/// The nonce-free header prefix (`header[..86]`). Packet 056: the KDF transcript and the
/// AEAD associated data bind ONLY this prefix, NOT the nonce. Under FIPS Scenario 2 the
/// module generates the nonce during seal (`RandomizedNonceKey`), so the key and the AAD
/// cannot depend on it. The nonce remains integrity-protected by AES-GCM itself (a flipped
/// nonce yields a wrong tag), so excluding it from the explicit AAD does not weaken tamper
/// detection — see `p3d_open_rejects_*_nonce_tampered`.
pub const HEADER_BOUND_LEN: usize = HEADER_LEN - NONCE_LEN;
/// Minimum envelope length **for the `0xA3` suite**.
///
/// Retained at its frozen value because it is re-exported on the public SDK surface as
/// `MIN_ENVELOPE_V2_BYTES`. It is *not* safe as a pre-suite-resolution bound — use
/// [`MIN_ENVELOPE_LEN_ANY_SUITE`] for that.
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + KEM_CIPHERTEXT_BYTES + TAG_LEN;

/// Smallest envelope any supported suite can produce.
///
/// `decode()`'s first guard runs before the suite byte has been validated, so it must
/// not assume any one suite's sizes. Derived from `wire::SUITE_TABLE`, so adding a
/// suite cannot leave this stale. With a single suite in the table this equals
/// [`MIN_ENVELOPE_LEN`].
pub const MIN_ENVELOPE_LEN_ANY_SUITE: usize =
    HEADER_LEN + crate::wire::MIN_KEM_CIPHERTEXT_BYTES + TAG_LEN;
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
    /// The suite resolved from `header[6]`, and the source of every length used to
    /// slice this envelope. Callers that decapsulate must check it against their own
    /// provider's `SUITE_KEM` — `decode` deliberately does not know which key you hold.
    pub suite: crate::wire::SuiteParams,
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
    ActiveBackend::sha3_256(&K::public_key_bytes(pk))
}

pub fn context_hash(context: &[u8]) -> [u8; 32] {
    ActiveBackend::sha3_256(context)
}

/// Build the 98-byte header for suite `K`.
///
/// The suite byte and `kem_ct_len` come from the provider, and both are cross-checked
/// against `wire::SUITE_TABLE` before anything is written. A provider whose associated
/// consts disagree with the table is a drift bug that would produce envelopes the
/// decoder rejects; it fails here instead, at encode time, on the writer's machine.
pub fn encode_header<K: KemProvider>(
    plaintext_len: usize,
    recipient_hash: &[u8; 32],
    context_hash: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<[u8; HEADER_LEN], EncodingError> {
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(EncodingError);
    }
    let suite = crate::wire::suite_params(K::SUITE_KEM).ok_or(EncodingError)?;
    if suite.kem_ciphertext_bytes != K::KEM_CIPHERTEXT_BYTES {
        return Err(EncodingError);
    }
    let kem_ct_len = u16::try_from(K::KEM_CIPHERTEXT_BYTES).map_err(|_| EncodingError)?;

    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = FLAGS;
    header[6] = K::SUITE_KEM;
    header[7] = SUITE_KDF;
    header[8] = SUITE_AEAD;
    header[9] = 0;
    header[10..12].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    header[12..14].copy_from_slice(&kem_ct_len.to_be_bytes());
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
    // Bind the nonce-free header prefix only (packet 056); the nonce at header[86..98] is
    // module-generated during seal and cannot be an input to the key derivation.
    let bound = header.get(..HEADER_BOUND_LEN).ok_or(EncodingError)?;
    let mut out = Vec::with_capacity(
        KDF_LABEL.len() + 2 + bound.len() + 2 + kem_ct.len() + 4 + context.len(),
    );
    out.extend_from_slice(KDF_LABEL);
    push_u16(&mut out, bound.len())?;
    out.extend_from_slice(bound);
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
    // Bind the nonce-free header prefix only (packet 056); the module-generated nonce at
    // header[86..98] is authenticated by AES-GCM itself, not by this explicit AAD.
    let bound = header.get(..HEADER_BOUND_LEN).ok_or(EncodingError)?;
    let mut out = Vec::with_capacity(
        AAD_LABEL.len()
            + 2
            + bound.len()
            + 2
            + kem_ct.len()
            + 4
            + context.len()
            + 4
            + caller_aad.len(),
    );
    out.extend_from_slice(AAD_LABEL);
    push_u16(&mut out, bound.len())?;
    out.extend_from_slice(bound);
    push_u16(&mut out, kem_ct.len())?;
    out.extend_from_slice(kem_ct);
    push_u32(&mut out, context.len())?;
    out.extend_from_slice(context);
    push_u32(&mut out, caller_aad.len())?;
    out.extend_from_slice(caller_aad);
    Ok(out)
}

pub fn derive_key(shared_secret: &[u8], transcript: &[u8]) -> Result<[u8; 32], EncodingError> {
    let salt = ActiveBackend::sha256(EXTRACT_SALT_LABEL);
    let mut key = [0u8; 32];
    ActiveBackend::hkdf_sha256(Some(&salt), shared_secret, transcript, &mut key)?;
    Ok(key)
}

pub fn encode<K: KemProvider>(
    header: &[u8; HEADER_LEN],
    kem_ct: &[u8],
    aead_ct: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    if kem_ct.len() != K::KEM_CIPHERTEXT_BYTES || aead_ct.len() < TAG_LEN {
        return Err(EncodingError);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + kem_ct.len() + aead_ct.len());
    out.extend_from_slice(header);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(aead_ct);
    Ok(out)
}

/// Strictly parse a CTD2 envelope of **any supported suite**.
///
/// Order matters and is the whole point of this function:
///
/// 1. A conservative length floor that assumes nothing about the suite
///    ([`MIN_ENVELOPE_LEN_ANY_SUITE`]) — enough to reach the header, no more.
/// 2. The suite-invariant header fields.
/// 3. **Resolve `header[6]` against the suite table.** Unsupported, allocated-but-
///    unimplemented, and reserved identifiers all resolve to `None` and reject here.
/// 4. Only now, every length comes from the resolved suite: the declared `kem_ct_len`
///    must equal it, and the **total length is re-checked exactly** against it.
///
/// Step 4's exact re-check is what makes the slicing below sound. Without it a short
/// envelope declaring a large suite (or the reverse) would be sliced with the wrong
/// offsets — the length-confusion trap this packet exists to close.
pub fn decode(data: &[u8]) -> Result<Parts<'_>, DecryptionError> {
    if data.len() < MIN_ENVELOPE_LEN_ANY_SUITE {
        return Err(DecryptionError);
    }
    let header = data.get(..HEADER_LEN).ok_or(DecryptionError)?;
    if &header[..4] != MAGIC
        || header[4] != VERSION
        || header[5] != FLAGS
        || header[7] != SUITE_KDF
        || header[8] != SUITE_AEAD
        || header[9] != 0
        || u16::from_be_bytes([header[10], header[11]]) as usize != HEADER_LEN
    {
        return Err(DecryptionError);
    }

    let suite = crate::wire::suite_params(header[6]).ok_or(DecryptionError)?;
    if u16::from_be_bytes([header[12], header[13]]) as usize != suite.kem_ciphertext_bytes {
        return Err(DecryptionError);
    }

    let encoded_len = u64::from_be_bytes(header[14..22].try_into().map_err(|_| DecryptionError)?);
    let plaintext_len = usize::try_from(encoded_len).map_err(|_| DecryptionError)?;
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(DecryptionError);
    }
    let expected_len = HEADER_LEN
        .checked_add(suite.kem_ciphertext_bytes)
        .and_then(|n| n.checked_add(TAG_LEN))
        .and_then(|n| n.checked_add(plaintext_len))
        .ok_or(DecryptionError)?;
    if data.len() != expected_len {
        return Err(DecryptionError);
    }

    // Sound because `data.len() == expected_len >= HEADER_LEN + suite.kem_ciphertext_bytes`.
    let kem_start = HEADER_LEN;
    let kem_end = kem_start + suite.kem_ciphertext_bytes;
    let nonce: &[u8; 12] = header[86..98].try_into().map_err(|_| DecryptionError)?;
    let recipient_key_hash = header[22..54].try_into().map_err(|_| DecryptionError)?;
    Ok(Parts {
        header,
        kem_ciphertext: &data[kem_start..kem_end],
        nonce,
        aead_ciphertext: &data[kem_end..],
        recipient_key_hash,
        plaintext_len,
        suite,
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
    // Packet 056: the nonce is generated by the AEAD backend during seal (fips: the module's
    // Scenario-2 `RandomizedNonceKey`; default: getrandom), NOT chosen up front. The header is
    // built with a zero placeholder — header[86..98] is excluded from the KDF/AAD binding — and
    // the real nonce is written in after seal returns it.
    let mut header = encode_header::<K>(
        plaintext.len(),
        &public_key_hash::<K>(pk),
        &context_hash(context),
        &[0u8; NONCE_LEN],
    )?;
    let transcript = kdf_transcript(&header, &kem_ct, context)?;
    let key = Zeroizing::new(derive_key(&shared_secret, &transcript)?);
    let bound_aad = associated_data(&header, &kem_ct, context, aad)?;
    let (nonce, aead_ct) = ActiveBackend::aead_seal(&key, plaintext, &bound_aad)?;
    header[HEADER_BOUND_LEN..HEADER_LEN].copy_from_slice(&nonce);
    encode::<K>(&header, &kem_ct, &aead_ct)
}

/// Deterministic (fixed-nonce) seal — checked-in vector generation ONLY (packet 056).
/// Gated to `kat` to match its sole caller, `crate::v2_test_vectors`; production `seal`
/// no longer routes through it (it uses the nonce-generating `ActiveBackend::aead_seal`).
#[cfg(feature = "kat")]
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
    let header = encode_header::<K>(
        plaintext.len(),
        &public_key_hash::<K>(pk),
        &context_hash(context),
        nonce,
    )?;
    let transcript = kdf_transcript(&header, kem_ct, context)?;
    let key = Zeroizing::new(derive_key(shared_secret, &transcript)?);
    let bound_aad = associated_data(&header, kem_ct, context, aad)?;
    // Deterministic (fixed-nonce) path — vector generation only. Uses the RustCrypto AES-GCM
    // primitive DIRECTLY, not `ActiveBackend`: AES-256-GCM is deterministic given (key, nonce,
    // aad) and byte-identical across RustCrypto and AWS-LC, so the reference vector is valid for
    // both backends. The fips build cannot fix the nonce (Scenario 2 / `RandomizedNonceKey`), so
    // it is proven instead by roundtrip + interop + a frozen-DECRYPT KAT against this vector.
    let aead_ct = crate::aead::aead_seal(&key, nonce, plaintext, &bound_aad)?;
    encode::<K>(&header, kem_ct, &aead_ct)
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
    // Cross-suite reject, before any crypto. `decode` validates that the envelope is
    // internally consistent for *its* suite; it cannot know which key the caller holds.
    // Opening an envelope of one suite with another suite's key must fail here, not
    // deeper in on a length mismatch inside decapsulate.
    if parts.suite.suite_kem != K::SUITE_KEM {
        return Err(DecryptionError);
    }
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
    let plaintext = ActiveBackend::aead_open(&key, parts.nonce, parts.aead_ciphertext, &bound_aad)?;
    if plaintext.len() != parts.plaintext_len {
        return Err(DecryptionError);
    }
    let expected_recipient = public_key_hash::<K>(&K::public_key_of(sk));
    if !bool::from(parts.recipient_key_hash.ct_eq(&expected_recipient)) {
        return Err(DecryptionError);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::{HybridX25519MlKem768Provider as P, KemProvider};

    #[test]
    fn decode_accepts_a_pristine_envelope() {
        let (pk, _sk) = P::keygen();
        let envelope: Vec<u8> = seal::<P>(&pk, b"a message", b"", b"ctx").expect("seal");
        let parts = decode(&envelope).expect("decode should accept pristine envelope");
        assert_eq!(
            parts.suite.suite_kem, 0xA3,
            "suite_kem must be 0xA3 for pristine envelope"
        );
    }

    #[test]
    fn decode_rejects_every_unsupported_suite_byte() {
        let (pk, _sk) = P::keygen();
        let pristine = seal::<P>(&pk, b"a message", b"", b"ctx").expect("seal");
        for suite_kem in 0..=u8::MAX {
            if suite_kem == 0xA3 {
                continue;
            }
            let mut envelope = pristine.clone();
            envelope[6] = suite_kem;
            assert!(
                decode(&envelope).is_err(),
                "suite byte {suite_kem:#04x} was accepted"
            );
        }
    }

    #[test]
    fn decode_rejects_allocated_and_reserved_suite_bytes() {
        let (pk, _sk) = P::keygen();
        let pristine = seal::<P>(&pk, b"a message", b"", b"ctx").expect("seal");
        for bad in [0xA4, 0xA5, 0xA6] {
            let mut envelope = pristine.clone();
            envelope[6] = bad;
            assert!(
                decode(&envelope).is_err(),
                "allocated/reserved suite byte {bad:#04x} was accepted"
            );
        }
    }

    #[test]
    fn decode_rejects_kem_ct_len_field_mismatch() {
        let (pk, _sk) = P::keygen();
        let pristine = seal::<P>(&pk, b"a message", b"", b"ctx").expect("seal");
        for bad_len in [1119u16, 1121, 0, 65535] {
            let mut envelope = pristine.clone();
            envelope[12..14].copy_from_slice(&bad_len.to_be_bytes());
            assert!(
                decode(&envelope).is_err(),
                "kem_ct_len {bad_len} was accepted"
            );
        }
    }

    #[test]
    fn decode_rejects_wrong_total_length() {
        let (pk, _sk) = P::keygen();
        let pristine = seal::<P>(&pk, b"a message", b"", b"ctx").expect("seal");
        for len in [HEADER_LEN - 1, HEADER_LEN + 1, HEADER_LEN] {
            let mut envelope = pristine.clone();
            envelope.truncate(len);
            assert!(
                decode(&envelope).is_err(),
                "envelope length {len} was accepted"
            );
        }
    }

    #[test]
    fn decode_rejects_altered_fixed_header_fields() {
        let (pk, _sk) = P::keygen();
        let pristine = seal::<P>(&pk, b"a message", b"", b"ctx").expect("seal");
        let mut envelope = pristine.clone();
        for i in [0, 4, 5, 7, 8, 9] {
            envelope[i] ^= 1;
            assert!(
                decode(&envelope).is_err(),
                "fixed header field at index {i} was altered"
            );
            envelope[i] ^= 1; // restore
        }
        let mut envelope = pristine.clone();
        envelope[10..12].copy_from_slice(&97u16.to_be_bytes());
        assert!(
            decode(&envelope).is_err(),
            "header length field set to 97 was accepted"
        );
    }

    #[test]
    fn decode_rejects_absurd_declared_plaintext_len() {
        let (pk, _sk) = P::keygen();
        let pristine = seal::<P>(&pk, b"a message", b"", b"ctx").expect("seal");
        for bad_len in [u64::MAX, 0x0000_0000_FFFF_FFFF, 0] {
            let mut envelope = pristine.clone();
            envelope[14..22].copy_from_slice(&bad_len.to_be_bytes());
            assert!(
                decode(&envelope).is_err(),
                "plaintext len {bad_len:#x} was accepted"
            );
        }
    }
}

#[cfg(test)]
mod p3c_cross_suite_tests {
    use super::*;
    use crate::kem::{HybridX25519MlKem768Provider as P3, KemProvider};
    use crate::kem_p384::HybridP384MlKem1024Provider as P4;

    const A3_TOTAL: usize = 1243;
    const A4_TOTAL: usize = 1788;

    #[test]
    fn p3c_decode_accepts_pristine_a4_envelope() {
        let (pk3, _sk3) = P3::keygen();
        let env3: Vec<u8> = seal::<P3>(&pk3, b"a message", b"", b"ctx").expect("seal a3");
        let (pk4, _sk4) = P4::keygen();
        let env4: Vec<u8> = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");

        assert_eq!(env3.len(), A3_TOTAL);
        assert_eq!(env4.len(), A4_TOTAL);

        let parts = decode(&env4).expect("decode should accept pristine a4 envelope");
        assert_eq!(parts.suite.suite_kem, 0xA4);
        assert_eq!(parts.kem_ciphertext.len(), 1665usize);
    }

    #[test]
    fn p3c_decode_rejects_a3_envelope_relabelled_a4() {
        let (pk3, _sk3) = P3::keygen();
        let env3: Vec<u8> = seal::<P3>(&pk3, b"a message", b"", b"ctx").expect("seal a3");
        let mut envelope = env3.clone();
        envelope[6] = 0xA4;
        assert!(
            decode(&envelope).is_err(),
            "a3 relabelled as a4 should be rejected"
        );
    }

    #[test]
    fn p3c_decode_rejects_a4_envelope_relabelled_a3() {
        let (pk4, _sk4) = P4::keygen();
        let env4: Vec<u8> = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        let mut envelope = env4.clone();
        envelope[6] = 0xA3;
        assert!(
            decode(&envelope).is_err(),
            "a4 relabelled as a3 should be rejected"
        );
    }

    #[test]
    fn p3c_decode_rejects_a4_envelope_truncated_to_a3_total_length() {
        let (pk4, _sk4) = P4::keygen();
        let env4: Vec<u8> = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        let mut envelope = env4.clone();
        envelope.truncate(A3_TOTAL);
        assert!(
            decode(&envelope).is_err(),
            "a4 truncated to a3 length should be rejected"
        );
    }

    #[test]
    fn p3c_decode_rejects_a3_envelope_padded_to_a4_total_length() {
        let (pk3, _sk3) = P3::keygen();
        let env3: Vec<u8> = seal::<P3>(&pk3, b"a message", b"", b"ctx").expect("seal a3");
        let mut envelope = env3.clone();
        while envelope.len() < A4_TOTAL {
            envelope.push(0u8);
        }
        assert!(
            decode(&envelope).is_err(),
            "a3 padded to a4 length should be rejected"
        );

        let mut envelope = env3.clone();
        envelope[6] = 0xA4;
        while envelope.len() < A4_TOTAL {
            envelope.push(0u8);
        }
        assert!(
            decode(&envelope).is_err(),
            "a3 with suite a4 padded to a4 length should be rejected"
        );
    }

    #[test]
    fn p3c_decode_rejects_one_byte_longer_than_valid() {
        let (pk3, _sk3) = P3::keygen();
        let env3: Vec<u8> = seal::<P3>(&pk3, b"a message", b"", b"ctx").expect("seal a3");
        let mut envelope = env3.clone();
        envelope.push(0u8);
        assert!(
            decode(&envelope).is_err(),
            "a3 one byte longer should be rejected"
        );

        let (pk4, _sk4) = P4::keygen();
        let env4: Vec<u8> = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        let mut envelope = env4.clone();
        envelope.push(0u8);
        assert!(
            decode(&envelope).is_err(),
            "a4 one byte longer should be rejected"
        );
    }

    #[test]
    fn p3c_decode_rejects_reserved_and_unknown_suite_bytes_on_both_envelopes() {
        let (pk3, _sk3) = P3::keygen();
        let env3: Vec<u8> = seal::<P3>(&pk3, b"a message", b"", b"ctx").expect("seal a3");
        for suite_byte in [0x00, 0xA5, 0xA6, 0xFF] {
            let mut envelope = env3.clone();
            envelope[6] = suite_byte;
            assert!(
                decode(&envelope).is_err(),
                "suite byte {suite_byte:#04x} should be rejected"
            );
        }

        let (pk4, _sk4) = P4::keygen();
        let env4: Vec<u8> = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        for suite_byte in [0x00, 0xA5, 0xA6, 0xFF] {
            let mut envelope = env4.clone();
            envelope[6] = suite_byte;
            assert!(
                decode(&envelope).is_err(),
                "suite byte {suite_byte:#04x} should be rejected"
            );
        }
    }
}

/// Open-layer red tests for the `0xA4` suite (VALIDATION red tests 1, 2, 3).
///
/// `p3c_cross_suite_tests` covers the codec: `decode` resolving `header[6]` and
/// validating every length from the resolved suite. These go through `open`, which is
/// where key material, the KDF transcript, and the AEAD actually participate.
///
/// Every test asserts only that the input is REJECTED, never which layer rejects it.
/// Which check fires first is an implementation detail a later hardening change is
/// allowed to move, and a test that pins it would fail for the wrong reason.
///
/// Measured caveat, recorded so the suite is not read as stronger than it is: of these
/// seven, only `p3d_open_rejects_a4_envelope_opened_with_a_different_aad` dies under any
/// single mutation of this crate. The others are regression tests -- the mechanisms they
/// depend on (differing ciphertext lengths, SEC1 parsing, the nonce) are all required for
/// correct decryption too, so breaking one kills the roundtrip control instead. See
/// eem/033_swarm/grade_p3d_open_layer.sh for the arms and the measurements.
#[cfg(test)]
mod p3d_open_layer_tests {
    use super::*;
    use crate::kem::{HybridX25519MlKem768Provider as P3, KemProvider};
    use crate::kem_p384::HybridP384MlKem1024Provider as P4;

    const A4_TOTAL: usize = 1788;

    /// The positive control. Without it, "open::<P4> rejects everything" -- including a
    /// `0xA4` path deleted outright -- would read as a clean sweep of the six red tests.
    #[test]
    fn p3d_open_roundtrips_a_pristine_a4_envelope() {
        let (pk4, sk4) = P4::keygen();
        let envelope = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        assert_eq!(envelope.len(), A4_TOTAL);
        let plaintext = open::<P4>(&sk4, &envelope, b"", b"ctx").expect("open a4");
        assert_eq!(&plaintext[..], b"a message");
    }

    /// VALIDATION red test 1.
    #[test]
    fn p3d_open_rejects_a3_envelope_with_an_a4_secret_key() {
        let (pk3, _sk3) = P3::keygen();
        let envelope = seal::<P3>(&pk3, b"a message", b"", b"ctx").expect("seal a3");
        let (_pk4, sk4) = P4::keygen();
        assert!(
            open::<P4>(&sk4, &envelope, b"", b"ctx").is_err(),
            "an a3 envelope must not open under an a4 key"
        );
    }

    /// VALIDATION red test 2.
    #[test]
    fn p3d_open_rejects_a4_envelope_with_an_a3_secret_key() {
        let (pk4, _sk4) = P4::keygen();
        let envelope = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        let (_pk3, sk3) = P3::keygen();
        assert!(
            open::<P3>(&sk3, &envelope, b"", b"ctx").is_err(),
            "an a4 envelope must not open under an a3 key"
        );
    }

    /// VALIDATION red test 3, restated.
    ///
    /// VALIDATION words this as "AEAD auth failure", which is not reachable: the suites'
    /// total lengths differ, so a flipped `header[6]` is rejected by `decode`'s exact
    /// total-length re-check long before any key is derived. No `header[6]` value can
    /// reach the AEAD on a well-formed envelope. The property worth testing is that the
    /// flip is rejected at all.
    #[test]
    fn p3d_open_rejects_a4_envelope_with_the_suite_byte_flipped_to_a3() {
        let (pk4, sk4) = P4::keygen();
        let mut envelope = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        envelope[6] = 0xA3;
        assert!(
            open::<P4>(&sk4, &envelope, b"", b"ctx").is_err(),
            "a suite-byte downgrade must be rejected"
        );
    }

    /// `envelope[22..54]` is the recipient key hash -- a header field `decode` does not
    /// validate, so this input survives the codec and is rejected inside `open`.
    #[test]
    fn p3d_open_rejects_a4_envelope_with_a_tampered_recipient_key_hash() {
        let (pk4, sk4) = P4::keygen();
        let mut envelope = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        envelope[22] ^= 0x01;
        assert!(
            open::<P4>(&sk4, &envelope, b"", b"ctx").is_err(),
            "a tampered recipient key hash must be rejected"
        );
    }

    /// `envelope[86..98]` is the nonce.
    #[test]
    fn p3d_open_rejects_a4_envelope_with_the_nonce_tampered() {
        let (pk4, sk4) = P4::keygen();
        let mut envelope = seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal a4");
        envelope[86] ^= 0x01;
        assert!(
            open::<P4>(&sk4, &envelope, b"", b"ctx").is_err(),
            "a tampered nonce must be rejected"
        );
    }

    /// The one test here with a mutation gate: dropping `caller_aad` from
    /// `associated_data` is symmetric across seal and open, so the roundtrip keeps
    /// working while this test starts passing bad input. Note the envelope is PRISTINE --
    /// only the caller's aad argument differs.
    #[test]
    fn p3d_open_rejects_a4_envelope_opened_with_a_different_aad() {
        let (pk4, sk4) = P4::keygen();
        let envelope = seal::<P4>(&pk4, b"a message", b"aad-one", b"ctx").expect("seal a4");
        assert!(
            open::<P4>(&sk4, &envelope, b"aad-two", b"ctx").is_err(),
            "opening under a different aad must fail"
        );
    }
}
