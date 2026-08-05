// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! ML-DSA-65 primitive operations on raw byte arrays.
//!
//! This module provides the low-level cryptographic primitives.
//! Key management is handled by citadel-keystore; this module
//! provides the algorithm layer that keystore calls.
//!
//! # API design
//!
//! All functions take and return plain byte slices or fixed arrays.
//! No ml-dsa types are exposed in the public API — callers use `Vec<u8>`
//! and `[u8; N]`. This insulates callers from ml-dsa crate version changes.
//!
//! # Key sizes (NIST FIPS 204 §7)
//!
//! | Material       | Size      | Notes                          |
//! |----------------|-----------|--------------------------------|
//! | Seed           | 32 bytes  | **Stored** — compact form      |
//! | Verifying key  | 1952 bytes| Public — stored in key_hex     |
//! | Signing key    | 4032 bytes| Expanded from seed on demand   |
//! | Signature      | 3309 bytes| Output of sign()               |

use crate::error::{SignError, VerifyError};
use crate::wire::{MLDSA65_SEED_BYTES, MLDSA65_SIG_BYTES, MLDSA65_VK_BYTES};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{KeyGen, MlDsa65, Signature as MlDsaSignature};
use rand_core::RngCore;
use zeroize::Zeroizing;

/// Generate an ML-DSA-65 keypair from a fresh random seed.
///
/// Returns `(verifying_key_bytes, seed_bytes)`:
/// - `verifying_key_bytes`: 1952-byte public verifying key (store in `public_key_hex`)
/// - `seed_bytes`: 32-byte seed (wrap under Citadel KEK; reconstruct signing key on demand)
///
/// The seed is wrapped in `Zeroizing` — it is zeroed when the caller drops it.
/// The caller must zeroize their copy after wrapping.
pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<[u8; MLDSA65_SEED_BYTES]>), SignError> {
    // Generate random seed using rand_core 0.6 OsRng.
    // We use from_seed() instead of key_gen() to avoid rand_core 0.10 dependency.
    let mut seed_bytes = Zeroizing::new([0u8; MLDSA65_SEED_BYTES]);
    rand_core::OsRng.fill_bytes(seed_bytes.as_mut());

    // Construct ml_dsa::Seed from our random bytes via TryFrom<&[u8]>
    let seed_array = ml_dsa::Seed::try_from(seed_bytes.as_slice())
        .map_err(|_| SignError("seed construction failed".into()))?;

    // Generate keypair from seed
    let kp = MlDsa65::from_seed(&seed_array);
    let vk_bytes: Vec<u8> = kp.verifying_key().encode().as_slice().to_vec();

    Ok((vk_bytes, seed_bytes))
}

/// Reconstruct the ML-DSA-65 verifying key from a 32-byte seed.
///
/// Useful for deriving the public key without storing the expanded signing key.
pub fn verifying_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, SignError> {
    if seed.len() != MLDSA65_SEED_BYTES {
        return Err(SignError(format!(
            "seed must be {} bytes, got {}",
            MLDSA65_SEED_BYTES,
            seed.len()
        )));
    }
    let seed_array =
        ml_dsa::Seed::try_from(seed).map_err(|_| SignError("seed construction failed".into()))?;
    let kp = MlDsa65::from_seed(&seed_array);
    Ok(kp.verifying_key().encode().as_slice().to_vec())
}

/// Sign a message using an ML-DSA-65 seed.
///
/// # Arguments
/// - `seed`: 32-byte ML-DSA-65 seed (unwrapped from Citadel by the keystore)
/// - `message`: message bytes to sign
///
/// # Returns
/// 3309-byte ML-DSA-65 signature.
///
/// Uses the deterministic variant of ML-DSA.Sign (no external randomness required).
pub fn sign_message(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, SignError> {
    if seed.len() != MLDSA65_SEED_BYTES {
        return Err(SignError(format!(
            "seed must be {} bytes, got {}",
            MLDSA65_SEED_BYTES,
            seed.len()
        )));
    }

    let seed_array =
        ml_dsa::Seed::try_from(seed).map_err(|_| SignError("seed construction failed".into()))?;

    let kp = MlDsa65::from_seed(&seed_array);

    let signature = kp
        .try_sign(message)
        .map_err(|e| SignError(format!("ML-DSA sign: {}", e)))?;

    Ok(signature.encode().as_slice().to_vec())
}

/// Verify an ML-DSA-65 signature.
///
/// # Arguments
/// - `verifying_key`: 1952-byte ML-DSA-65 verifying key (from `public_key_hex`)
/// - `message`: the signed message bytes
/// - `signature`: 3309-byte ML-DSA-65 signature
///
/// # Returns
/// `Ok(true)` if valid, `Ok(false)` if invalid (wrong key, tampered message, etc.).
/// `Err(VerifyError)` only for structural problems (wrong sizes, malformed bytes).
///
/// This function does NOT access Citadel or any secret key material — it is
/// fully stateless and can run without a Citadel server.
pub fn verify_message(
    verifying_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    if verifying_key.len() != MLDSA65_VK_BYTES {
        return Err(VerifyError(format!(
            "verifying key must be {} bytes, got {}",
            MLDSA65_VK_BYTES,
            verifying_key.len()
        )));
    }
    if signature.len() != MLDSA65_SIG_BYTES {
        return Err(VerifyError(format!(
            "signature must be {} bytes, got {}",
            MLDSA65_SIG_BYTES,
            signature.len()
        )));
    }

    // Decode verifying key
    let vk_encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key)
        .map_err(|_| VerifyError("verifying key decode failed".into()))?;
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_encoded);

    // Decode signature
    let sig_encoded = ml_dsa::EncodedSignature::<MlDsa65>::try_from(signature)
        .map_err(|_| VerifyError("signature decode failed".into()))?;
    let sig = MlDsaSignature::<MlDsa65>::decode(&sig_encoded)
        .ok_or_else(|| VerifyError("signature malformed".into()))?;

    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes_match_fips204() {
        // ML-DSA-65: vk=1952, sk(seed)=32, sig=3309
        // FIPS 204 §7 confirmed from ml-dsa source test output_sizes
        assert_eq!(MLDSA65_VK_BYTES, 1952);
        assert_eq!(MLDSA65_SEED_BYTES, 32);
        assert_eq!(MLDSA65_SIG_BYTES, 3309);
    }

    #[test]
    fn test_generate_keypair_sizes() {
        let (vk, seed) = generate_keypair().expect("keygen");
        assert_eq!(
            vk.len(),
            MLDSA65_VK_BYTES,
            "verifying key must be 1952 bytes"
        );
        assert_eq!(seed.len(), MLDSA65_SEED_BYTES, "seed must be 32 bytes");
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (vk, seed) = generate_keypair().expect("keygen");
        let message = b"citadel-signer test message for ML-DSA-65";

        let sig = sign_message(seed.as_slice(), message).expect("sign");
        assert_eq!(sig.len(), MLDSA65_SIG_BYTES, "signature must be 3309 bytes");

        let valid = verify_message(&vk, message, &sig).expect("verify");
        assert!(valid, "signature must verify");
    }

    #[test]
    fn test_tampered_message_rejected() {
        let (vk, seed) = generate_keypair().expect("keygen");
        let message = b"original message";
        let tampered = b"tampered message";

        let sig = sign_message(seed.as_slice(), message).expect("sign");
        let valid = verify_message(&vk, tampered, &sig).expect("verify");
        assert!(!valid, "tampered message must not verify");
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (_, seed1) = generate_keypair().expect("keygen1");
        let (vk2, _) = generate_keypair().expect("keygen2");
        let message = b"test message";

        let sig = sign_message(seed1.as_slice(), message).expect("sign");
        let valid = verify_message(&vk2, message, &sig).expect("verify");
        assert!(!valid, "wrong key must not verify");
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let (vk, seed) = generate_keypair().expect("keygen");
        let message = b"test message";
        let mut sig = sign_message(seed.as_slice(), message).expect("sign");

        // Flip a byte in the middle of the signature
        sig[1500] ^= 0xFF;

        // May return Ok(false) or Err (malformed) — both are correct rejections
        let result = verify_message(&vk, message, &sig);
        if let Ok(valid) = result {
            assert!(!valid, "tampered signature must not verify");
        }
    }

    #[test]
    fn test_verifying_key_from_seed() {
        let (vk, seed) = generate_keypair().expect("keygen");
        let vk2 = verifying_key_from_seed(seed.as_slice()).expect("reconstruct vk");
        assert_eq!(
            vk, vk2,
            "verifying key must be deterministically derived from seed"
        );
    }

    #[test]
    fn test_wrong_seed_size_rejected() {
        let bad_seed = vec![0u8; 16]; // Wrong size
        assert!(sign_message(&bad_seed, b"test").is_err());
    }

    #[test]
    fn test_wrong_vk_size_rejected() {
        let bad_vk = vec![0u8; 100]; // Wrong size
        let bad_sig = vec![0u8; MLDSA65_SIG_BYTES];
        assert!(verify_message(&bad_vk, b"test", &bad_sig).is_err());
    }
}
