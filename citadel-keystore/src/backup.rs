// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Encrypted backup and restore for key metadata.
//!
//! Backup format:
//! ```text
//! magic[7]     = b"CTDLBAK"
//! version[1]   = 0x01
//! timestamp[8] = u64 BE unix seconds
//! nonce[12]    = random AES-GCM nonce
//! ciphertext   = AES-256-GCM(CITADEL_MASTER_KEY, JSON(backup_payload))
//! tag[16]      = GCM authentication tag (appended by aes-gcm crate)
//! ```
//!
//! The payload is a JSON array of `KeyMetadata` objects. Wrapped key material
//! (AES-encrypted or Citadel-envelope-encrypted) is safe to include — it cannot
//! be decrypted without CITADEL_MASTER_KEY or the parent KEK's secret key.
//!
//! The backup does NOT include:
//! - CITADEL_MASTER_KEY itself
//! - Plaintext secret key bytes (these would only appear in dev mode)

use crate::types::KeyMetadata;
use crate::{RootKeyError, RootKeyProvider};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const BACKUP_MAGIC: &[u8; 7] = b"CTDLBAK";
pub const BACKUP_VERSION: u8 = 0x01;
const HEADER_LEN: usize = 7 + 1 + 8 + 12; // magic + version + timestamp + nonce

// ---------------------------------------------------------------------------
// Backup payload
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    schema_version: u32,
    created_at: DateTime<Utc>,
    keys: Vec<KeyMetadata>,
    key_count: usize,
}

// ---------------------------------------------------------------------------
// Create backup
// ---------------------------------------------------------------------------

/// Create an encrypted backup of all key metadata.
///
/// Encrypts with `CITADEL_MASTER_KEY` using AES-256-GCM + HKDF-SHA256.
/// A unique wrapping key is derived: `HKDF(master_key, info="citadel-backup-v1:{timestamp}")`.
pub fn create_backup(keys: &[KeyMetadata], master_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload = BackupPayload {
        schema_version: 1,
        created_at: Utc::now(),
        keys: keys.to_vec(),
        key_count: keys.len(),
    };

    let json = serde_json::to_vec(&payload).map_err(|e| format!("serialize: {}", e))?;

    // Derive a backup-specific wrapping key.
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut info = Vec::new();
    info.extend_from_slice(b"citadel-backup-v1:");
    info.extend_from_slice(&now_unix.to_be_bytes());
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, wrap_key.as_mut())
        .map_err(|e| format!("HKDF expand: {}", e))?;

    // Random 12-byte nonce.
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new((&*wrap_key).into());
    let nonce = Nonce::from(nonce_bytes);
    // AAD binds to the timestamp so the nonce can't be reused across backup files.
    let aad = now_unix.to_be_bytes();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &json,
                aad: &aad,
            },
        )
        .map_err(|_| "AES-256-GCM encryption failed")?;

    // Assemble backup file.
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.push(BACKUP_VERSION);
    out.extend_from_slice(&now_unix.to_be_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

// ---------------------------------------------------------------------------
// Verify backup
// ---------------------------------------------------------------------------

/// Verify that a backup file is structurally valid and decryptable.
///
/// Returns `(key_count, created_at)` on success.
pub fn verify_backup(data: &[u8], master_key: &[u8; 32]) -> Result<(usize, DateTime<Utc>), String> {
    let payload = decrypt_backup(data, master_key)?;
    Ok((payload.key_count, payload.created_at))
}

// ---------------------------------------------------------------------------
// Restore backup
// ---------------------------------------------------------------------------

/// Decrypt and return all key metadata from a backup.
pub fn restore_backup(data: &[u8], master_key: &[u8; 32]) -> Result<Vec<KeyMetadata>, String> {
    let payload = decrypt_backup(data, master_key)?;
    Ok(payload.keys)
}

/// Create a backup using an explicit custody provider without exposing key
/// bytes through the application call site.
pub fn create_backup_with_provider(
    keys: &[KeyMetadata],
    provider: &dyn RootKeyProvider,
) -> Result<Vec<u8>, String> {
    let key = provider.load_root_key().map_err(root_provider_error)?;
    create_backup(keys, &key)
}

/// Verify a backup using the configured custody provider.
pub fn verify_backup_with_provider(
    data: &[u8],
    provider: &dyn RootKeyProvider,
) -> Result<(usize, DateTime<Utc>), String> {
    let key = provider.load_root_key().map_err(root_provider_error)?;
    verify_backup(data, &key)
}

/// Restore a backup using the configured custody provider.
pub fn restore_backup_with_provider(
    data: &[u8],
    provider: &dyn RootKeyProvider,
) -> Result<Vec<KeyMetadata>, String> {
    let key = provider.load_root_key().map_err(root_provider_error)?;
    restore_backup(data, &key)
}

fn root_provider_error(error: RootKeyError) -> String {
    format!("root-key provider unavailable: {error}")
}

// ---------------------------------------------------------------------------
// Internal decryption
// ---------------------------------------------------------------------------

fn decrypt_backup(data: &[u8], master_key: &[u8; 32]) -> Result<BackupPayload, String> {
    if data.len() < HEADER_LEN + 16 {
        return Err("backup file too short".into());
    }

    // Validate magic.
    if &data[..7] != BACKUP_MAGIC {
        return Err(format!(
            "invalid magic bytes; expected {:?}, got {:?}",
            BACKUP_MAGIC,
            &data[..7]
        ));
    }

    // Version.
    if data[7] != BACKUP_VERSION {
        return Err(format!(
            "unsupported backup version {}; expected {}",
            data[7], BACKUP_VERSION
        ));
    }

    // Timestamp (used in key derivation).
    let timestamp = u64::from_be_bytes(data[8..16].try_into().unwrap());

    // Nonce.
    let nonce_bytes: &[u8; 12] = data[16..28].try_into().unwrap();
    let ciphertext = &data[28..];

    // Re-derive the wrapping key.
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut info = Vec::new();
    info.extend_from_slice(b"citadel-backup-v1:");
    info.extend_from_slice(&timestamp.to_be_bytes());
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, wrap_key.as_mut())
        .map_err(|e| format!("HKDF expand: {}", e))?;

    let cipher = Aes256Gcm::new((&*wrap_key).into());
    let nonce = Nonce::from(*nonce_bytes);
    let aad = timestamp.to_be_bytes();
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "AES-256-GCM decryption failed — wrong master key or corrupted backup")?;

    serde_json::from_slice(&plaintext).map_err(|e| format!("backup payload parse failed: {}", e))
}

// ---------------------------------------------------------------------------
// P194 -- Backup/restore security boundary tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn wrong_master_key() -> [u8; 32] {
        [0xFFu8; 32]
    }

    fn sample_keys() -> Vec<KeyMetadata> {
        vec![] // empty is valid for backup/restore test
    }

    /// P194 -- Backup created with valid master key can be verified and restored.
    #[test]
    fn backup_roundtrip_succeeds_with_correct_key() {
        let master = test_master_key();
        let keys = sample_keys();

        let backup = create_backup(&keys, &master).expect("create_backup must succeed");
        assert!(!backup.is_empty(), "backup must produce non-empty output");

        let (count, _) = verify_backup(&backup, &master).expect("verify_backup must succeed");
        assert_eq!(count, keys.len(), "verified key count must match");

        let restored = restore_backup(&backup, &master).expect("restore_backup must succeed");
        assert_eq!(restored.len(), keys.len(), "restored key count must match");
    }

    /// P194 -- Restore with wrong master key must fail -- must not silently succeed.
    #[test]
    fn restore_with_wrong_master_key_fails() {
        let master = test_master_key();
        let wrong = wrong_master_key();
        let keys = sample_keys();

        let backup = create_backup(&keys, &master).expect("create_backup must succeed");

        let result = restore_backup(&backup, &wrong);
        assert!(result.is_err(), "restore with wrong master key must fail");

        let verify_result = verify_backup(&backup, &wrong);
        assert!(
            verify_result.is_err(),
            "verify with wrong master key must fail"
        );
    }

    /// P194 -- Restore of corrupted backup must fail cleanly -- no panic.
    #[test]
    fn restore_corrupted_backup_fails_cleanly() {
        let master = test_master_key();
        let backup = create_backup(&sample_keys(), &master).expect("create must succeed");

        // Flip bytes in the ciphertext portion (after the header)
        let mut corrupted = backup.clone();
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0xFF;
        corrupted[mid + 1] ^= 0xFF;

        let result = restore_backup(&corrupted, &master);
        assert!(result.is_err(), "corrupted backup must fail to restore");

        // Truncated backup must also fail
        let truncated = &backup[..backup.len() / 2];
        let result2 = restore_backup(truncated, &master);
        assert!(result2.is_err(), "truncated backup must fail to restore");
    }

    /// P194 -- Empty / zero-length backup fails cleanly.
    #[test]
    fn restore_empty_backup_fails_cleanly() {
        let master = test_master_key();
        let result = restore_backup(&[], &master);
        assert!(result.is_err(), "empty backup must fail to restore");
    }
}
