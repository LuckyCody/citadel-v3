// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! P007: External audit log anchoring for tamper detection
//!
//! Provides immutable witness infrastructure to detect audit log truncation.
//! Every N entries, the current hash is published to an external witness service.
//! Verification compares local hash chain against external anchors to detect tampering.

use serde::{Deserialize, Serialize};

/// P007: Error type for witness operations
#[derive(Debug, Clone)]
pub struct WitnessError {
    pub message: String,
}

impl WitnessError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "witness error: {}", self.message)
    }
}

impl std::error::Error for WitnessError {}

/// P007: Receipt proving hash was published to external witness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// Entry number that was anchored
    pub entry_number: u64,
    /// Hash that was anchored
    pub hash_hex: String,
    /// Timestamp when anchored
    pub timestamp: String,
    /// Witness identifier (URL, service name, etc)
    pub witness_id: String,
    /// Signature or proof from witness (format depends on witness type)
    pub proof: String,
}

/// P007: Trait for external audit witnesses
///
/// Implementations must provide immutable storage where:
/// - Published hashes cannot be deleted
/// - Published hashes cannot be modified
/// - Publication order is preserved
/// - Timestamp is trustworthy
pub trait AuditWitness: Send + Sync {
    /// Publish hash to external immutable witness.
    ///
    /// Returns receipt proving publication.
    fn publish_hash(&self, entry_number: u64, hash: &[u8]) -> Result<WitnessReceipt, WitnessError>;

    /// Verify hash against witness record.
    ///
    /// Returns true if hash matches what was published, false otherwise.
    fn verify_hash(&self, entry_number: u64, hash: &[u8]) -> Result<bool, WitnessError>;

    /// Get receipt for a previously published hash.
    fn get_receipt(&self, entry_number: u64) -> Result<WitnessReceipt, WitnessError>;

    /// Get witness identifier for logging
    fn witness_id(&self) -> &str;
}

// ---------------------------------------------------------------------------
// File-based witness (for development/testing)
// ---------------------------------------------------------------------------

/// P007: File-based witness for development and testing.
///
/// Stores receipts in append-only files with fsync.
/// NOT suitable for production (local attacker can truncate files).
/// Use S3, timestamping service, or CT log for production.
pub struct FileWitness {
    receipts_path: std::path::PathBuf,
}

impl FileWitness {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Result<Self, WitnessError> {
        let receipts_path = path.into();

        // Create parent directory if needed
        if let Some(parent) = receipts_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WitnessError::new(format!("create witness dir: {}", e)))?;
        }

        Ok(Self { receipts_path })
    }
}

impl AuditWitness for FileWitness {
    fn publish_hash(&self, entry_number: u64, hash: &[u8]) -> Result<WitnessReceipt, WitnessError> {
        use std::io::Write;

        let receipt = WitnessReceipt {
            entry_number,
            hash_hex: hex::encode(hash),
            timestamp: chrono::Utc::now().to_rfc3339(),
            witness_id: format!("file:{}", self.receipts_path.display()),
            proof: format!("fsync-{}", entry_number),
        };

        let opts = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut o = std::fs::OpenOptions::new();
                o.create(true).append(true).mode(0o600);
                o
            }
            #[cfg(not(unix))]
            {
                let mut o = std::fs::OpenOptions::new();
                o.create(true).append(true);
                o
            }
        };
        let mut file = opts
            .open(&self.receipts_path)
            .map_err(|e| WitnessError::new(format!("open receipts file: {}", e)))?;

        let line = format!(
            "{}\n",
            serde_json::to_string(&receipt)
                .map_err(|e| WitnessError::new(format!("serialize receipt: {}", e)))?
        );

        file.write_all(line.as_bytes())
            .map_err(|e| WitnessError::new(format!("write receipt: {}", e)))?;

        file.sync_all()
            .map_err(|e| WitnessError::new(format!("fsync receipts: {}", e)))?;

        Ok(receipt)
    }

    fn verify_hash(&self, entry_number: u64, hash: &[u8]) -> Result<bool, WitnessError> {
        let receipt = self.get_receipt(entry_number)?;
        let expected_hex = hex::encode(hash);
        Ok(receipt.hash_hex == expected_hex)
    }

    fn get_receipt(&self, entry_number: u64) -> Result<WitnessReceipt, WitnessError> {
        use std::io::BufRead;

        let file = std::fs::File::open(&self.receipts_path)
            .map_err(|e| WitnessError::new(format!("open receipts file: {}", e)))?;

        let reader = std::io::BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(|e| WitnessError::new(format!("read receipt line: {}", e)))?;

            let receipt: WitnessReceipt = serde_json::from_str(&line)
                .map_err(|e| WitnessError::new(format!("parse receipt: {}", e)))?;

            if receipt.entry_number == entry_number {
                return Ok(receipt);
            }
        }

        Err(WitnessError::new(format!(
            "receipt not found for entry {}",
            entry_number
        )))
    }

    fn witness_id(&self) -> &str {
        "file-witness"
    }
}

// ---------------------------------------------------------------------------
// No-op witness (when anchoring is disabled)
// ---------------------------------------------------------------------------

/// P007: No-op witness when external anchoring is disabled.
///
/// All operations succeed without actually anchoring anything.
/// Used when CITADEL_AUDIT_WITNESS_TYPE is not set or set to "none".
pub struct NoOpWitness;

impl AuditWitness for NoOpWitness {
    fn publish_hash(&self, entry_number: u64, hash: &[u8]) -> Result<WitnessReceipt, WitnessError> {
        Ok(WitnessReceipt {
            entry_number,
            hash_hex: hex::encode(hash),
            timestamp: chrono::Utc::now().to_rfc3339(),
            witness_id: "none".into(),
            proof: "disabled".into(),
        })
    }

    fn verify_hash(&self, _entry_number: u64, _hash: &[u8]) -> Result<bool, WitnessError> {
        Ok(true) // Always passes when disabled
    }

    fn get_receipt(&self, _entry_number: u64) -> Result<WitnessReceipt, WitnessError> {
        Err(WitnessError::new("witness disabled"))
    }

    fn witness_id(&self) -> &str {
        "none"
    }
}

// ---------------------------------------------------------------------------
// Witness factory
// ---------------------------------------------------------------------------

/// P007: Create witness from environment configuration
pub fn create_witness_from_env() -> Result<Box<dyn AuditWitness>, WitnessError> {
    let witness_type =
        std::env::var("CITADEL_AUDIT_WITNESS_TYPE").unwrap_or_else(|_| "none".to_string());

    match witness_type.as_str() {
        "none" | "" => {
            tracing::info!("audit witness disabled (CITADEL_AUDIT_WITNESS_TYPE=none)");
            Ok(Box::new(NoOpWitness))
        }
        "file" => {
            let path = std::env::var("CITADEL_AUDIT_WITNESS_PATH")
                .unwrap_or_else(|_| "./citadel-data/audit-receipts.jsonl".to_string());
            tracing::info!(path = %path, "using file-based audit witness (NOT FOR PRODUCTION)");
            Ok(Box::new(FileWitness::new(path)?))
        }
        other => Err(WitnessError::new(format!(
            "unknown witness type '{}' (supported: none, file)",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_witness() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("receipts.jsonl");

        let witness = FileWitness::new(&path).unwrap();

        let hash = b"test_hash_12345678901234567890123";
        let receipt = witness.publish_hash(1, hash).unwrap();

        assert_eq!(receipt.entry_number, 1);
        assert_eq!(receipt.hash_hex, hex::encode(hash));

        // Verify
        assert!(witness.verify_hash(1, hash).unwrap());

        // Wrong hash should fail
        assert!(!witness.verify_hash(1, b"wrong_hash").unwrap());
    }

    #[test]
    fn test_noop_witness() {
        let witness = NoOpWitness;

        let hash = b"any_hash";
        let receipt = witness.publish_hash(1, hash).unwrap();

        assert_eq!(receipt.witness_id, "none");
        assert!(witness.verify_hash(1, hash).unwrap());
    }
}
