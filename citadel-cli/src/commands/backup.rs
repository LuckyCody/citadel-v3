// SPDX-License-Identifier: AGPL-3.0-or-later
//! `citadel backup` subcommands.

use crate::CliContext;
use citadel_keystore::{
    backup::{create_backup, restore_backup, verify_backup},
    storage::{FileBackend, StorageBackend},
};
use clap::Subcommand;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Subcommand, Debug)]
pub enum BackupAction {
    /// Create an encrypted backup of all key metadata.
    Create {
        /// Output file path (e.g. backup.ctdlbak).
        output: PathBuf,
    },
    /// Verify a backup file can be decrypted and parsed.
    Verify {
        /// Backup file to verify.
        path: PathBuf,
    },
    /// Restore key metadata from an encrypted backup.
    Restore {
        /// Backup file to restore from.
        path: PathBuf,

        /// Dry run — decode and show what would be restored without writing.
        #[arg(long)]
        dry_run: bool,

        /// Overwrite existing keys (default: fail if a key ID already exists in storage).
        /// Without this flag, conflicting keys are reported and skipped.
        #[arg(long)]
        overwrite: bool,
    },
}

pub async fn run(ctx: &CliContext, action: BackupAction) -> i32 {
    match action {
        BackupAction::Create { output } => cmd_create(ctx, &output).await,
        BackupAction::Verify { path } => cmd_verify(&path).await,
        BackupAction::Restore {
            path,
            dry_run,
            overwrite,
        } => cmd_restore(ctx, &path, dry_run, overwrite).await,
    }
}

fn load_master_key() -> Result<Zeroizing<[u8; 32]>, String> {
    let hex_str = std::env::var("CITADEL_MASTER_KEY").map_err(|_| "CITADEL_MASTER_KEY not set")?;
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| format!("CITADEL_MASTER_KEY invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "CITADEL_MASTER_KEY must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

async fn cmd_create(ctx: &CliContext, output: &PathBuf) -> i32 {
    let master_key = match load_master_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let storage = match FileBackend::new(ctx.keys_dir()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let keys = match storage.list() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error listing keys: {}", e);
            return 1;
        }
    };

    let data = match create_backup(&keys, &master_key) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error creating backup: {}", e);
            return 1;
        }
    };

    if let Err(e) = std::fs::write(output, &data) {
        eprintln!("Error writing backup file: {}", e);
        return 1;
    }

    println!(
        "Backup created: {:?} ({} bytes, {} keys)",
        output,
        data.len(),
        keys.len()
    );
    0
}

async fn cmd_verify(path: &PathBuf) -> i32 {
    let master_key = match load_master_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading backup: {}", e);
            return 1;
        }
    };

    match verify_backup(&data, &master_key) {
        Ok((count, created_at)) => {
            println!(
                "Backup valid: {} key(s), created {}",
                count,
                created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            0
        }
        Err(e) => {
            eprintln!("Backup verification FAILED: {}", e);
            1
        }
    }
}

async fn cmd_restore(ctx: &CliContext, path: &PathBuf, dry_run: bool, overwrite: bool) -> i32 {
    let master_key = match load_master_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading backup: {}", e);
            return 1;
        }
    };

    let keys = match restore_backup(&data, &master_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error decrypting backup: {}", e);
            return 1;
        }
    };

    if dry_run {
        println!("Dry run — would restore {} key(s):", keys.len());
        for k in &keys {
            println!("  {} ({}) — {}", k.name, k.id.as_str(), k.state);
        }
        return 0;
    }

    // Write key files to disk.
    let storage = match FileBackend::new(ctx.keys_dir()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let mut restored = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for key in &keys {
        // P088 — Conflict policy: check before writing.
        // Default: fail-if-exists (skip conflicting keys and report them).
        // --overwrite: unconditionally overwrite any existing key with same ID.
        match storage.get(&key.id) {
            Ok(Some(existing)) if !overwrite => {
                eprintln!(
                    "  CONFLICT: key '{}' ({}) already exists (state={}) — skipping. \
                     Use --overwrite to replace.",
                    key.name,
                    key.id.as_str(),
                    existing.state
                );
                skipped += 1;
                continue;
            }
            Ok(Some(existing)) => {
                eprintln!(
                    "  OVERWRITE: replacing '{}' ({}) (existing state={}, backup state={})",
                    key.name,
                    key.id.as_str(),
                    existing.state,
                    key.state
                );
            }
            Ok(None) => {} // New key — restore normally.
            Err(e) => {
                eprintln!("  Error checking '{}': {}", key.name, e);
                errors += 1;
                continue;
            }
        }
        match storage.put(key) {
            Ok(()) => {
                println!("  Restored: {} ({})", key.name, key.id.as_str());
                restored += 1;
            }
            Err(e) => {
                eprintln!("  Error restoring {}: {}", key.name, e);
                errors += 1;
            }
        }
    }

    println!(
        "Restore complete: {}/{} restored, {} skipped (conflict), {} error(s).",
        restored,
        keys.len(),
        skipped,
        errors
    );
    if errors > 0 {
        1
    } else {
        0
    }
}
