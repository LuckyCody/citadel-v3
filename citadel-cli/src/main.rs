// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Citadel CLI — key management, diagnostics, migration, and backup.
//!
//! # Commands
//!
//! ```text
//! citadel doctor                     — deployment health check
//! citadel key graph                  — display hierarchy tree
//! citadel key generate               — create a new key
//! citadel key inspect <id>           — show key details
//! citadel key rotate <id>            — rotate a key
//! citadel key revoke <id>            — revoke a key
//! citadel key destroy <id>           — destroy a key
//! citadel migrate hierarchy          — upgrade to V3 hierarchy
//! citadel audit export               — export audit log
//! citadel audit verify-chain         — verify audit hash chain
//! citadel backup create <path>       — create encrypted backup
//! citadel backup verify <path>       — verify backup integrity
//! citadel backup restore <path>      — restore from backup
//! citadel replay status              — show replay cache status
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
use commands::{audit, backup, doctor, key, migrate, replay};

// ---------------------------------------------------------------------------
// Global CLI args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "citadel",
    version,
    about = "Citadel post-quantum key management — V3",
    long_about = "Citadel V3 CLI for managing post-quantum hybrid encryption keys.\n\n\
                  Run 'citadel doctor' first to verify your deployment is correctly configured."
)]
struct Cli {
    /// Citadel data directory (default: ./citadel-data or CITADEL_DATA_DIR).
    #[arg(
        long,
        env = "CITADEL_DATA_DIR",
        default_value = "./citadel-data",
        global = true
    )]
    data_dir: PathBuf,

    /// Output format: text (default) or json.
    #[arg(long, default_value = "text", global = true)]
    output: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run deployment health checks. Exits 0=all pass, 1=failure, 2=warnings.
    Doctor,

    /// Key management subcommands.
    Key {
        #[command(subcommand)]
        action: key::KeyAction,
    },

    /// Hierarchy migration.
    Migrate {
        #[command(subcommand)]
        action: migrate::MigrateAction,
    },

    /// Audit log operations.
    Audit {
        #[command(subcommand)]
        action: audit::AuditAction,
    },

    /// Backup and restore operations.
    Backup {
        #[command(subcommand)]
        action: backup::BackupAction,
    },

    /// Replay cache status.
    Replay {
        #[command(subcommand)]
        action: replay::ReplayAction,
    },
}

// ---------------------------------------------------------------------------
// Context passed to all command handlers
// ---------------------------------------------------------------------------

pub struct CliContext {
    pub data_dir: PathBuf,
    pub output_json: bool,
}

impl CliContext {
    fn new(data_dir: PathBuf, output: &str) -> Self {
        Self {
            data_dir,
            output_json: output == "json",
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.data_dir.join("keys")
    }

    pub fn audit_path(&self) -> PathBuf {
        self.data_dir.join("citadel-audit.jsonl")
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Initialize tracing (stderr only — stdout is for command output).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "citadel=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let ctx = CliContext::new(cli.data_dir, &cli.output);

    let exit_code = match cli.command {
        Commands::Doctor => doctor::run(&ctx).await,
        Commands::Key { action } => key::run(&ctx, action).await,
        Commands::Migrate { action } => migrate::run(&ctx, action).await,
        Commands::Audit { action } => audit::run(&ctx, action).await,
        Commands::Backup { action } => backup::run(&ctx, action).await,
        Commands::Replay { action } => replay::run(&ctx, action).await,
    };

    std::process::exit(exit_code);
}
