// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! `citadel audit` subcommands.

use crate::CliContext;
use clap::Subcommand;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader};

#[derive(Subcommand, Debug)]
pub enum AuditAction {
    /// Export audit log as JSONL or pretty JSON.
    Export {
        /// Output file (default: stdout).
        #[arg(long)]
        output: Option<std::path::PathBuf>,

        /// Format: jsonl (one event per line) or json (array).
        #[arg(long, default_value = "jsonl")]
        format: String,

        /// Maximum number of events to export.
        #[arg(long)]
        limit: Option<usize>,
    },

    /// Verify the SHA-256 integrity chain in the audit log.
    VerifyChain,
}

pub async fn run(ctx: &CliContext, action: AuditAction) -> i32 {
    match action {
        AuditAction::Export {
            output,
            format,
            limit,
        } => cmd_export(ctx, output.as_deref(), &format, limit).await,
        AuditAction::VerifyChain => cmd_verify_chain(ctx).await,
    }
}

async fn cmd_export(
    ctx: &CliContext,
    output: Option<&std::path::Path>,
    format: &str,
    limit: Option<usize>,
) -> i32 {
    let audit_path = ctx.audit_path();
    if !audit_path.exists() {
        eprintln!("Error: audit log not found at {:?}", audit_path);
        return 1;
    }

    let file = match std::fs::File::open(&audit_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening audit log: {}", e);
            return 1;
        }
    };

    let reader = BufReader::new(file);
    let mut lines: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect();

    if let Some(n) = limit {
        lines.truncate(n);
    }

    let formatted = match format {
        "jsonl" => lines.join("\n"),
        "json" => {
            let events: Vec<serde_json::Value> = lines
                .iter()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            serde_json::to_string_pretty(&events).unwrap_or_default()
        }
        _ => {
            eprintln!("Error: unknown format '{}' — use 'jsonl' or 'json'", format);
            return 1;
        }
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &formatted) {
                eprintln!("Error writing output: {}", e);
                return 1;
            }
            println!("Exported {} event(s) to {:?}", lines.len(), path);
        }
        None => {
            println!("{}", formatted);
        }
    }
    0
}

async fn cmd_verify_chain(ctx: &CliContext) -> i32 {
    let audit_path = ctx.audit_path();
    if !audit_path.exists() {
        eprintln!("Error: audit log not found at {:?}", audit_path);
        return 1;
    }

    let file = match std::fs::File::open(&audit_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening audit log: {}", e);
            return 1;
        }
    };

    let reader = BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect();

    if lines.is_empty() {
        println!("Audit log is empty — nothing to verify.");
        return 0;
    }

    // Genesis hash: SHA-256("citadel-audit-genesis")
    let genesis = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));
    let mut expected_prev = genesis.clone();
    let mut verified = 0usize;
    let mut broken_at: Option<usize> = None;

    for (i, line) in lines.iter().enumerate() {
        let event: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("  Line {}: invalid JSON", i + 1);
                broken_at = Some(i);
                break;
            }
        };

        let seq = event.get("sequence").and_then(|v| v.as_u64());
        let prev_hash = event
            .get("prev_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if seq.is_none() || prev_hash.is_empty() {
            // Events without chain fields (produced before IntegrityChainSink was active).
            verified += 1;
            continue;
        }

        if prev_hash != expected_prev {
            eprintln!(
                "  Chain broken at event {} (seq {:?}): expected prev_hash {}, got {}",
                i + 1,
                seq,
                &expected_prev[..8],
                &prev_hash[..8.min(prev_hash.len())]
            );
            broken_at = Some(i);
            break;
        }

        // Compute this event's hash for the next link.
        expected_prev = format!("{:x}", Sha256::digest(line.as_bytes()));
        verified += 1;
    }

    if let Some(break_pos) = broken_at {
        eprintln!(
            "Chain integrity FAILED at event {}. {} event(s) verified before break.",
            break_pos + 1,
            verified
        );
        1
    } else {
        println!(
            "Chain intact — {} event(s) verified. Last hash: {}...",
            verified,
            &expected_prev[..16]
        );
        0
    }
}
