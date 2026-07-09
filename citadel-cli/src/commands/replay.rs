// SPDX-License-Identifier: AGPL-3.0-or-later
//! `citadel replay` subcommands.

use crate::CliContext;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum ReplayAction {
    /// Show replay cache configuration and status.
    Status,
}

pub async fn run(ctx: &CliContext, action: ReplayAction) -> i32 {
    match action {
        ReplayAction::Status => cmd_status(ctx).await,
    }
}

async fn cmd_status(ctx: &CliContext) -> i32 {
    // P099 — Read CITADEL_REPLAY_STORE (canonical name matching the API).
    // Support CITADEL_REPLAY_BACKEND as a deprecated alias with a warning.
    let backend = match std::env::var("CITADEL_REPLAY_STORE") {
        Ok(v) => v,
        Err(_) => {
            // Deprecated alias — warn and use value if present.
            if let Ok(legacy) = std::env::var("CITADEL_REPLAY_BACKEND") {
                eprintln!(
                    "WARN: CITADEL_REPLAY_BACKEND is deprecated. \
                     Use CITADEL_REPLAY_STORE={} instead.",
                    legacy
                );
                legacy
            } else {
                "memory".into()
            }
        }
    };

    let redis_url = std::env::var("CITADEL_REDIS_URL").ok();
    let fail_closed = std::env::var("CITADEL_REPLAY_FAIL_CLOSED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);

    if ctx.output_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "backend": backend,
                "redis_url": redis_url,
                "fail_closed": fail_closed,
            }))
            .unwrap_or_default()
        );
        return 0;
    }

    println!("Replay Store Status");
    println!("{}", "═".repeat(40));
    println!("  Backend:     {}", backend);
    match backend.as_str() {
        "redis" => match &redis_url {
            Some(url) => println!("  Redis URL:   {}", url),
            None => {
                println!("  Redis URL:   (not set — CITADEL_REDIS_URL required)");
                eprintln!("WARN: CITADEL_REPLAY_STORE=redis but CITADEL_REDIS_URL is not set");
                return 1;
            }
        },
        "file" => {
            let replay_path = ctx.data_dir.join("replay.json");
            println!("  Cache file:  {:?}", replay_path);
            if replay_path.exists() {
                let size = std::fs::metadata(&replay_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                println!("  File size:   {} bytes", size);
            } else {
                println!("  File size:   (not yet created)");
            }
        }
        _ => {
            println!("  Note:        In-memory — not persistent across restarts");
        }
    }
    println!(
        "  Fail closed: {}",
        if fail_closed {
            "yes (production safe)"
        } else {
            "no (development only)"
        }
    );
    0
}
