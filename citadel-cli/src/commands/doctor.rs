// SPDX-License-Identifier: AGPL-3.0-or-later
//! `citadel doctor` — deployment health and safety diagnostics.

use crate::CliContext;
use citadel_keystore::{
    doctor::{run_all_checks, CheckStatus},
    storage::{FileBackend, StorageBackend},
};

pub async fn run(ctx: &CliContext) -> i32 {
    let has_master_key = std::env::var("CITADEL_MASTER_KEY").is_ok();
    let data_dir_str = ctx.data_dir.to_string_lossy().to_string();

    // Load keys from disk (best-effort — if storage fails, still run other checks).
    let keys = match FileBackend::new(ctx.keys_dir()) {
        Ok(storage) => storage.list().unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // Gather policies from a temporary keystore (reads env).
    let policies: Vec<(String, citadel_keystore::KeyPolicy)> = vec![
        (
            "default-dek".into(),
            citadel_keystore::KeyPolicy::default_dek(),
        ),
        (
            "default-kek".into(),
            citadel_keystore::KeyPolicy::default_kek(),
        ),
    ];

    let report = run_all_checks(
        &data_dir_str,
        has_master_key,
        &keys,
        &policies,
        // P113: CLI doctor reads env to infer replay backend — it is NOT querying a live API.
        // This reflects the CITADEL_REPLAY_STORE value in the current shell environment.
        // To verify a running API server's actual backend, check its startup log or
        // use: curl http://localhost:8443/api/status | jq .replay_backend
        &std::env::var("CITADEL_REPLAY_STORE").unwrap_or_else(|_| "memory".into()),
    );

    if ctx.output_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return report.exit_code();
    }

    // Text output.
    println!("Citadel Doctor — Configuration Check");
    println!("{}", "═".repeat(60));
    println!("Scope: environment configuration only.");
    println!("       This is NOT live API runtime verification.");
    println!("       For end-to-end proof: ./scripts/smoke-test.sh");
    println!("{}", "─".repeat(60));
    println!("NOTE: replay-store-type check reflects CITADEL_REPLAY_STORE env var in this");
    println!("      shell, not the live API server backend. Check API startup log to verify.");
    println!();

    for check in &report.checks {
        let icon = match check.status {
            CheckStatus::Pass => "✓",
            CheckStatus::Warn => "⚠",
            CheckStatus::Fail => "✗",
        };
        let color_code = match check.status {
            CheckStatus::Pass => "\x1b[32m", // green
            CheckStatus::Warn => "\x1b[33m", // yellow
            CheckStatus::Fail => "\x1b[31m", // red
        };
        let reset = "\x1b[0m";

        println!(
            "  {}{}  {}{} — {}",
            color_code, icon, check.status, reset, check.description
        );
        if check.status != CheckStatus::Pass {
            println!("       Detail: {}", check.detail);
            if let Some(ref rem) = check.remediation {
                println!("       Fix:    {}", rem);
            }
        }
    }

    println!();
    let (pass, warn, fail) = report.counts();
    println!("  {}", "─".repeat(58));
    println!("  Result: {} pass  {} warn  {} fail", pass, warn, fail);
    println!();

    if report.has_failures() {
        eprintln!("FAIL: one or more critical checks failed.");
    } else if report.has_warnings() {
        eprintln!("WARN: deployment has advisories. Review above.");
    } else {
        eprintln!("PASS: all checks passed.");
    }

    report.exit_code()
}
