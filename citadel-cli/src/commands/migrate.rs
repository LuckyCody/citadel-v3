// SPDX-License-Identifier: AGPL-3.0-or-later
//! `citadel migrate hierarchy` subcommand.

use crate::CliContext;
use citadel_keystore::{
    migration::{plan_migration, MigrationOptions},
    storage::{FileBackend, StorageBackend},
    AuditSinkSync, FileAuditSink, IntegrityChainSink, KeyId, KeyState, KeyType, Keystore,
};
use clap::Subcommand;
use std::sync::Arc;

#[derive(Subcommand, Debug)]
pub enum MigrateAction {
    /// Upgrade keys to V3 hierarchy (Root→Domain→KEK→DEK).
    Hierarchy {
        /// Show what would be done without making changes.
        #[arg(long)]
        dry_run: bool,

        /// Execute the migration (required unless --dry-run).
        #[arg(long)]
        execute: bool,

        /// Name for the Root key.
        #[arg(long, default_value = "default-root")]
        root_name: String,

        /// Name for the Domain KEK.
        #[arg(long, default_value = "default-domain")]
        domain_name: String,

        /// Name for the Project KEK.
        #[arg(long, default_value = "default-kek")]
        kek_name: String,
    },
}

pub async fn run(ctx: &CliContext, action: MigrateAction) -> i32 {
    match action {
        MigrateAction::Hierarchy {
            dry_run,
            execute,
            root_name,
            domain_name,
            kek_name,
        } => cmd_hierarchy(ctx, dry_run, execute, &root_name, &domain_name, &kek_name).await,
    }
}

async fn cmd_hierarchy(
    ctx: &CliContext,
    dry_run: bool,
    execute: bool,
    root_name: &str,
    domain_name: &str,
    kek_name: &str,
) -> i32 {
    if !dry_run && !execute {
        eprintln!("Error: specify --dry-run to preview or --execute to apply changes.");
        return 1;
    }

    let storage = match FileBackend::new(ctx.keys_dir()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let keys = storage.list().unwrap_or_default();
    let opts = MigrationOptions {
        root_name: root_name.into(),
        domain_name: domain_name.into(),
        kek_name: kek_name.into(),
        skip_already_wrapped: true,
        skip_destroyed: true,
    };

    let plan = plan_migration(&keys, &opts);

    if ctx.output_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan).unwrap_or_default()
        );
    } else {
        println!("Migration Plan");
        println!("{}", "═".repeat(60));
        println!();
        println!("  Keys to create ({}):", plan.keys_to_create.len());
        for k in &plan.keys_to_create {
            let parent_str = k.parent_name.as_deref().unwrap_or("(none)");
            println!("    + {} [{}] (parent: {})", k.name, k.key_type, parent_str);
            println!("      Reason: {}", k.reason);
        }
        println!();
        println!("  Keys to rewrap ({}):", plan.keys_to_rewrap.len());
        for k in &plan.keys_to_rewrap {
            println!(
                "    ~ {} — {} → under {}",
                k.key_name, k.current_wrapping, k.target_parent_name
            );
        }
        println!();
        println!("  Keys skipped ({}):", plan.keys_skipped.len());
        for k in &plan.keys_skipped {
            println!("    - {} ({})", k.key_name, k.reason);
        }
        println!();
        println!("  {}", plan.summary());
    }

    if dry_run {
        println!();
        println!("  Dry run — no changes made. Run with --execute to apply.");
        return 0;
    }

    if plan.is_empty() {
        println!("  Nothing to do.");
        return 0;
    }

    // Execute: create hierarchy keys, then rewrap DEKs.
    // P082: removed set_var("CITADEL_ALLOW_PLAINTEXT_KEYS") and set_var("CITADEL_ENV")
    // Production migration requires CITADEL_MASTER_KEY — validated by Keystore::new().

    let audit_path = ctx.audit_path();
    let file_sink: Arc<dyn AuditSinkSync> = Arc::new(FileAuditSink::new(&audit_path));
    let audit: Arc<dyn AuditSinkSync> = Arc::new(IntegrityChainSink::new(file_sink));
    let ks = Keystore::new(Arc::new(storage), audit);

    let mut created_ids: std::collections::HashMap<String, KeyId> =
        std::collections::HashMap::new();
    let mut errors = 0usize;

    // P092 — Pre-populate created_ids from existing storage so that pre-existing
    // Root/Domain/KEK are correctly found as parents for newly-created children.
    // Without this, Domain created when Root already exists gets parent_id=None.
    let all_existing = ks.list_keys().await.unwrap_or_default();
    for (target_name, target_type) in &[
        (root_name, KeyType::Root),
        (domain_name, KeyType::Domain),
        (kek_name, KeyType::KeyEncrypting),
    ] {
        if let Some(existing) = all_existing.iter().find(|k| {
            k.name.as_str() == *target_name
                && k.key_type == *target_type
                && k.state == KeyState::Active
        }) {
            println!(
                "  Resolved existing {}: {} ({})",
                target_type,
                target_name,
                existing.id.as_str()
            );
            created_ids.insert(target_name.to_string(), existing.id.clone());
        }
    }

    for key_spec in &plan.keys_to_create {
        let kt = match key_spec.key_type.as_str() {
            "Root" => KeyType::Root,
            "Domain" => KeyType::Domain,
            "KeyEncrypting" => KeyType::KeyEncrypting,
            _ => KeyType::DataEncrypting,
        };
        let parent = key_spec
            .parent_name
            .as_ref()
            .and_then(|pname| created_ids.get(pname))
            .cloned();

        match ks.generate(&key_spec.name, kt, None, parent).await {
            Ok(id) => {
                if let Err(e) = ks.activate(&id).await {
                    eprintln!("  Error activating {}: {}", key_spec.name, e);
                    errors += 1;
                } else {
                    println!(
                        "  Created and activated: {} ({})",
                        key_spec.name,
                        id.as_str()
                    );
                    created_ids.insert(key_spec.name.clone(), id);
                }
            }
            Err(e) => {
                eprintln!("  Error creating {}: {}", key_spec.name, e);
                errors += 1;
            }
        }
    }

    // P081: actually call ks.rewrap() — replace the manual note with real execution.
    let kek_id = created_ids.get(kek_name).cloned();
    for rewrap_spec in &plan.keys_to_rewrap {
        match &kek_id {
            Some(ref kek) => {
                let target_id = KeyId::new(&rewrap_spec.key_id);
                match ks.rewrap(&target_id, Some(kek)).await {
                    Ok(()) => {
                        println!(
                            "  Rewrapped '{}' ({}) under new KEK",
                            rewrap_spec.key_name,
                            &rewrap_spec.key_id[..8.min(rewrap_spec.key_id.len())]
                        );
                    }
                    Err(e) => {
                        eprintln!("  Error rewrapping '{}': {}", rewrap_spec.key_name, e);
                        errors += 1;
                    }
                }
            }
            None => {
                eprintln!(
                    "  Error: KEK '{}' not created, cannot rewrap {}",
                    kek_name, rewrap_spec.key_name
                );
                errors += 1;
            }
        }
    }

    if errors > 0 {
        eprintln!("Migration completed with {} error(s).", errors);
        1
    } else {
        println!("Migration complete.");
        0
    }
}
