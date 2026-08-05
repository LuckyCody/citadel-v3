// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Key management subcommands.

use crate::CliContext;
use citadel_keystore::{
    graph::KeyGraph,
    storage::{FileBackend, StorageBackend},
    AuditSinkSync, FileAuditSink, IntegrityChainSink, KeyId, KeyType, Keystore, PolicyId,
};
use clap::Subcommand;
use std::sync::Arc;

#[derive(Subcommand, Debug)]
pub enum KeyAction {
    /// Display the key hierarchy as an ASCII tree.
    Graph,

    /// Show detailed metadata for a specific key.
    Inspect {
        /// Key ID (full or prefix).
        id: String,
    },

    /// Generate a new key.
    Generate {
        /// Human-readable name.
        #[arg(long)]
        name: String,

        /// Key type: root, domain, kek, dek, hybrid-id.
        #[arg(long, default_value = "dek")]
        key_type: String,

        /// Parent key ID (required for kek, dek, hybrid-id).
        #[arg(long)]
        parent: Option<String>,

        /// Policy ID to associate.
        #[arg(long)]
        policy: Option<String>,

        /// Activate the key immediately after generation.
        #[arg(long)]
        activate: bool,
    },

    /// Rotate an active key (creates new version, keeps old for decryption).
    Rotate {
        /// Key ID to rotate.
        id: String,
    },

    /// Revoke a key (emergency deactivation).
    Revoke {
        /// Key ID to revoke.
        id: String,

        /// Reason for revocation (required).
        #[arg(long)]
        reason: String,
    },

    /// Destroy a key (purge material — irreversible).
    Destroy {
        /// Key ID to destroy.
        id: String,

        /// Confirm you understand this is irreversible.
        #[arg(long)]
        confirm: bool,
    },

    /// Re-wrap a key under a different parent KEK (after parent rotation).
    Rewrap {
        /// Key ID to rewrap.
        id: String,

        /// New parent KEK ID. Omit to rewrap under the external master key.
        #[arg(long)]
        parent: Option<String>,
    },
}

pub async fn run(ctx: &CliContext, action: KeyAction) -> i32 {
    match action {
        KeyAction::Graph => cmd_graph(ctx).await,
        KeyAction::Inspect { id } => cmd_inspect(ctx, &id).await,
        KeyAction::Generate {
            name,
            key_type,
            parent,
            policy,
            activate,
        } => {
            cmd_generate(
                ctx,
                &name,
                &key_type,
                parent.as_deref(),
                policy.as_deref(),
                activate,
            )
            .await
        }
        KeyAction::Rotate { id } => cmd_rotate(ctx, &id).await,
        KeyAction::Revoke { id, reason } => cmd_revoke(ctx, &id, &reason).await,
        KeyAction::Destroy { id, confirm } => cmd_destroy(ctx, &id, confirm).await,
        KeyAction::Rewrap { id, parent } => cmd_rewrap(ctx, &id, parent.as_deref()).await,
    }
}

// ---------------------------------------------------------------------------
// Keystore factory
// ---------------------------------------------------------------------------

fn open_keystore(ctx: &CliContext) -> Result<Keystore, String> {
    // P100: Removed set_var("CITADEL_ALLOW_PLAINTEXT_KEYS") and set_var("CITADEL_ENV").
    // The CLI must use the same env rules as production:
    //   - CITADEL_MASTER_KEY set → keys are wrapped at rest (production)
    //   - CITADEL_ALLOW_PLAINTEXT_KEYS=1 + CITADEL_ENV=development → dev mode
    //   - Neither → fails closed (Keystore::new enforces this)
    // Operators must set dev mode explicitly outside the process if needed.
    let storage = FileBackend::new(ctx.keys_dir()).map_err(|e| format!("storage: {}", e))?;
    let audit_path = ctx.audit_path();
    let file_sink: Arc<dyn AuditSinkSync> = Arc::new(FileAuditSink::new(&audit_path));
    let audit: Arc<dyn AuditSinkSync> = Arc::new(IntegrityChainSink::new(file_sink));
    Ok(Keystore::new(Arc::new(storage), audit))
}

fn parse_key_type(s: &str) -> Option<KeyType> {
    match s.to_lowercase().as_str() {
        "root" => Some(KeyType::Root),
        "domain" => Some(KeyType::Domain),
        "kek" | "keyencrypting" => Some(KeyType::KeyEncrypting),
        "dek" | "dataencrypting" => Some(KeyType::DataEncrypting),
        "hybrid-id" | "hybrididentity" => Some(KeyType::HybridIdentity),
        "signing" | "sign" => Some(KeyType::Signing),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// graph
// ---------------------------------------------------------------------------

async fn cmd_graph(ctx: &CliContext) -> i32 {
    let storage = match FileBackend::new(ctx.keys_dir()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: cannot open storage: {}", e);
            return 1;
        }
    };

    let keys = match storage.list() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: cannot list keys: {}", e);
            return 1;
        }
    };

    let graph = KeyGraph::build(&keys);

    if ctx.output_json {
        // JSON output: just the flat key list with parent references.
        let json: Vec<serde_json::Value> = keys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "id": k.id.as_str(),
                    "name": k.name,
                    "type": format!("{}", k.key_type),
                    "state": format!("{}", k.state),
                    "version": k.current_version,
                    "parent_id": k.parent_id.as_ref().map(|p| p.as_str()),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );
        return 0;
    }

    println!("Citadel Key Hierarchy");
    println!("{}", "═".repeat(60));
    println!();
    print!("{}", graph.render());
    println!();
    println!("  {}", graph.summary());
    0
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

async fn cmd_inspect(ctx: &CliContext, id_prefix: &str) -> i32 {
    let storage = match FileBackend::new(ctx.keys_dir()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let keys = storage.list().unwrap_or_default();
    let matching: Vec<_> = keys
        .iter()
        .filter(|k| k.id.as_str().starts_with(id_prefix) || k.name == id_prefix)
        .collect();

    if matching.is_empty() {
        eprintln!("Error: no key found matching '{}'", id_prefix);
        return 1;
    }
    if matching.len() > 1 {
        eprintln!(
            "Error: multiple keys match '{}'; be more specific:",
            id_prefix
        );
        for k in &matching {
            eprintln!("  {} ({})", k.id.as_str(), k.name);
        }
        return 1;
    }

    let key = matching[0];
    if ctx.output_json {
        println!("{}", serde_json::to_string_pretty(key).unwrap_or_default());
        return 0;
    }

    println!("Key: {} ({})", key.name, key.id.as_str());
    println!("{}", "─".repeat(60));
    println!("  Type:            {}", key.key_type);
    println!("  Role:            {}", key.role());
    println!("  State:           {}", key.state);
    println!("  Current version: {}", key.current_version);
    println!("  Total versions:  {}", key.versions.len());
    println!("  Usage count:     {}", key.usage_count);
    println!(
        "  Created:         {}",
        key.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(at) = key.activated_at {
        println!("  Activated:       {}", at.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    if let Some(pid) = &key.parent_id {
        println!("  Parent ID:       {}", pid.as_str());
    }
    if let Some(pol) = &key.policy_id {
        println!("  Policy:          {}", pol.as_str());
    }
    println!();
    println!("  Versions:");
    for v in &key.versions {
        let wm = v.effective_wrapping_mode();
        println!(
            "    v{}: {} | wrapping: {}",
            v.version,
            if v.is_destroyed() {
                "DESTROYED"
            } else if v.is_citadel_wrapped() {
                "CitadelWrapped"
            } else if v.is_aes_wrapped() {
                "AES-GCM"
            } else {
                "Plaintext"
            },
            wm.summary()
        );
    }
    0
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

async fn cmd_generate(
    ctx: &CliContext,
    name: &str,
    key_type_str: &str,
    parent: Option<&str>,
    policy: Option<&str>,
    activate: bool,
) -> i32 {
    let kt = match parse_key_type(key_type_str) {
        Some(kt) => kt,
        None => {
            eprintln!(
                "Error: unknown key type '{}'. Valid: root, domain, kek, dek, hybrid-id, signing",
                key_type_str
            );
            return 1;
        }
    };

    let ks = match open_keystore(ctx) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let parent_id = parent.map(KeyId::new);
    let policy_id = policy.map(PolicyId::new);

    let id = match ks.generate(name, kt, policy_id, parent_id).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error generating key: {}", e);
            return 1;
        }
    };

    if activate {
        if let Err(e) = ks.activate(&id).await {
            eprintln!("Error activating key: {}", e);
            return 1;
        }
        println!("Generated and activated key: {}", id.as_str());
    } else {
        println!("Generated key (PENDING): {}", id.as_str());
        println!(
            "Activate with: citadel key generate ... then citadel key inspect {}",
            &id.as_str()[..8]
        );
    }
    0
}

// ---------------------------------------------------------------------------
// rotate
// ---------------------------------------------------------------------------

async fn cmd_rotate(ctx: &CliContext, id: &str) -> i32 {
    let ks = match open_keystore(ctx) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    match ks.rotate(&KeyId::new(id)).await {
        Ok(new_id) => {
            println!(
                "Rotated key {} — now active with new version",
                new_id.as_str()
            );
            0
        }
        Err(e) => {
            eprintln!("Error rotating key: {}", e);
            1
        }
    }
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

async fn cmd_revoke(ctx: &CliContext, id: &str, reason: &str) -> i32 {
    let ks = match open_keystore(ctx) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    match ks.revoke(&KeyId::new(id), reason).await {
        Ok(()) => {
            println!("Revoked key {}", id);
            0
        }
        Err(e) => {
            eprintln!("Error revoking key: {}", e);
            1
        }
    }
}

// ---------------------------------------------------------------------------
// destroy
// ---------------------------------------------------------------------------

async fn cmd_destroy(ctx: &CliContext, id: &str, confirm: bool) -> i32 {
    if !confirm {
        eprintln!(
            "Error: --confirm is required. Key destruction is IRREVERSIBLE.\n\
             Run with --confirm if you are sure."
        );
        return 1;
    }

    let ks = match open_keystore(ctx) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    match ks.destroy(&KeyId::new(id)).await {
        Ok(()) => {
            println!("Destroyed key {} — material purged", id);
            0
        }
        Err(e) => {
            eprintln!("Error destroying key: {}", e);
            1
        }
    }
}

// ─── rewrap ───────────────────────────────────────────────────────────────────

async fn cmd_rewrap(ctx: &CliContext, id: &str, parent: Option<&str>) -> i32 {
    let ks = match open_keystore(ctx) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };

    let new_parent = parent.map(KeyId::new);
    match ks.rewrap(&KeyId::new(id), new_parent.as_ref()).await {
        Ok(()) => {
            match parent {
                Some(p) => println!("Rewrapped {} under parent {}", id, p),
                None => println!("Rewrapped {} under external master key", id),
            }
            0
        }
        Err(e) => {
            eprintln!("Error rewrapping key: {}", e);
            1
        }
    }
}
