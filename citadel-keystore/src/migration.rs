// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hierarchy migration — upgrade flat master-key-wrapped keys to a proper
//! Root → DomainKek → Kek → Dek hierarchy.

use crate::types::{KeyState, KeyType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Migration options
// ---------------------------------------------------------------------------

/// Options for planning and executing a hierarchy migration.
#[derive(Clone, Debug)]
pub struct MigrationOptions {
    /// Name for the Root key to create (or use if it already exists).
    pub root_name: String,
    /// Name for the Domain KEK to create.
    pub domain_name: String,
    /// Name for the Project KEK to create.
    pub kek_name: String,
    /// Whether to skip keys that are already wrapped by a KEK.
    pub skip_already_wrapped: bool,
    /// Whether to skip destroyed keys.
    pub skip_destroyed: bool,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            root_name: "default-root".into(),
            domain_name: "default-domain".into(),
            kek_name: "default-kek".into(),
            skip_already_wrapped: true,
            skip_destroyed: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Migration plan
// ---------------------------------------------------------------------------

/// What the migration will do (dry-run output).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Keys to be created (Root, Domain, KEK if not present).
    pub keys_to_create: Vec<KeyToCreate>,
    /// Existing DEKs to be rewrapped under the new KEK.
    pub keys_to_rewrap: Vec<KeyToRewrap>,
    /// Keys skipped and why.
    pub keys_skipped: Vec<KeySkipped>,
    /// When the plan was generated.
    pub generated_at: DateTime<Utc>,
}

/// A key that will be created as part of the migration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyToCreate {
    pub name: String,
    pub key_type: String,
    pub parent_name: Option<String>,
    pub reason: String,
}

/// An existing DEK that will be rewrapped under the new hierarchy KEK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyToRewrap {
    pub key_id: String,
    pub key_name: String,
    pub current_wrapping: String,
    pub target_parent_name: String,
}

/// A key that was skipped during migration planning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySkipped {
    pub key_id: String,
    pub key_name: String,
    pub reason: String,
}

impl MigrationPlan {
    /// Returns `true` if this plan would make no changes.
    pub fn is_empty(&self) -> bool {
        self.keys_to_create.is_empty() && self.keys_to_rewrap.is_empty()
    }

    /// Human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Migration plan: {} key(s) to create, {} key(s) to rewrap, {} key(s) skipped",
            self.keys_to_create.len(),
            self.keys_to_rewrap.len(),
            self.keys_skipped.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Migration report
// ---------------------------------------------------------------------------

/// Result of executing a migration plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationReport {
    pub keys_created: Vec<String>,
    pub keys_rewrapped: Vec<String>,
    pub keys_failed: Vec<(String, String)>,
    pub completed_at: DateTime<Utc>,
}

impl MigrationReport {
    pub fn summary(&self) -> String {
        format!(
            "Migration complete: {} created, {} rewrapped, {} failed",
            self.keys_created.len(),
            self.keys_rewrapped.len(),
            self.keys_failed.len()
        )
    }

    pub fn has_failures(&self) -> bool {
        !self.keys_failed.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Plan builder (pure, no side effects)
// ---------------------------------------------------------------------------

/// Build a migration plan from the current set of keys.
///
/// Does NOT perform any changes — callers execute the plan separately.
pub fn plan_migration(
    keys: &[crate::types::KeyMetadata],
    opts: &MigrationOptions,
) -> MigrationPlan {
    let mut keys_to_create = Vec::new();
    let mut keys_to_rewrap = Vec::new();
    let mut keys_skipped = Vec::new();

    // Check if the specific named Root already exists.
    let has_root = keys.iter().any(|k| {
        k.key_type == KeyType::Root && k.state == KeyState::Active && k.name == opts.root_name
    });

    // Check if the specific named Domain KEK already exists.
    let has_domain = keys.iter().any(|k| {
        k.key_type == KeyType::Domain && k.state == KeyState::Active && k.name == opts.domain_name
    });

    // Check if the specific named project KEK already exists.
    let has_kek = keys.iter().any(|k| {
        k.key_type == KeyType::KeyEncrypting
            && k.state == KeyState::Active
            && k.name == opts.kek_name
    });

    // Determine what needs to be created.
    if !has_root {
        keys_to_create.push(KeyToCreate {
            name: opts.root_name.clone(),
            key_type: "Root".into(),
            parent_name: None,
            reason: "No active Root key exists".into(),
        });
    }

    if !has_domain {
        keys_to_create.push(KeyToCreate {
            name: opts.domain_name.clone(),
            key_type: "Domain".into(),
            parent_name: Some(opts.root_name.clone()),
            reason: "No active Domain KEK exists".into(),
        });
    }

    if !has_kek {
        keys_to_create.push(KeyToCreate {
            name: opts.kek_name.clone(),
            key_type: "KeyEncrypting".into(),
            parent_name: Some(opts.domain_name.clone()),
            reason: "No active KEK exists for DEK wrapping".into(),
        });
    }

    // Plan rewrapping of DEKs that are currently master-key-wrapped.
    for key in keys {
        if opts.skip_destroyed && key.state == KeyState::Destroyed {
            keys_skipped.push(KeySkipped {
                key_id: key.id.as_str().to_string(),
                key_name: key.name.clone(),
                reason: "Destroyed — no key material to rewrap".into(),
            });
            continue;
        }

        // Only rewrap DataEncrypting keys.
        if key.key_type != KeyType::DataEncrypting {
            keys_skipped.push(KeySkipped {
                key_id: key.id.as_str().to_string(),
                key_name: key.name.clone(),
                reason: format!("Not a DEK (type: {})", key.key_type),
            });
            continue;
        }

        // Check current wrapping.
        let current_wrapping = key
            .current_key_version()
            .map(|kv| kv.effective_wrapping_mode().summary())
            .unwrap_or_else(|| "unknown".into());

        let is_already_wrapped_by_kek = key
            .current_key_version()
            .and_then(|kv| kv.wrapping_key_id.as_deref())
            .is_some();

        if opts.skip_already_wrapped && is_already_wrapped_by_kek {
            keys_skipped.push(KeySkipped {
                key_id: key.id.as_str().to_string(),
                key_name: key.name.clone(),
                reason: format!("Already wrapped by KEK ({})", current_wrapping),
            });
            continue;
        }

        if !matches!(key.state, KeyState::Active | KeyState::Rotated) {
            keys_skipped.push(KeySkipped {
                key_id: key.id.as_str().to_string(),
                key_name: key.name.clone(),
                reason: format!("State {} — not rewrapping inactive key", key.state),
            });
            continue;
        }

        keys_to_rewrap.push(KeyToRewrap {
            key_id: key.id.as_str().to_string(),
            key_name: key.name.clone(),
            current_wrapping,
            target_parent_name: opts.kek_name.clone(),
        });
    }

    MigrationPlan {
        keys_to_create,
        keys_to_rewrap,
        keys_skipped,
        generated_at: Utc::now(),
    }
}
