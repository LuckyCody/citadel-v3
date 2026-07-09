// SPDX-License-Identifier: AGPL-3.0-or-later
//! Citadel Doctor — deployment health and safety diagnostics.
//!
//! `Keystore::doctor()` runs all checks and returns a `DoctorReport`.
//! The CLI (`citadel doctor`) prints it as a PASS/WARN/FAIL table.

use crate::hierarchy::{validate_wrapping_graph, GraphViolation, ViolationKind};
use crate::policy::KeyPolicy;
use crate::types::KeyMetadata;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Check status
// ---------------------------------------------------------------------------

/// Outcome of a single diagnostic check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Requirement met.
    Pass,
    /// Advisory — not blocking but should be addressed.
    Warn,
    /// Requirement failed — deployment is unsafe or non-functional.
    Fail,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Warn => write!(f, "WARN"),
            CheckStatus::Fail => write!(f, "FAIL"),
        }
    }
}

// ---------------------------------------------------------------------------
// DoctorCheck
// ---------------------------------------------------------------------------

/// One diagnostic check with its result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Short identifier for the check (e.g. "master-key-present").
    pub name: String,
    /// Human-readable description of what was checked.
    pub description: String,
    /// Result.
    pub status: CheckStatus,
    /// Explanation of why this status was assigned.
    pub detail: String,
    /// Recommended action when status is Warn or Fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl DoctorCheck {
    fn pass(name: &str, description: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            status: CheckStatus::Pass,
            detail: detail.into(),
            remediation: None,
        }
    }

    fn warn(
        name: &str,
        description: &str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
            remediation: Some(remediation.into()),
        }
    }

    fn fail(
        name: &str,
        description: &str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            status: CheckStatus::Fail,
            detail: detail.into(),
            remediation: Some(remediation.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// DoctorReport
// ---------------------------------------------------------------------------

/// Aggregated result of all diagnostic checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// `true` if any check has status `Fail`.
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }

    /// `true` if any check has status `Warn`.
    pub fn has_warnings(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Warn)
    }

    /// Count by status.
    pub fn counts(&self) -> (usize, usize, usize) {
        let pass = self
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Pass)
            .count();
        let warn = self
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Warn)
            .count();
        let fail = self
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .count();
        (pass, warn, fail)
    }

    /// Overall exit code: 0 = all pass, 1 = any fail, 2 = warn only.
    pub fn exit_code(&self) -> i32 {
        if self.has_failures() {
            1
        } else if self.has_warnings() {
            2
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Individual check implementations
// ---------------------------------------------------------------------------

/// Check 1: CITADEL_MASTER_KEY is present.
pub fn check_master_key_present(has_master_key: bool) -> DoctorCheck {
    if has_master_key {
        DoctorCheck::pass(
            "master-key-present",
            "CITADEL_MASTER_KEY environment variable is set",
            "Master key loaded successfully",
        )
    } else {
        DoctorCheck::fail(
            "master-key-present",
            "CITADEL_MASTER_KEY environment variable is set",
            "CITADEL_MASTER_KEY is not set",
            "Generate a key: openssl rand -hex 32 → export CITADEL_MASTER_KEY=<hex>",
        )
    }
}

/// Check 2: CITADEL_MASTER_KEY is a valid 64-char hex string.
pub fn check_master_key_valid() -> DoctorCheck {
    match std::env::var("CITADEL_MASTER_KEY") {
        Err(_) => DoctorCheck::fail(
            "master-key-valid",
            "CITADEL_MASTER_KEY decodes to exactly 32 bytes",
            "CITADEL_MASTER_KEY is not set",
            "Set CITADEL_MASTER_KEY to a 64-char hex string",
        ),
        Ok(val) => match hex::decode(val.trim()) {
            Ok(bytes) if bytes.len() == 32 => DoctorCheck::pass(
                "master-key-valid",
                "CITADEL_MASTER_KEY decodes to exactly 32 bytes",
                "Master key is 32 bytes (256 bits)",
            ),
            Ok(bytes) => DoctorCheck::fail(
                "master-key-valid",
                "CITADEL_MASTER_KEY decodes to exactly 32 bytes",
                format!("Decoded to {} bytes, expected 32", bytes.len()),
                "Generate a valid 32-byte key: openssl rand -hex 32",
            ),
            Err(e) => DoctorCheck::fail(
                "master-key-valid",
                "CITADEL_MASTER_KEY decodes to exactly 32 bytes",
                format!("Hex decode failed: {}", e),
                "Ensure CITADEL_MASTER_KEY contains only hex characters (0-9, a-f)",
            ),
        },
    }
}

/// Check 3: Plaintext key mode is disabled outside development.
pub fn check_plaintext_mode_disabled() -> DoctorCheck {
    let plaintext_allowed = std::env::var("CITADEL_ALLOW_PLAINTEXT_KEYS").as_deref() == Ok("1");
    let is_dev = std::env::var("CITADEL_ENV").as_deref() == Ok("development");
    let master_key_set = std::env::var("CITADEL_MASTER_KEY").is_ok();

    if !plaintext_allowed && master_key_set {
        DoctorCheck::pass(
            "plaintext-mode-disabled",
            "Plaintext key storage is disabled",
            "CITADEL_ALLOW_PLAINTEXT_KEYS is not set; CITADEL_MASTER_KEY is present",
        )
    } else if plaintext_allowed && is_dev {
        DoctorCheck::warn(
            "plaintext-mode-disabled",
            "Plaintext key storage is disabled",
            "CITADEL_ALLOW_PLAINTEXT_KEYS=1 with CITADEL_ENV=development: dev mode active",
            "Do not use CITADEL_ALLOW_PLAINTEXT_KEYS=1 in production",
        )
    } else if plaintext_allowed {
        DoctorCheck::fail(
            "plaintext-mode-disabled",
            "Plaintext key storage is disabled",
            "CITADEL_ALLOW_PLAINTEXT_KEYS=1 without CITADEL_ENV=development",
            "Remove CITADEL_ALLOW_PLAINTEXT_KEYS from production environment",
        )
    } else {
        DoctorCheck::fail(
            "plaintext-mode-disabled",
            "Plaintext key storage is disabled",
            "CITADEL_MASTER_KEY is not set; keys would be stored as plaintext",
            "Set CITADEL_MASTER_KEY to a 64-char hex string",
        )
    }
}

/// Check 4: Storage directory permissions are owner-only (0700 on Unix).
pub fn check_storage_permissions(data_dir: &str) -> DoctorCheck {
    // P164: keys_dir is used inside #[cfg(unix)] block; on Windows it is unused.
    #[allow(unused_variables)]
    let keys_dir = format!("{}/keys", data_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(&keys_dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => DoctorCheck::warn(
                "storage-permissions",
                "Key storage directory has owner-only permissions (0700)",
                format!("Directory '{}' does not exist yet", keys_dir),
                "The directory will be created on first key generation",
            ),
            Err(e) => DoctorCheck::fail(
                "storage-permissions",
                "Key storage directory has owner-only permissions (0700)",
                format!("Cannot stat '{}': {}", keys_dir, e),
                "Ensure the data directory is accessible",
            ),
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o700 {
                    DoctorCheck::pass(
                        "storage-permissions",
                        "Key storage directory has owner-only permissions (0700)",
                        format!("'{}' has mode {:04o}", keys_dir, mode),
                    )
                } else {
                    DoctorCheck::fail(
                        "storage-permissions",
                        "Key storage directory has owner-only permissions (0700)",
                        format!("'{}' has mode {:04o} (expected 0700)", keys_dir, mode),
                        format!("Run: chmod 700 '{}'", keys_dir),
                    )
                }
            }
        }
    }

    #[cfg(not(unix))]
    DoctorCheck::warn(
        "storage-permissions",
        "Key storage directory has owner-only permissions (0700)",
        "Permission check not available on non-Unix platform",
        "Verify storage directory access controls manually",
    )
}

/// Check 5: No legacy plaintext keys in storage.
pub fn check_no_plaintext_keys(keys: &[KeyMetadata]) -> DoctorCheck {
    let plaintext: Vec<&str> = keys
        .iter()
        .filter(|k| {
            k.current_key_version()
                .map(|v| v.is_plaintext())
                .unwrap_or(false)
        })
        .map(|k| k.name.as_str())
        .collect();

    if plaintext.is_empty() {
        DoctorCheck::pass(
            "no-plaintext-keys",
            "No keys are stored in plaintext",
            "All keys use AES-GCM or Citadel-envelope wrapping",
        )
    } else {
        DoctorCheck::warn(
            "no-plaintext-keys",
            "No keys are stored in plaintext",
            format!("{} key(s) stored as plaintext: {}", plaintext.len(), plaintext.join(", ")),
            "Run 'citadel key rewrap --all' or rotate each key to re-encrypt under CITADEL_MASTER_KEY",
        )
    }
}

/// Check 6: Wrapping graph has no cycles or invalid directions.
pub fn check_wrapping_graph(keys: &[KeyMetadata]) -> DoctorCheck {
    let violations = validate_wrapping_graph(keys);
    if violations.is_empty() {
        DoctorCheck::pass(
            "wrapping-graph-valid",
            "Key wrapping graph has no cycles or invalid hierarchy directions",
            format!("Graph of {} keys is valid", keys.len()),
        )
    } else {
        let cycles: Vec<&GraphViolation> = violations
            .iter()
            .filter(|v| v.kind == ViolationKind::Cycle)
            .collect();
        let status = if !cycles.is_empty() {
            CheckStatus::Fail
        } else {
            CheckStatus::Warn
        };
        let details: Vec<&str> = violations.iter().map(|v| v.detail.as_str()).collect();
        DoctorCheck {
            name: "wrapping-graph-valid".into(),
            description: "Key wrapping graph has no cycles or invalid hierarchy directions".into(),
            status,
            detail: format!("{} violation(s): {}", violations.len(), details.join("; ")),
            remediation: Some("Run 'citadel migrate hierarchy' to restructure or 'citadel key rewrap' to fix individual keys".into()),
        }
    }
}

/// Check 7: No orphaned child keys (parent exists and is accessible).
pub fn check_no_orphaned_keys(keys: &[KeyMetadata]) -> DoctorCheck {
    use std::collections::HashSet;
    let all_ids: HashSet<&str> = keys.iter().map(|k| k.id.as_str()).collect();
    let orphans: Vec<&str> = keys
        .iter()
        .filter(|k| {
            k.parent_id
                .as_ref()
                .map(|pid| !all_ids.contains(pid.as_str()))
                .unwrap_or(false)
        })
        .map(|k| k.name.as_str())
        .collect();

    if orphans.is_empty() {
        DoctorCheck::pass(
            "no-orphaned-keys",
            "All keys with parent_id references have accessible parents",
            "No orphaned child keys found",
        )
    } else {
        DoctorCheck::warn(
            "no-orphaned-keys",
            "All keys with parent_id references have accessible parents",
            format!(
                "{} key(s) reference missing parents: {}",
                orphans.len(),
                orphans.join(", ")
            ),
            "Run 'citadel key inspect <id>' to examine orphaned keys",
        )
    }
}

/// Check 8: No keys with expired lifetimes (by policy).
pub fn check_no_expired_keys(
    keys: &[KeyMetadata],
    policies: &[(String, KeyPolicy)],
) -> DoctorCheck {
    use crate::policy::evaluate;
    use crate::types::KeyState;
    use std::collections::HashMap;

    let policy_map: HashMap<&str, &KeyPolicy> =
        policies.iter().map(|(id, p)| (id.as_str(), p)).collect();

    let mut overdue: Vec<String> = Vec::new();
    for key in keys {
        if key.state != KeyState::Active {
            continue;
        }
        if let Some(pid) = &key.policy_id {
            if let Some(policy) = policy_map.get(pid.as_str()) {
                let verdict = evaluate(policy, key);
                if verdict.needs_rotation() {
                    overdue.push(format!("{} ({})", key.name, key.id));
                }
            }
        }
    }

    if overdue.is_empty() {
        DoctorCheck::pass(
            "rotation-current",
            "No active keys are overdue for rotation",
            "All active keys are within policy rotation windows",
        )
    } else {
        DoctorCheck::warn(
            "rotation-current",
            "No active keys are overdue for rotation",
            format!(
                "{} key(s) need rotation: {}",
                overdue.len(),
                overdue.join(", ")
            ),
            "Run 'citadel key rotate <id>' for each overdue key, or enable auto_rotate in policy",
        )
    }
}

/// Check 9: No keys in PENDING state for more than 24 hours.
pub fn check_no_stale_pending_keys(keys: &[KeyMetadata]) -> DoctorCheck {
    use crate::types::KeyState;
    let stale: Vec<&str> = keys
        .iter()
        .filter(|k| {
            k.state == KeyState::Pending && {
                let age = chrono::Utc::now() - k.created_at;
                age.num_hours() > 24
            }
        })
        .map(|k| k.name.as_str())
        .collect();

    if stale.is_empty() {
        DoctorCheck::pass(
            "no-stale-pending",
            "No keys have been in PENDING state for more than 24 hours",
            "All pending keys are recently created",
        )
    } else {
        DoctorCheck::warn(
            "no-stale-pending",
            "No keys have been in PENDING state for more than 24 hours",
            format!("{} stale pending key(s): {}", stale.len(), stale.join(", ")),
            "Activate or destroy stale pending keys: 'citadel key activate <id>'",
        )
    }
}

/// Check 10: Hierarchy exists (Root, Domain, and KEK).
///
/// P216: Updated to check for the complete Root→Domain→KEK hierarchy.
/// After P211 strict enforcement, Domain is required — Root→KEK is no longer valid.
pub fn check_hierarchy_exists(keys: &[KeyMetadata]) -> DoctorCheck {
    use crate::types::{KeyState, KeyType};
    let has_active_root = keys
        .iter()
        .any(|k| k.key_type == KeyType::Root && k.state == KeyState::Active);
    let has_active_domain = keys
        .iter()
        .any(|k| k.key_type == KeyType::Domain && k.state == KeyState::Active);
    let has_active_kek = keys
        .iter()
        .any(|k| k.key_type == KeyType::KeyEncrypting && k.state == KeyState::Active);

    if keys.is_empty() {
        return DoctorCheck::warn(
            "hierarchy-exists",
            "Root, Domain, and at least one KEK exist and are active",
            "No keys found — fresh installation",
            "Run 'citadel migrate hierarchy' to initialize the key hierarchy",
        );
    }

    match (has_active_root, has_active_domain, has_active_kek) {
        (true, true, true) => DoctorCheck::pass(
            "hierarchy-exists",
            "Root, Domain, and at least one KEK exist and are active",
            "Root, Domain, and KEK present and active",
        ),
        (false, _, _) => DoctorCheck::warn(
            "hierarchy-exists",
            "Root, Domain, and at least one KEK exist and are active",
            "No active Root key found",
            "Run 'citadel migrate hierarchy' to create the default hierarchy",
        ),
        (true, false, _) => DoctorCheck::warn(
            "hierarchy-exists",
            "Root, Domain, and at least one KEK exist and are active",
            "Root exists but no active Domain found",
            "Run 'citadel key generate --type domain --parent <root-id>' to create Domain key",
        ),
        (true, true, false) => DoctorCheck::warn(
            "hierarchy-exists",
            "Root, Domain, and at least one KEK exist and are active",
            "Root and Domain exist but no active KEK found",
            "Run 'citadel key generate --type kek --parent <domain-id>' to create KEK under Domain",
        ),
    }
}

/// Check 11: Orphaned src/ directory (from pre-V1 codebase) is absent.
pub fn check_no_orphaned_src() -> DoctorCheck {
    let orphan = std::path::Path::new("src");
    if orphan.exists() && orphan.is_dir() {
        DoctorCheck::warn(
            "no-orphaned-src",
            "Orphaned root src/ directory (pre-V1 code with known defects) is absent",
            "Found src/ at workspace root — contains deprecated code with crypto defects",
            "Run: git rm -r src/",
        )
    } else {
        DoctorCheck::pass(
            "no-orphaned-src",
            "Orphaned root src/ directory (pre-V1 code with known defects) is absent",
            "src/ directory not present at workspace root",
        )
    }
}

/// Check 12: Destroyed keys are present (expected, informational).
pub fn check_destroyed_keys_info(keys: &[KeyMetadata]) -> DoctorCheck {
    use crate::types::KeyState;
    let destroyed: Vec<&str> = keys
        .iter()
        .filter(|k| k.state == KeyState::Destroyed)
        .map(|k| k.name.as_str())
        .collect();

    if destroyed.is_empty() {
        DoctorCheck::pass(
            "destroyed-keys-info",
            "Destroyed key count (informational)",
            "No destroyed keys on record",
        )
    } else {
        DoctorCheck::pass(
            "destroyed-keys-info",
            "Destroyed key count (informational)",
            format!(
                "{} destroyed key record(s) present (expected — audit trail)",
                destroyed.len()
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// P068 — Active children under revoked parent
// ---------------------------------------------------------------------------

/// Check that no Active or Rotated key has an ancestor in Revoked state.
///
/// P068: After revoke_cascade() is called, children should be Suspended.
/// If any Active/Rotated key still has a Revoked ancestor in its parent chain,
/// the deployment is in a split state — decrypt-time enforcement will block
/// those keys anyway, but operators need visibility.
pub fn check_no_active_children_under_revoked(keys: &[KeyMetadata]) -> DoctorCheck {
    use crate::types::KeyState;
    use std::collections::HashMap;

    // Build a lookup of id → state for parent chain traversal.
    let by_id: HashMap<&str, &KeyMetadata> = keys.iter().map(|k| (k.id.as_str(), k)).collect();

    let mut violations: Vec<String> = Vec::new();

    for key in keys {
        if !matches!(key.state, KeyState::Active | KeyState::Rotated) {
            continue;
        }
        // Walk the parent chain.
        let mut current_id = key.parent_id.as_ref().map(|id| id.as_str().to_string());
        let mut depth = 0u8;
        while let Some(pid) = current_id {
            depth += 1;
            if depth > 6 {
                break; // Guard against circular chains
            }
            if let Some(parent) = by_id.get(pid.as_str()) {
                if matches!(parent.state, KeyState::Revoked | KeyState::Destroyed) {
                    violations.push(format!(
                        "'{}' ({}) is Active/Rotated but ancestor '{}' is {}",
                        key.name, key.id, parent.name, parent.state
                    ));
                    break;
                }
                current_id = parent.parent_id.as_ref().map(|id| id.as_str().to_string());
            } else {
                break;
            }
        }
    }

    if violations.is_empty() {
        DoctorCheck::pass(
            "no-active-children-under-revoked",
            "Active keys under revoked ancestor (P064)",
            "No Active/Rotated keys have a Revoked/Destroyed ancestor",
        )
    } else {
        DoctorCheck::fail(
            "no-active-children-under-revoked",
            "Active keys under revoked ancestor (P064)",
            format!(
                "{} key(s) are Active/Rotated but have a Revoked/Destroyed ancestor: {}",
                violations.len(),
                violations.join("; ")
            ),
            "Run `revoke_cascade()` on the revoked parent to Suspend all descendants, \
             then `rewrap()` + `activate()` each under a healthy parent.",
        )
    }
}

/// Verify replay store is not memory-only in production.
///
/// P085: Checks the actual runtime backend name (from `Keystore::replay_backend_name()`)
/// rather than an environment variable hint. This prevents false-pass if the API
/// startup code failed to install the requested backend.
pub fn check_replay_store_backend(actual_backend: &str) -> DoctorCheck {
    match actual_backend {
        "redis" => DoctorCheck::pass(
            "replay-store-type",
            "Replay store backend (P066/P085)",
            "RedisReplayStore active — distributed, restart-safe, fail-closed",
        ),
        "file" => DoctorCheck::pass(
            "replay-store-type",
            "Replay store backend (P066/P085)",
            "FileReplayStore active — single-instance, restart-safe",
        ),
        _ => DoctorCheck::warn(
            "replay-store-type",
            "Replay store backend (P066/P085)",
            format!(
                "MemoryReplayStore is active (backend='{}') — not restart-safe, \
                 not distributed across instances. Replay events from before a restart \
                 or from other instances will NOT be caught.",
                actual_backend
            ),
            "Set CITADEL_REPLAY_STORE=file (single node) or =redis (multi-node) \
             and restart the server. MemoryReplayStore is acceptable for development only.",
        ),
    }
}

// ---------------------------------------------------------------------------
// Run all checks
// ---------------------------------------------------------------------------

/// Run all diagnostic checks and return a full report.
pub fn run_all_checks(
    data_dir: &str,
    has_master_key: bool,
    keys: &[KeyMetadata],
    policies: &[(String, crate::policy::KeyPolicy)],
    actual_replay_backend: &str,
) -> DoctorReport {
    let checks = vec![
        check_master_key_present(has_master_key),
        check_master_key_valid(),
        check_plaintext_mode_disabled(),
        check_storage_permissions(data_dir),
        check_no_plaintext_keys(keys),
        check_wrapping_graph(keys),
        check_no_orphaned_keys(keys),
        check_no_expired_keys(keys, policies),
        check_no_stale_pending_keys(keys),
        check_hierarchy_exists(keys),
        check_no_orphaned_src(),
        check_destroyed_keys_info(keys),
        // P068 new checks:
        check_no_active_children_under_revoked(keys),
        check_replay_store_backend(actual_replay_backend),
    ];
    DoctorReport { checks }
}
