// SPDX-License-Identifier: AGPL-3.0-or-later
//! Formal key hierarchy: roles, wrapping modes, graph validation.
//!
//! V3 introduces type-safe representations of:
//! - `KeyRole` — position in the four-level hierarchy
//! - `WrappingMode` — how a key's secret material is protected
//! - `WrapAlgorithm` — the cryptographic algorithm used for wrapping
//! - `validate_wrapping_graph()` — enforces direction + detects cycles

use crate::types::{KeyMetadata, KeyType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// KeyRole
// ---------------------------------------------------------------------------

/// Formal role of a key in the cryptographic hierarchy.
///
/// Maps to `KeyType` but carries stronger semantics about hierarchy position
/// and what each key is permitted to do.
///
/// Valid wrapping chain:
/// ```text
/// Root → DomainKek → Kek → Dek
///                         └── HybridIdentityKey
///                         └── SigningKey
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyRole {
    /// Offline root — wraps DomainKeks. Wrapped only by ExternalMaster or HSM.
    Root = 1,
    /// Domain/tenant KEK — wraps project KEKs. Wrapped by Root.
    DomainKek = 2,
    /// Project/application KEK — wraps DEKs and identity keys. Wrapped by DomainKek.
    Kek = 3,
    /// Data-encrypting key — encrypts user data. Wrapped by Kek.
    Dek = 4,
    /// Hybrid identity key — used for authenticated key exchange. Wrapped by Kek.
    HybridIdentityKey = 5,
    /// Signing key — P361. Holds ML-DSA-65 (NIST FIPS 204) keypair seed.
    /// Wrapped by Kek. Cannot be a parent of any other key.
    SigningKey = 6,
}

impl KeyRole {
    /// Numeric depth in the hierarchy (Root = 1, DomainKek = 2, ...).
    pub fn depth(self) -> u32 {
        self as u32
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            KeyRole::Root => "Root",
            KeyRole::DomainKek => "DomainKek",
            KeyRole::Kek => "Kek",
            KeyRole::Dek => "Dek",
            KeyRole::HybridIdentityKey => "HybridIdentityKey",
            KeyRole::SigningKey => "SigningKey",
        }
    }

    /// Returns `true` if this role can be the parent of `child`.
    ///
    /// Valid parent-child pairings:
    /// - Root → DomainKek
    /// - DomainKek → Kek
    /// - Kek → Dek, HybridIdentityKey, SigningKey
    pub fn can_wrap(self, child: KeyRole) -> bool {
        matches!(
            (self, child),
            (KeyRole::Root, KeyRole::DomainKek)
                | (KeyRole::DomainKek, KeyRole::Kek)
                | (KeyRole::Kek, KeyRole::Dek)
                | (KeyRole::Kek, KeyRole::HybridIdentityKey)
                | (KeyRole::Kek, KeyRole::SigningKey)
        )
    }

    /// Whether this role can be wrapped by `ExternalMaster` (CITADEL_MASTER_KEY).
    /// Only Root and DomainKek may be wrapped by the external master.
    pub fn allow_external_master(self) -> bool {
        matches!(self, KeyRole::Root | KeyRole::DomainKek)
    }
}

impl From<KeyType> for KeyRole {
    fn from(kt: KeyType) -> Self {
        match kt {
            KeyType::Root => KeyRole::Root,
            KeyType::Domain => KeyRole::DomainKek,
            KeyType::KeyEncrypting => KeyRole::Kek,
            KeyType::DataEncrypting => KeyRole::Dek,
            KeyType::HybridIdentity => KeyRole::HybridIdentityKey,
            KeyType::Signing => KeyRole::SigningKey,
        }
    }
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// WrapAlgorithm
// ---------------------------------------------------------------------------

/// Cryptographic algorithm used to wrap (encrypt) a key's secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapAlgorithm {
    /// AES-256-GCM with HKDF-SHA256 key derivation (V1/V2 master-key wrapping).
    Aes256GcmHkdfSha256,
    /// Citadel hybrid envelope: X25519 + ML-KEM-768 + AES-256-GCM (V2 KEK hierarchy).
    CitadelHybridV2,
}

impl std::fmt::Display for WrapAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapAlgorithm::Aes256GcmHkdfSha256 => write!(f, "AES-256-GCM+HKDF-SHA256"),
            WrapAlgorithm::CitadelHybridV2 => write!(f, "X25519+ML-KEM-768+AES-256-GCM"),
        }
    }
}

// ---------------------------------------------------------------------------
// WrappingMode
// ---------------------------------------------------------------------------

/// How a `KeyVersion`'s secret material is cryptographically protected.
///
/// This is the V3 replacement for the ad-hoc triple
/// `(wrapping_key_id, wrapping_key_version, wrap_nonce_hex)`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum WrappingMode {
    /// Protected by `CITADEL_MASTER_KEY` via AES-256-GCM + HKDF-SHA256.
    ///
    /// This is the V1/V2 default for Root and Domain keys, and for all keys
    /// when no parent KEK is available.
    ExternalMaster,

    /// Protected by a parent key within the Citadel keystore hierarchy.
    ///
    /// Unwrapping requires loading and decrypting the parent key first,
    /// potentially recursively through the chain.
    WrappedByKey {
        parent_key_id: String,
        parent_version: u32,
        algorithm: WrapAlgorithm,
    },

    /// Protected by an external HSM or cloud KMS.
    ///
    /// The keystore does not hold the wrapping key material; unwrapping
    /// requires calling the provider's API.
    HsmBacked {
        /// Provider identifier (e.g. "aws-kms", "gcp-kms", "pkcs11").
        provider: String,
        /// Provider-specific key reference (ARN, resource name, label).
        key_ref: String,
    },
}

impl WrappingMode {
    /// Derive a `WrappingMode` from the V2 legacy fields on `KeyVersion`.
    ///
    /// Used during deserialization of V2 keys that do not yet have a
    /// `wrapping_mode` field.
    pub fn from_legacy(
        wrapping_key_id: &Option<String>,
        wrapping_key_version: &Option<u32>,
        is_citadel_wrapped: bool,
    ) -> Self {
        match (wrapping_key_id, wrapping_key_version) {
            (Some(kid), Some(kver)) if is_citadel_wrapped => WrappingMode::WrappedByKey {
                parent_key_id: kid.clone(),
                parent_version: *kver,
                algorithm: WrapAlgorithm::CitadelHybridV2,
            },
            _ => WrappingMode::ExternalMaster,
        }
    }

    /// Human-readable summary.
    pub fn summary(&self) -> String {
        match self {
            WrappingMode::ExternalMaster => "external-master-key".into(),
            WrappingMode::WrappedByKey {
                parent_key_id,
                parent_version,
                algorithm,
            } => format!(
                "key:{}@v{}({})",
                &parent_key_id[..8.min(parent_key_id.len())],
                parent_version,
                algorithm
            ),
            WrappingMode::HsmBacked { provider, key_ref } => {
                format!("hsm:{}/{}", provider, key_ref)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Graph violation types
// ---------------------------------------------------------------------------

/// A violation detected during wrapping graph validation.
#[derive(Debug, Clone)]
pub struct GraphViolation {
    pub kind: ViolationKind,
    pub detail: String,
}

/// Category of graph violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// A→B→...→A cycle detected.
    Cycle,
    /// Parent has a higher or equal depth than child (invalid direction).
    InvalidDirection,
    /// Parent key not found in the key set.
    OrphanedParent,
    /// Parent key is in a state that prevents it from wrapping children.
    InactiveParent,
    /// Wrapping mode incompatible with key role.
    InvalidWrappingForRole,
}

// ---------------------------------------------------------------------------
// Graph validation
// ---------------------------------------------------------------------------

/// Validate the wrapping relationships across all keys.
///
/// Checks:
/// 1. **Cycles**: DFS from every key, looking for back-edges.
/// 2. **Direction**: parent role must be strictly one level above child role.
/// 3. **Orphaned parents**: `wrapping_key_id` references a non-existent key.
/// 4. **Inactive parents**: parent is not Active or Rotated (cannot wrap children).
/// 5. **Role compatibility**: ExternalMaster only for Root/DomainKek roles.
///
/// Returns all violations found (not just the first).
pub fn validate_wrapping_graph(keys: &[KeyMetadata]) -> Vec<GraphViolation> {
    use crate::types::KeyState;

    let mut violations = Vec::new();

    // Build lookup: key_id → (KeyMetadata, wrapping_key_id_of_current_version)
    let by_id: HashMap<&str, &KeyMetadata> = keys.iter().map(|k| (k.id.as_str(), k)).collect();

    for key in keys {
        let role = KeyRole::from(key.key_type);

        // Get the current version's parent reference.
        let parent_id: Option<&str> = key
            .current_key_version()
            .and_then(|kv| kv.wrapping_key_id.as_deref());

        // ── Check 1: orphaned parent ──────────────────────────────────────
        if let Some(pid) = parent_id {
            if !by_id.contains_key(pid) {
                violations.push(GraphViolation {
                    kind: ViolationKind::OrphanedParent,
                    detail: format!(
                        "key '{}' ({}) references parent '{}' which does not exist",
                        key.name, role, pid
                    ),
                });
                continue; // Can't validate direction without parent
            }

            let parent = by_id[pid];
            let parent_role = KeyRole::from(parent.key_type);

            // ── Check 2: invalid direction ────────────────────────────────
            if !parent_role.can_wrap(role) {
                violations.push(GraphViolation {
                    kind: ViolationKind::InvalidDirection,
                    detail: format!(
                        "key '{}' ({}) is wrapped by '{}' ({}) — invalid: {} cannot wrap {}",
                        key.name, role, parent.name, parent_role, parent_role, role
                    ),
                });
            }

            // ── Check 3: inactive parent ──────────────────────────────────
            if !matches!(parent.state, KeyState::Active | KeyState::Rotated) {
                violations.push(GraphViolation {
                    kind: ViolationKind::InactiveParent,
                    detail: format!(
                        "key '{}' is wrapped by '{}' which is in state {}",
                        key.name, parent.name, parent.state
                    ),
                });
            }
        } else {
            // No parent — must be acceptable for this role.
            // ── Check 4: ExternalMaster for roles that must have a parent ─
            if !role.allow_external_master() && !matches!(role, KeyRole::Root | KeyRole::DomainKek)
            {
                violations.push(GraphViolation {
                    kind: ViolationKind::InvalidWrappingForRole,
                    detail: format!(
                        "key '{}' ({}) has no parent but its role requires one",
                        key.name, role
                    ),
                });
            }
        }
    }

    // ── Check 5: cycle detection (DFS) ────────────────────────────────────
    let mut visited_global: HashSet<&str> = HashSet::new();

    for key in keys {
        if visited_global.contains(key.id.as_str()) {
            continue;
        }
        let mut path: Vec<&str> = Vec::new();
        let mut in_path: HashSet<&str> = HashSet::new();
        detect_cycle(
            key.id.as_str(),
            &by_id,
            &mut path,
            &mut in_path,
            &mut visited_global,
            &mut violations,
        );
    }

    violations
}

fn detect_cycle<'a>(
    current_id: &'a str,
    by_id: &HashMap<&'a str, &'a KeyMetadata>,
    path: &mut Vec<&'a str>,
    in_path: &mut std::collections::HashSet<&'a str>,
    visited_global: &mut std::collections::HashSet<&'a str>,
    violations: &mut Vec<GraphViolation>,
) {
    if in_path.contains(current_id) {
        let cycle: Vec<&str> = path
            .iter()
            .skip_while(|&&id| id != current_id)
            .copied()
            .collect();
        violations.push(GraphViolation {
            kind: ViolationKind::Cycle,
            detail: format!("cycle detected: {} → {}", cycle.join(" → "), current_id),
        });
        return;
    }
    if visited_global.contains(current_id) {
        return;
    }

    let Some(meta) = by_id.get(current_id) else {
        return;
    };

    path.push(current_id);
    in_path.insert(current_id);

    if let Some(parent_id) = meta
        .current_key_version()
        .and_then(|kv| kv.wrapping_key_id.as_deref())
    {
        detect_cycle(parent_id, by_id, path, in_path, visited_global, violations);
    }

    in_path.remove(current_id);
    visited_global.insert(current_id);
    path.pop();
}
