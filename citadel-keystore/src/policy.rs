// SPDX-License-Identifier: AGPL-3.0-or-later
//! Policy engine: defines when and how keys rotate, expire, and age out.

use crate::types::{KeyMetadata, KeyState, KeyType, PolicyId};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Rotation triggers
// ---------------------------------------------------------------------------

/// What causes a key to need rotation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RotationTrigger {
    /// Key has been active for longer than this duration.
    Age(Duration),
    /// Key has been used more than this many times.
    UsageCount(u64),
    /// External signal (e.g., security incident, compliance requirement).
    ExternalSignal(String),
    /// Parent key was rotated — cascade to children.
    ParentRotated,
}

// ---------------------------------------------------------------------------
// Key policy
// ---------------------------------------------------------------------------

/// Policy governing key lifecycle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Unique policy identifier.
    pub id: PolicyId,
    /// Human-readable name.
    pub name: String,
    /// Which key types this policy applies to.
    pub applies_to: Vec<KeyType>,
    /// Conditions that trigger rotation.
    pub rotation_triggers: Vec<RotationTrigger>,
    /// How long a ROTATED key remains decryptable.
    pub rotation_grace_period: Duration,
    /// Maximum total lifetime for an ACTIVE key (None = unlimited).
    pub max_lifetime: Option<Duration>,
    /// Maximum encryption operations (None = unlimited).
    pub max_usage_count: Option<u64>,
    /// Whether to auto-rotate when triggers fire.
    pub auto_rotate: bool,
    /// Minimum number of old versions to retain before destruction.
    pub min_versions_retained: u32,
    /// P005: Whether this policy chooses strict operation-time cryptoperiod enforcement.
    /// When true, `max_lifetime` must be set and both protection and processing
    /// operations are denied after it elapses. NIST SP 800-57 permits some
    /// deactivated keys to process previously protected data; deployments that
    /// require that recipient-usage/archive behavior must leave this strict mode
    /// disabled until a separately authorized archival-processing path is configured.
    #[serde(default)]
    pub enforce_cryptoperiod: bool,
}

impl KeyPolicy {
    /// P005: Default DEK policy with optional strict cryptoperiod enforcement.
    /// - Rotation trigger: 90 days
    /// - Grace period: 7 days
    /// - Hard expiration: 97 days (rotation + grace)
    /// - Enforced: Based on CITADEL_ENFORCE_CRYPTOPERIODS env var
    pub fn default_dek() -> Self {
        let enforce = std::env::var("CITADEL_ENFORCE_CRYPTOPERIODS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        Self {
            id: PolicyId::new("default-dek"),
            name: "Default DEK Policy (NIST SP 800-57)".into(),
            applies_to: vec![KeyType::DataEncrypting],
            rotation_triggers: vec![RotationTrigger::Age(Duration::from_secs(90 * 86400))],
            rotation_grace_period: Duration::from_secs(7 * 86400),
            max_lifetime: Some(Duration::from_secs(97 * 86400)), // P005: rotation + grace
            max_usage_count: None,
            auto_rotate: false,
            min_versions_retained: 3,
            enforce_cryptoperiod: enforce,
        }
    }

    /// P005: Default KEK policy with optional strict cryptoperiod enforcement.
    /// - Rotation trigger: 365 days
    /// - Grace period: 30 days
    /// - Hard expiration: 395 days (rotation + grace)
    /// - Enforced: Based on CITADEL_ENFORCE_CRYPTOPERIODS env var
    pub fn default_kek() -> Self {
        let enforce = std::env::var("CITADEL_ENFORCE_CRYPTOPERIODS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        Self {
            id: PolicyId::new("default-kek"),
            name: "Default KEK Policy (NIST SP 800-57)".into(),
            applies_to: vec![KeyType::KeyEncrypting],
            rotation_triggers: vec![RotationTrigger::Age(Duration::from_secs(365 * 86400))],
            rotation_grace_period: Duration::from_secs(30 * 86400),
            max_lifetime: Some(Duration::from_secs(395 * 86400)), // P005: rotation + grace
            max_usage_count: None,
            auto_rotate: false,
            min_versions_retained: 5,
            enforce_cryptoperiod: enforce,
        }
    }

    /// P005: Default Root policy with optional strict cryptoperiod enforcement.
    /// - Rotation trigger: 730 days (2 years)
    /// - Grace period: 90 days
    /// - Hard expiration: 820 days (rotation + grace)
    /// - Enforced: Based on CITADEL_ENFORCE_CRYPTOPERIODS env var
    pub fn default_root() -> Self {
        let enforce = std::env::var("CITADEL_ENFORCE_CRYPTOPERIODS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        Self {
            id: PolicyId::new("default-root"),
            name: "Default Root Policy (NIST SP 800-57)".into(),
            applies_to: vec![KeyType::Domain],
            rotation_triggers: vec![RotationTrigger::Age(Duration::from_secs(730 * 86400))],
            rotation_grace_period: Duration::from_secs(90 * 86400),
            max_lifetime: Some(Duration::from_secs(820 * 86400)), // P005: rotation + grace
            max_usage_count: None,
            auto_rotate: false,
            min_versions_retained: 10,
            enforce_cryptoperiod: enforce,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy evaluator
// ---------------------------------------------------------------------------

/// Result of evaluating a policy against a key.
#[derive(Clone, Debug)]
pub enum PolicyVerdict {
    /// Key is compliant — no action needed.
    Compliant,
    /// Key needs rotation.
    RotationNeeded { reason: String },
    /// Key is approaching a trigger threshold (warning).
    Warning { reason: String },
    /// Key has exceeded max_usage_count.
    UsageLimitExceeded { count: u64, limit: u64 },
    /// P005: Key has exceeded max_lifetime with enforcement enabled.
    /// This is a HARD STOP — key CANNOT be used for any operations.
    Expired { age_days: i64, limit_days: u64 },
}

impl PolicyVerdict {
    pub fn needs_rotation(&self) -> bool {
        matches!(
            self,
            Self::RotationNeeded { .. } | Self::UsageLimitExceeded { .. }
        )
    }

    /// P005: Check if key is expired and operations must be denied.
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::Expired { .. })
    }
}

/// Evaluate a policy against a key's current metadata.
pub fn evaluate(policy: &KeyPolicy, key: &KeyMetadata) -> PolicyVerdict {
    // Only evaluate active keys for rotation
    if key.state != KeyState::Active {
        return PolicyVerdict::Compliant;
    }

    // P005: Check hard expiration when cryptoperiod enforcement is enabled
    if policy.enforce_cryptoperiod {
        if let Some(max_lifetime) = policy.max_lifetime {
            if let Some(activated) = key.activated_at {
                let age = Utc::now() - activated;
                let max_lifetime_chrono =
                    chrono::Duration::from_std(max_lifetime).unwrap_or(chrono::Duration::MAX);

                if age >= max_lifetime_chrono {
                    // HARD STOP - key is expired and cannot be used
                    return PolicyVerdict::Expired {
                        age_days: age.num_days(),
                        limit_days: max_lifetime.as_secs() / 86400,
                    };
                }

                // Warn at 80% of max_lifetime (earlier than rotation trigger)
                let warn_threshold = chrono::Duration::from_std(Duration::from_secs(
                    (max_lifetime.as_secs() as f64 * 0.8) as u64,
                ))
                .unwrap_or(chrono::Duration::MAX);

                if age >= warn_threshold {
                    let pct = (age.num_seconds() * 100) / max_lifetime_chrono.num_seconds();
                    tracing::warn!(
                        key_id = %key.id,
                        age_days = age.num_days(),
                        limit_days = max_lifetime.as_secs() / 86400,
                        percent = pct,
                        "key approaching cryptoperiod expiration ({}%)", pct
                    );
                }
            }
        } else {
            // Enforcement enabled but no max_lifetime set - log warning
            tracing::warn!(
                key_id = %key.id,
                policy_id = %policy.id,
                "cryptoperiod enforcement enabled but max_lifetime not set"
            );
        }
    }

    // Check usage count limit
    if let Some(max_count) = policy.max_usage_count {
        if key.usage_count >= max_count {
            return PolicyVerdict::UsageLimitExceeded {
                count: key.usage_count,
                limit: max_count,
            };
        }
        // Warn at 90%
        let threshold = (max_count as f64 * 0.9) as u64;
        if key.usage_count >= threshold {
            return PolicyVerdict::Warning {
                reason: format!(
                    "usage {}/{} ({}%)",
                    key.usage_count,
                    max_count,
                    key.usage_count * 100 / max_count
                ),
            };
        }
    }

    // Check age-based triggers
    if let Some(activated) = key.activated_at {
        let age = Utc::now() - activated;
        for trigger in &policy.rotation_triggers {
            if let RotationTrigger::Age(max_age) = trigger {
                let max_age_chrono =
                    chrono::Duration::from_std(*max_age).unwrap_or(chrono::Duration::MAX);
                if age >= max_age_chrono {
                    return PolicyVerdict::RotationNeeded {
                        reason: format!(
                            "age {} exceeds max {}",
                            format_duration(age),
                            format_std_duration(*max_age)
                        ),
                    };
                }
                // Warn at 90%
                let warn_threshold = chrono::Duration::from_std(Duration::from_secs(
                    (max_age.as_secs() as f64 * 0.9) as u64,
                ))
                .unwrap_or(chrono::Duration::MAX);
                if age >= warn_threshold {
                    return PolicyVerdict::Warning {
                        reason: format!(
                            "age {} approaching max {}",
                            format_duration(age),
                            format_std_duration(*max_age),
                        ),
                    };
                }
            }
        }
    }

    PolicyVerdict::Compliant
}

fn format_duration(d: chrono::Duration) -> String {
    let days = d.num_days();
    if days > 0 {
        format!("{}d", days)
    } else {
        format!("{}h", d.num_hours())
    }
}

fn format_std_duration(d: Duration) -> String {
    let days = d.as_secs() / 86400;
    if days > 0 {
        format!("{}d", days)
    } else {
        format!("{}h", d.as_secs() / 3600)
    }
}
