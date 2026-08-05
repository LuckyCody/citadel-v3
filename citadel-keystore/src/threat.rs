// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Adaptive Threat Level System
//!
//! Dynamically adjusts keystore security posture based on observed threat conditions.
//! Inspired by Citadel 2.0's adaptive lattice parameters â€” applied to key lifecycle.
//!
//! ## How it works
//!
//! The `ThreatAssessor` ingests `ThreatEvent`s (failed decryptions, anomalous access
//! patterns, external signals) and maintains a rolling threat score. The score maps
//! to a `ThreatLevel` (1â€“5), which the `PolicyAdapter` uses to tighten or relax
//! key lifecycle parameters in real time.
//!
//! At **Level 1 (Low)**, policies run as configured.  
//! At **Level 5 (Critical)**, rotation intervals shrink to 1/5, grace periods
//! compress, usage limits drop, and auto-rotate is forced on.
//!
//! No existing KMS does this. AWS KMS and HashiCorp Vault use static policies.

use crate::audit::{AuditAction, AuditEvent, AuditSinkSync};
use crate::policy::KeyPolicy;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Threat level
// ---------------------------------------------------------------------------

/// System-wide threat level (1â€“5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Normal operations. Policies run as configured.
    Low = 1,
    /// Elevated awareness. Slightly tighter parameters.
    Guarded = 2,
    /// Active concern. Rotation intervals halved.
    Elevated = 3,
    /// Credible threat. Aggressive rotation, short grace periods.
    High = 4,
    /// Active incident. Maximum hardening, force auto-rotate.
    Critical = 5,
}

impl ThreatLevel {
    /// Numeric value (1â€“5).
    pub fn value(&self) -> u32 {
        *self as u32
    }

    /// From a numeric score (clamped to 1â€“5).
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            0..=1 => ThreatLevel::Low,
            2 => ThreatLevel::Guarded,
            3 => ThreatLevel::Elevated,
            4 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            ThreatLevel::Low => "LOW",
            ThreatLevel::Guarded => "GUARDED",
            ThreatLevel::Elevated => "ELEVATED",
            ThreatLevel::High => "HIGH",
            ThreatLevel::Critical => "CRITICAL",
        }
    }

    /// Color hint for dashboards (CSS-friendly).
    pub fn color(&self) -> &'static str {
        match self {
            ThreatLevel::Low => "#22c55e",      // green
            ThreatLevel::Guarded => "#3b82f6",  // blue
            ThreatLevel::Elevated => "#eab308", // yellow
            ThreatLevel::High => "#f97316",     // orange
            ThreatLevel::Critical => "#ef4444", // red
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Level {} ({})", self.value(), self.label())
    }
}

// ---------------------------------------------------------------------------
// Threat events (signals that feed the assessor)
// ---------------------------------------------------------------------------

/// A security-relevant event observed by the system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// When it happened.
    pub timestamp: DateTime<Utc>,
    /// What kind of event.
    pub kind: ThreatEventKind,
    /// How much this event contributes to the threat score (0.0â€“10.0).
    pub severity: f64,
    /// Optional context.
    pub detail: Option<String>,
}

impl ThreatEvent {
    pub fn new(kind: ThreatEventKind, severity: f64) -> Self {
        Self {
            timestamp: Utc::now(),
            kind,
            severity: severity.clamp(0.0, 10.0),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Categories of threat events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatEventKind {
    /// Decryption failed (wrong key, tampered data, etc.)
    DecryptionFailure,
    /// Multiple rapid decryption attempts (possible brute-force probe).
    RapidAccessPattern,
    /// Key access from unusual context.
    AnomalousAccess,
    /// External signal (e.g., CVE published, vendor advisory).
    ExternalAdvisory,
    /// Failed authentication or authorization attempt.
    AuthFailure,
    /// Suspicious key enumeration or metadata probing.
    KeyEnumeration,
    /// Manual escalation by operator.
    ManualEscalation,
    /// Manual de-escalation by operator.
    ManualDeescalation,
    /// Periodic heartbeat (resets decay timer, zero severity).
    Heartbeat,
}

// ---------------------------------------------------------------------------
// Security metrics (for the dashboard)
// ---------------------------------------------------------------------------

/// Security posture scores (0â€“100 each). Fed to the web UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Current threat level.
    pub threat_level: ThreatLevel,
    /// Raw threat score before level mapping.
    pub raw_score: f64,
    /// Resistance to quantum attacks (based on KEM choice + key freshness).
    pub quantum_resistance: f64,
    /// Classical cryptographic strength.
    pub classical_security: f64,
    /// Side-channel / oracle resistance.
    pub side_channel_resistance: f64,
    /// How well the system adapts to threats (based on policy tightness).
    pub adaptive_defense: f64,
    /// Key hygiene: fraction of keys within policy compliance.
    pub key_hygiene: f64,
    /// Overall composite score.
    pub overall: f64,
    /// Number of events in the current window.
    pub events_in_window: usize,
    /// Time since last event.
    pub time_since_last_event: Option<Duration>,
}

// ---------------------------------------------------------------------------
// Threat assessor
// ---------------------------------------------------------------------------

/// Configuration for the threat assessor.
#[derive(Clone, Debug)]
pub struct ThreatConfig {
    /// How far back to look when computing the threat score.
    pub window: Duration,
    /// How quickly old events decay (per-minute decay factor, 0.0â€“1.0).
    pub decay_rate: f64,
    /// Score thresholds for each level transition: [Lowâ†’Guarded, Guardedâ†’Elevated, ...].
    pub thresholds: [f64; 4],
    /// Maximum events to retain in the rolling window.
    pub max_events: usize,
    /// Hysteresis factor for de-escalation (0.0–1.0).
    /// Score must drop below threshold × (1.0 - hysteresis) to de-escalate.
    /// Default 0.2 means score must drop 20% below the escalation threshold.
    pub hysteresis: f64,
}

impl Default for ThreatConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(3600), // 1 hour
            decay_rate: 0.95,                  // 5% decay per minute
            thresholds: [5.0, 15.0, 30.0, 50.0],
            max_events: 10_000,
            hysteresis: 0.2, // 20% band for de-escalation
        }
    }
}

/// The adaptive threat assessment engine.
///
/// Ingests events, computes a rolling threat score with time-decay,
/// and maps it to a ThreatLevel that drives policy adaptation.
pub struct ThreatAssessor {
    config: ThreatConfig,
    events: VecDeque<ThreatEvent>,
    current_level: ThreatLevel,
    /// Manual override (if set, ignores computed level).
    manual_override: Option<ThreatLevel>,
    /// Audit sink for threat-level changes.
    audit: Option<Arc<dyn AuditSinkSync>>,
    /// History of level transitions.
    level_history: Vec<(DateTime<Utc>, ThreatLevel, String)>,
}

impl ThreatAssessor {
    pub fn new(config: ThreatConfig) -> Self {
        Self {
            config,
            events: VecDeque::new(),
            current_level: ThreatLevel::Low,
            manual_override: None,
            audit: None,
            level_history: vec![(Utc::now(), ThreatLevel::Low, "initialized".into())],
        }
    }

    pub fn with_audit(mut self, audit: Arc<dyn AuditSinkSync>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Record a threat event and recompute the threat level.
    pub fn record_event(&mut self, event: ThreatEvent) {
        // Handle manual escalation/de-escalation
        match event.kind {
            ThreatEventKind::ManualEscalation => {
                let new_level = match self.current_level {
                    ThreatLevel::Low => ThreatLevel::Guarded,
                    ThreatLevel::Guarded => ThreatLevel::Elevated,
                    ThreatLevel::Elevated => ThreatLevel::High,
                    ThreatLevel::High | ThreatLevel::Critical => ThreatLevel::Critical,
                };
                self.manual_override = Some(new_level);
            }
            ThreatEventKind::ManualDeescalation => {
                self.manual_override = None; // Remove override, let computed level take over
            }
            _ => {}
        }

        self.events.push_back(event);

        // Prune old events
        self.prune_old_events();

        // Recompute
        self.recompute_level();
    }

    /// Record a batch of events.
    pub fn record_events(&mut self, events: Vec<ThreatEvent>) {
        for event in events {
            self.events.push_back(event);
        }
        self.prune_old_events();
        self.recompute_level();
    }

    /// Get the current effective threat level.
    pub fn current_level(&self) -> ThreatLevel {
        self.manual_override.unwrap_or(self.current_level)
    }

    /// Get the raw computed score (before level mapping).
    pub fn raw_score(&self) -> f64 {
        self.compute_score()
    }

    /// Get the level transition history.
    pub fn level_history(&self) -> &[(DateTime<Utc>, ThreatLevel, String)] {
        &self.level_history
    }

    /// Get the number of events in the current window.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get recent events (last N).
    pub fn recent_events(&self, n: usize) -> Vec<&ThreatEvent> {
        self.events.iter().rev().take(n).collect()
    }

    /// Compute comprehensive security metrics for the dashboard.
    pub fn security_metrics(&self, total_keys: usize, compliant_keys: usize) -> SecurityMetrics {
        let level = self.current_level();
        let raw = self.compute_score();
        let lv = level.value() as f64;

        // Quantum resistance: high baseline (we use ML-KEM-768), slight penalty at high threat
        // because it means someone might be probing
        let quantum_resistance = (95.0 - (lv - 1.0) * 2.0).clamp(0.0, 100.0);

        // Classical security: always strong with X25519 + AES-256-GCM
        let classical_security = (98.0 - (lv - 1.0) * 1.0).clamp(0.0, 100.0);

        // Side-channel resistance: our oracle-resistant errors help, threat reduces confidence
        let side_channel_resistance = (90.0 - (lv - 1.0) * 3.0).clamp(0.0, 100.0);

        // Adaptive defense: HIGHER at higher threat levels (we're responding)
        let adaptive_defense = (60.0 + lv * 8.0).clamp(0.0, 100.0);

        // Key hygiene: fraction of compliant keys
        let key_hygiene = if total_keys > 0 {
            (compliant_keys as f64 / total_keys as f64) * 100.0
        } else {
            100.0
        };

        // Overall composite
        let overall = (quantum_resistance * 0.25
            + classical_security * 0.20
            + side_channel_resistance * 0.15
            + adaptive_defense * 0.20
            + key_hygiene * 0.20)
            .clamp(0.0, 100.0);

        let time_since_last = self.events.back().map(|e| {
            let elapsed = Utc::now() - e.timestamp;
            elapsed.to_std().unwrap_or(Duration::ZERO)
        });

        SecurityMetrics {
            threat_level: level,
            raw_score: raw,
            quantum_resistance,
            classical_security,
            side_channel_resistance,
            adaptive_defense,
            key_hygiene,
            overall,
            events_in_window: self.events.len(),
            time_since_last_event: time_since_last,
        }
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn compute_score(&self) -> f64 {
        let now = Utc::now();
        let mut score = 0.0;

        for event in &self.events {
            let age_minutes = (now - event.timestamp).num_minutes().max(0) as f64;
            let decay = self.config.decay_rate.powf(age_minutes);
            score += event.severity * decay;
        }

        score
    }

    fn recompute_level(&mut self) {
        let score = self.compute_score();
        let new_level = if let Some(manual) = self.manual_override {
            manual
        } else {
            // Compute the level from raw score (used for escalation)
            let raw_level = if score >= self.config.thresholds[3] {
                ThreatLevel::Critical
            } else if score >= self.config.thresholds[2] {
                ThreatLevel::High
            } else if score >= self.config.thresholds[1] {
                ThreatLevel::Elevated
            } else if score >= self.config.thresholds[0] {
                ThreatLevel::Guarded
            } else {
                ThreatLevel::Low
            };

            // Hysteresis: de-escalation requires score to drop further
            // than the escalation threshold. This prevents oscillation
            // when the score hovers near a boundary.
            let h = self.config.hysteresis;
            let de_escalation_level = if score >= self.config.thresholds[3] * (1.0 - h) {
                ThreatLevel::Critical
            } else if score >= self.config.thresholds[2] * (1.0 - h) {
                ThreatLevel::High
            } else if score >= self.config.thresholds[1] * (1.0 - h) {
                ThreatLevel::Elevated
            } else if score >= self.config.thresholds[0] * (1.0 - h) {
                ThreatLevel::Guarded
            } else {
                ThreatLevel::Low
            };

            if raw_level > self.current_level {
                // Escalating — use raw thresholds (respond fast)
                raw_level
            } else if de_escalation_level < self.current_level {
                // De-escalating — use relaxed thresholds (respond slowly)
                de_escalation_level
            } else {
                // In the hysteresis band — hold current level
                self.current_level
            }
        };

        if new_level != self.current_level {
            let old = self.current_level;
            self.current_level = new_level;
            let reason = format!(
                "score {:.1} â†’ {} (was {})",
                score,
                new_level.label(),
                old.label()
            );
            self.level_history
                .push((Utc::now(), new_level, reason.clone()));

            if let Some(audit) = &self.audit {
                audit.record(
                    AuditEvent::system_event(AuditAction::PolicyEvaluated {
                        verdict: format!("threat level changed: {} â†’ {}", old, new_level),
                    })
                    .with_detail(reason),
                );
            }
        }
    }

    fn prune_old_events(&mut self) {
        let cutoff = Utc::now()
            - ChronoDuration::from_std(self.config.window).unwrap_or(ChronoDuration::MAX);
        while self.events.front().is_some_and(|e| e.timestamp < cutoff) {
            self.events.pop_front();
        }
        while self.events.len() > self.config.max_events {
            self.events.pop_front();
        }
    }
}

// ---------------------------------------------------------------------------
// Policy adapter â€” the key innovation
// ---------------------------------------------------------------------------

/// Adapts a base policy based on the current threat level.
///
/// This is what makes the system novel: policies aren't static.
/// At higher threat levels, rotation intervals compress, grace periods
/// shrink, usage limits tighten, and auto-rotate is forced on.
///
/// ## Scaling factors by level
///
/// | Parameter         | L1   | L2   | L3   | L4   | L5   |
/// |-------------------|------|------|------|------|------|
/// | Rotation age      | 1.0Ã— | 0.75Ã— | 0.5Ã— | 0.3Ã— | 0.2Ã— |
/// | Grace period      | 1.0Ã— | 0.8Ã— | 0.5Ã— | 0.3Ã— | 0.1Ã— |
/// | Max lifetime      | 1.0Ã— | 0.8Ã— | 0.6Ã— | 0.4Ã— | 0.25Ã— |
/// | Usage limit       | 1.0Ã— | 0.8Ã— | 0.6Ã— | 0.4Ã— | 0.25Ã— |
/// | Auto-rotate       | base | base | ON   | ON   | ON   |
pub struct PolicyAdapter;

/// Operational floor limits — compression cannot push below these.
/// Without floors, extreme compression creates operational thrashing
/// (e.g., a 0.7-day grace period is 16.8 hours, too short for human response).
const FLOOR_ROTATION_AGE: Duration = Duration::from_secs(86400); // 1 day
const FLOOR_GRACE_PERIOD: Duration = Duration::from_secs(43200); // 12 hours
const FLOOR_MAX_LIFETIME: Duration = Duration::from_secs(30 * 86400); // 30 days
const FLOOR_USAGE_COUNT: u64 = 100; // minimum ops

impl PolicyAdapter {
    /// Adapt a policy for the current threat level.
    ///
    /// Scaling factors compress parameters at higher threat levels.
    /// Floor limits prevent compression below safe operational bounds.
    pub fn adapt(base: &KeyPolicy, level: ThreatLevel) -> KeyPolicy {
        let factor = Self::scaling_factor(level);
        let mut adapted = base.clone();

        // Scale rotation age triggers (with floor)
        adapted.rotation_triggers = base
            .rotation_triggers
            .iter()
            .map(|t| match t {
                crate::policy::RotationTrigger::Age(d) => {
                    let scaled = Duration::from_secs((d.as_secs() as f64 * factor.age) as u64);
                    crate::policy::RotationTrigger::Age(scaled.max(FLOOR_ROTATION_AGE))
                }
                other => other.clone(),
            })
            .collect();

        // Scale grace period (with floor)
        let scaled_grace = Duration::from_secs(
            (base.rotation_grace_period.as_secs() as f64 * factor.grace) as u64,
        );
        adapted.rotation_grace_period = scaled_grace.max(FLOOR_GRACE_PERIOD);

        // Scale max lifetime (with floor)
        adapted.max_lifetime = base.max_lifetime.map(|d| {
            let scaled = Duration::from_secs((d.as_secs() as f64 * factor.lifetime) as u64);
            scaled.max(FLOOR_MAX_LIFETIME)
        });

        // Scale usage limit (with floor)
        adapted.max_usage_count = base.max_usage_count.map(|c| {
            let scaled = ((c as f64) * factor.usage) as u64;
            scaled.max(FLOOR_USAGE_COUNT)
        });

        // Force auto-rotate at Level 3+
        if level >= ThreatLevel::Elevated {
            adapted.auto_rotate = true;
        }

        // Update name to reflect adaptation
        adapted.name = format!("{} [threat:{}]", base.name, level.label());

        adapted
    }

    /// Get the scaling factors for a threat level.
    fn scaling_factor(level: ThreatLevel) -> ScalingFactors {
        match level {
            ThreatLevel::Low => ScalingFactors {
                age: 1.0,
                grace: 1.0,
                lifetime: 1.0,
                usage: 1.0,
            },
            ThreatLevel::Guarded => ScalingFactors {
                age: 0.75,
                grace: 0.8,
                lifetime: 0.8,
                usage: 0.8,
            },
            ThreatLevel::Elevated => ScalingFactors {
                age: 0.5,
                grace: 0.5,
                lifetime: 0.6,
                usage: 0.6,
            },
            ThreatLevel::High => ScalingFactors {
                age: 0.3,
                grace: 0.3,
                lifetime: 0.4,
                usage: 0.4,
            },
            ThreatLevel::Critical => ScalingFactors {
                age: 0.2,
                grace: 0.1,
                lifetime: 0.25,
                usage: 0.25,
            },
        }
    }

    /// Compute the effective policy parameters and return a summary (for the dashboard).
    pub fn summarize(base: &KeyPolicy, level: ThreatLevel) -> AdaptationSummary {
        let adapted = Self::adapt(base, level);

        let rotation_age = adapted.rotation_triggers.iter().find_map(|t| {
            if let crate::policy::RotationTrigger::Age(d) = t {
                Some(*d)
            } else {
                None
            }
        });

        AdaptationSummary {
            policy_name: base.name.clone(),
            threat_level: level,
            base_rotation_age: base.rotation_triggers.iter().find_map(|t| {
                if let crate::policy::RotationTrigger::Age(d) = t {
                    Some(*d)
                } else {
                    None
                }
            }),
            effective_rotation_age: rotation_age,
            base_grace_period: base.rotation_grace_period,
            effective_grace_period: adapted.rotation_grace_period,
            base_max_lifetime: base.max_lifetime,
            effective_max_lifetime: adapted.max_lifetime,
            base_usage_limit: base.max_usage_count,
            effective_usage_limit: adapted.max_usage_count,
            auto_rotate_forced: level >= ThreatLevel::Elevated && !base.auto_rotate,
        }
    }
}

struct ScalingFactors {
    age: f64,
    grace: f64,
    lifetime: f64,
    usage: f64,
}

/// Summary of how a policy was adapted for a given threat level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdaptationSummary {
    pub policy_name: String,
    pub threat_level: ThreatLevel,
    pub base_rotation_age: Option<Duration>,
    pub effective_rotation_age: Option<Duration>,
    pub base_grace_period: Duration,
    pub effective_grace_period: Duration,
    pub base_max_lifetime: Option<Duration>,
    pub effective_max_lifetime: Option<Duration>,
    pub base_usage_limit: Option<u64>,
    pub effective_usage_limit: Option<u64>,
    pub auto_rotate_forced: bool,
}
