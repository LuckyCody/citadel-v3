// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Citadel Keystore (V3)
//!
//! Post-quantum key lifecycle management with V3 improvements:
//!
//! - **Formal key hierarchy (P051)**: `KeyRole`, `WrappingMode`, `WrapAlgorithm` types.
//!   `KeyType::HybridIdentity` added. `KeyVersion::effective_wrapping_mode()` for
//!   backward-compatible hierarchy introspection.
//!
//! - **Graph validation (P052)**: `validate_wrapping_graph()` enforces direction
//!   (Root→DomainKek→Kek→Dek/HybridIdentityKey) and detects cycles.
//!
//! - **Citadel Doctor (P053)**: `run_all_checks()` and `DoctorReport` for deployment
//!   health diagnostics. CLI: `citadel doctor`.
//!
//! - **Key graph display (P054)**: `KeyGraph::build()` + `KeyGraph::render()` renders
//!   the hierarchy as an ASCII tree. CLI: `citadel key graph`.
//!
//! - **Hierarchy migration (P055)**: `plan_migration()` generates a dry-run-safe
//!   `MigrationPlan` for upgrading flat master-key-wrapped keys to the V3 hierarchy.
//!
//! - **ReplayStore trait (P056)**: `MemoryReplayStore`, `FileReplayStore`,
//!   `RedisReplayStore` (optional feature) provide distributed replay protection.
//!   Replay key = SHA-256(key_id || key_version || nonce). `fail_closed` policy.
//!
//! - **Encrypted backup (P060)**: `create_backup()`, `verify_backup()`, `restore_backup()`
//!   using AES-256-GCM + HKDF-SHA256.

pub mod audit;
pub mod audit_witness; // P007
pub mod backup;
pub mod doctor;
pub mod error;
pub mod graph;
pub mod hierarchy;
pub mod keystore;
pub mod migration;
pub mod policy;
/// V2 replay types — deprecated in 0.3.0, removed in 0.4.0.
/// Use `MemoryReplayStore`, `FileReplayStore`, `ReplayStore::claim()/release()` instead.
#[deprecated(
    since = "0.3.0",
    note = "Use replay_store::{MemoryReplayStore, FileReplayStore, ReplayStore} instead"
)]
pub mod replay;
pub mod replay_store;
pub mod root_key_provider;
pub mod sharded_replay_cache; // P006
pub mod storage;
pub mod threat;
pub mod types;

pub use audit::{
    AuditEvent, AuditSinkSync, FileAuditSink, InMemoryAuditSink, IntegrityChainSink,
    TracingAuditSink,
};
pub use backup::{
    create_backup, create_backup_with_provider, restore_backup, restore_backup_with_provider,
    verify_backup, verify_backup_with_provider,
};
pub use doctor::{run_all_checks, CheckStatus, DoctorCheck, DoctorReport};
pub use error::{
    CascadeError, DecryptError, DestroyDecision, EncryptError, ExpirationDecision,
    ExpirationReport, ExpirationSource, ExpireError, GenerateError, KeystoreError, LifecycleError,
    RewrapError, RotateError,
};
pub use graph::{GraphNode, KeyGraph};
pub use hierarchy::{
    validate_wrapping_graph, GraphViolation, KeyRole, ViolationKind, WrapAlgorithm, WrappingMode,
};
pub use keystore::{EncryptedBlob, Keystore, SignError, SignedPayload, VerifyError};
pub use migration::{plan_migration, MigrationOptions, MigrationPlan};
pub use policy::{KeyPolicy, PolicyVerdict, RotationTrigger};
// P388: V2 replay types (FileReplayCache, InMemoryReplayCache, ReplayCacheBackend)
// are deprecated and no longer re-exported at the crate root.
// They remain accessible via `citadel_keystore::replay::*` for
// callers that explicitly opt into the deprecated module.
// Prefer: MemoryReplayStore, FileReplayStore, ReplayStore::claim()/release()
pub use replay_store::{
    derive_replay_key, FileReplayStore, MemoryReplayStore, RedisReplayStore, ReplayError,
    ReplayStore,
};
pub use root_key_provider::{
    LinuxFileRootKeyProvider, LocalPilotConfig, RootKeyCapabilities, RootKeyError, RootKeyProvider,
};
pub use storage::{FileBackend, InMemoryBackend, StorageBackend};
pub use threat::{
    AdaptationSummary, PolicyAdapter, SecurityMetrics, ThreatAssessor, ThreatConfig, ThreatEvent,
    ThreatEventKind, ThreatLevel,
};
pub use types::{KeyId, KeyMetadata, KeyState, KeyType, KeyVersion, PolicyId, SecretKeyMaterial};

// ---------------------------------------------------------------------------
// Tests (unchanged from V2 — all must still pass)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use citadel_envelope::{Aad, Context};
    use std::sync::Arc;
    use std::time::Duration;

    fn test_keystore() -> Keystore {
        // Unit tests create flat DEKs (no hierarchy) for plumbing verification.
        // P211 strict hierarchy enforcement is tested in vertical_slice.rs; these unit tests use the override.
        std::env::set_var("CITADEL_ALLOW_PLAINTEXT_KEYS", "1");
        std::env::set_var("CITADEL_ENV", "development");
        std::env::set_var("CITADEL_ALLOW_FLAT_DEKS", "1");
        let storage = Arc::new(InMemoryBackend::new());
        let audit = Arc::new(InMemoryAuditSink::new());
        Keystore::new(storage, audit)
    }

    /// P288: Helper that creates a full Root -> Domain -> KEK -> DEK hierarchy.
    ///
    /// Required for tests that call encrypt() -- P225 domain-bound AAD enforcement
    /// calls resolve_domain_for_key() at encrypt time, which fails for orphaned
    /// flat DEKs even when CITADEL_ALLOW_FLAT_DEKS=1. The flag only bypasses
    /// the generate constraint, not the runtime domain resolution.
    async fn test_keystore_with_dek() -> (Keystore, KeyId) {
        let master_key = [0xABu8; 32];
        let storage = Arc::new(InMemoryBackend::new());
        let audit = Arc::new(InMemoryAuditSink::new());
        let ks = Keystore::with_master_key(
            storage as Arc<dyn StorageBackend>,
            audit as Arc<dyn AuditSinkSync>,
            master_key,
        );

        let root = ks
            .generate("root", KeyType::Root, None, None)
            .await
            .unwrap();
        ks.activate(&root).await.unwrap();

        let domain = ks
            .generate("domain", KeyType::Domain, None, Some(root))
            .await
            .unwrap();
        ks.activate(&domain).await.unwrap();

        let kek = ks
            .generate("kek", KeyType::KeyEncrypting, None, Some(domain))
            .await
            .unwrap();
        ks.activate(&kek).await.unwrap();

        let dek = ks
            .generate("dek", KeyType::DataEncrypting, None, Some(kek))
            .await
            .unwrap();
        ks.activate(&dek).await.unwrap();

        (ks, dek)
    }

    #[tokio::test]
    async fn test_generate_key() {
        let ks = test_keystore();
        let id = ks
            .generate("test-key", KeyType::DataEncrypting, None, None)
            .await
            .unwrap();
        let meta = ks.get(&id).await.unwrap();
        assert_eq!(meta.name, "test-key");
        assert_eq!(meta.state, KeyState::Pending);
    }

    #[tokio::test]
    async fn test_generate_hybrid_identity_type() {
        let ks = test_keystore();
        let id = ks
            .generate("hybrid-id-key", KeyType::HybridIdentity, None, None)
            .await
            .unwrap();
        let meta = ks.get(&id).await.unwrap();
        assert_eq!(meta.key_type, KeyType::HybridIdentity);
        assert_eq!(meta.role(), KeyRole::HybridIdentityKey);
    }

    #[tokio::test]
    async fn test_key_role_from_type() {
        assert_eq!(KeyRole::from(KeyType::Root), KeyRole::Root);
        assert_eq!(KeyRole::from(KeyType::Domain), KeyRole::DomainKek);
        assert_eq!(KeyRole::from(KeyType::KeyEncrypting), KeyRole::Kek);
        assert_eq!(KeyRole::from(KeyType::DataEncrypting), KeyRole::Dek);
        assert_eq!(
            KeyRole::from(KeyType::HybridIdentity),
            KeyRole::HybridIdentityKey
        );
    }

    #[tokio::test]
    async fn test_wrapping_mode_external_master() {
        let ks = test_keystore();
        let id = ks
            .generate("dek", KeyType::DataEncrypting, None, None)
            .await
            .unwrap();
        let meta = ks.get(&id).await.unwrap();
        let kv = meta.current_key_version().unwrap();
        let mode = kv.effective_wrapping_mode();
        // In plaintext dev mode, no wrapping → ExternalMaster
        matches!(mode, WrappingMode::ExternalMaster);
    }

    #[tokio::test]
    async fn test_validate_graph_empty() {
        let violations = validate_wrapping_graph(&[]);
        assert!(violations.is_empty());
    }

    #[tokio::test]
    async fn test_doctor_report_empty_keystore() {
        let report = run_all_checks("./test-data", false, &[], &[], "memory");
        assert!(report.has_failures(), "should fail with no master key");
    }

    #[tokio::test]
    async fn test_key_graph_build_empty() {
        let graph = KeyGraph::build(&[]);
        assert_eq!(graph.total_keys, 0);
        assert!(graph.roots.is_empty());
    }

    #[tokio::test]
    async fn test_migration_plan_empty() {
        let plan = plan_migration(&[], &MigrationOptions::default());
        assert!(
            !plan.is_empty(),
            "empty keystore still needs root/domain/kek created"
        );
        assert_eq!(plan.keys_to_create.len(), 3);
    }

    #[tokio::test]
    async fn test_memory_replay_store() {
        let store = MemoryReplayStore::new(Duration::from_secs(3600), true);
        let key = b"test-nonce-key";
        assert!(
            store.claim(key, Duration::from_secs(60)).unwrap(),
            "first claim should succeed"
        );
        assert!(
            !store.claim(key, Duration::from_secs(60)).unwrap(),
            "second claim should be rejected as replay"
        );
        store.release(key).unwrap();
        assert!(
            store.claim(key, Duration::from_secs(60)).unwrap(),
            "claim after release should succeed"
        );
    }

    #[tokio::test]
    async fn test_activate_key() {
        let ks = test_keystore();
        let id = ks
            .generate("key", KeyType::DataEncrypting, None, None)
            .await
            .unwrap();
        ks.activate(&id).await.unwrap();
        assert_eq!(ks.get(&id).await.unwrap().state, KeyState::Active);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // P288: must use a full hierarchy — encrypt() calls resolve_domain_for_key()
        // (P225 domain-bound AAD). A flat DEK with no Domain ancestor fails at
        // encrypt time regardless of CITADEL_ALLOW_FLAT_DEKS.
        let (ks, dek_id) = test_keystore_with_dek().await;
        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");
        let blob = ks.encrypt(&dek_id, b"hello v3", &aad, &ctx).await.unwrap();
        let pt = ks.decrypt(&blob, &aad, &ctx).await.unwrap();
        assert_eq!(pt, b"hello v3");
    }

    /// Strict enforcement is an operation-time boundary, not merely a background
    /// lifecycle transition. Non-strict policy preserves recipient processing of
    /// existing ciphertext, as permitted by NIST SP 800-57.
    #[tokio::test]
    async fn test_decrypt_cryptoperiod_respects_strict_enforcement_mode() {
        let master_key = [0xACu8; 32];
        let storage = Arc::new(InMemoryBackend::new());
        let audit = Arc::new(InMemoryAuditSink::new());
        let mut ks = Keystore::with_master_key(
            storage.clone() as Arc<dyn StorageBackend>,
            audit as Arc<dyn AuditSinkSync>,
            master_key,
        );

        let policy_id = PolicyId::new("test-enforced-decrypt-cryptoperiod");
        ks.register_policy(KeyPolicy {
            id: policy_id.clone(),
            name: "Test enforced decrypt cryptoperiod".into(),
            applies_to: vec![KeyType::DataEncrypting],
            rotation_triggers: vec![],
            rotation_grace_period: Duration::from_secs(30),
            max_lifetime: Some(Duration::from_secs(60)),
            max_usage_count: None,
            auto_rotate: false,
            min_versions_retained: 1,
            enforce_cryptoperiod: true,
        });

        let root = ks
            .generate("root", KeyType::Root, None, None)
            .await
            .unwrap();
        ks.activate(&root).await.unwrap();
        let domain = ks
            .generate("domain", KeyType::Domain, None, Some(root))
            .await
            .unwrap();
        ks.activate(&domain).await.unwrap();
        let kek = ks
            .generate("kek", KeyType::KeyEncrypting, None, Some(domain))
            .await
            .unwrap();
        ks.activate(&kek).await.unwrap();
        let dek = ks
            .generate(
                "dek",
                KeyType::DataEncrypting,
                Some(policy_id.clone()),
                Some(kek),
            )
            .await
            .unwrap();
        ks.activate(&dek).await.unwrap();

        let aad = Aad::raw(b"cryptoperiod-aad");
        let ctx = Context::raw(b"cryptoperiod-context");
        let blob = ks
            .encrypt(&dek, b"must not decrypt after expiration", &aad, &ctx)
            .await
            .unwrap();

        // Simulate passage beyond the policy lifetime while leaving lifecycle
        // state Active, which is the interval between expiry and a sweeper run.
        let mut meta = storage.get(&dek).unwrap().unwrap();
        meta.activated_at = Some(chrono::Utc::now() - chrono::Duration::days(40));
        storage.put(&meta).unwrap();

        let result = ks.decrypt(&blob, &aad, &ctx).await;
        assert!(
            result.is_err(),
            "decrypt must fail at operation time when an enforced cryptoperiod has elapsed"
        );

        // Re-register the same policy without strict enforcement. The failed
        // strict-mode attempt occurs before replay claim, so the same valid blob
        // must remain processable under the explicit recipient-usage choice.
        ks.register_policy(KeyPolicy {
            id: policy_id,
            name: "Test recipient processing after originator period".into(),
            applies_to: vec![KeyType::DataEncrypting],
            rotation_triggers: vec![],
            rotation_grace_period: Duration::from_secs(30),
            max_lifetime: Some(Duration::from_secs(60)),
            max_usage_count: None,
            auto_rotate: false,
            min_versions_retained: 1,
            enforce_cryptoperiod: false,
        });
        let plaintext = ks.decrypt(&blob, &aad, &ctx).await.unwrap();
        assert_eq!(plaintext, b"must not decrypt after expiration");
    }

    #[tokio::test]
    async fn test_replay_protection() {
        // P288: must use a full hierarchy for the same reason as test_encrypt_decrypt_roundtrip.
        // CITADEL_ALLOW_FLAT_DEKS only bypasses key generation, not runtime domain resolution.
        let (ks, dek_id) = test_keystore_with_dek().await;
        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");
        let blob = ks.encrypt(&dek_id, b"data", &aad, &ctx).await.unwrap();
        // First decrypt succeeds
        let _ = ks.decrypt(&blob, &aad, &ctx).await.unwrap();
        // Second decrypt of same blob must be rejected by replay protection
        let result = ks.decrypt(&blob, &aad, &ctx).await;
        assert!(result.is_err(), "replay of same blob must be rejected");
    }

    #[test]
    fn test_wrapping_mode_from_legacy_none() {
        let mode = WrappingMode::from_legacy(&None, &None, false);
        assert_eq!(mode, WrappingMode::ExternalMaster);
    }

    #[test]
    fn test_wrapping_mode_from_legacy_citadel() {
        let mode = WrappingMode::from_legacy(&Some("parent-id".into()), &Some(1), true);
        matches!(mode, WrappingMode::WrappedByKey { .. });
    }

    #[test]
    fn test_key_role_can_wrap() {
        assert!(KeyRole::Root.can_wrap(KeyRole::DomainKek));
        assert!(KeyRole::DomainKek.can_wrap(KeyRole::Kek));
        assert!(KeyRole::Kek.can_wrap(KeyRole::Dek));
        assert!(KeyRole::Kek.can_wrap(KeyRole::HybridIdentityKey));
        assert!(KeyRole::Kek.can_wrap(KeyRole::SigningKey)); // P361
        assert!(!KeyRole::Dek.can_wrap(KeyRole::Kek));
        assert!(!KeyRole::Kek.can_wrap(KeyRole::Root));
        assert!(!KeyRole::SigningKey.can_wrap(KeyRole::Dek)); // SigningKey cannot be a parent
    }

    /// P384 — Keystore without a bound StateEnforcer MUST reject all authorized methods.
    ///
    /// This proves "cannot be used incorrectly" — not "correct if used properly."
    /// A Keystore created without calling with_enforcer() is a misconfiguration
    /// and authorized operations must fail-closed, not silently succeed.
    #[tokio::test]
    async fn test_p384_keystore_without_enforcer_rejects_authorized_methods() {
        use crate::storage::InMemoryBackend;
        use citadel_core::StateEnforcer;
        use std::sync::Arc;

        let storage = Arc::new(InMemoryBackend::new());
        let audit = Arc::new(crate::audit::InMemoryAuditSink::new());
        // Deliberately do NOT call with_enforcer() — this is the misconfiguration case
        let ks = Keystore::new(
            storage as Arc<dyn crate::storage::StorageBackend>,
            audit as Arc<dyn crate::audit::AuditSinkSync>,
        );

        // Create a valid AuthorizedContext from a separate enforcer (as a caller might)
        let mut caller_enforcer = StateEnforcer::new();
        caller_enforcer.register_key("key-1".into(), None);
        let auth_ctx = caller_enforcer
            .authorize_encrypt("key-1", None, None)
            .expect("caller enforcer should authorize");

        // Keystore has no bound enforcer — encrypt_authorized MUST fail
        let aad = citadel_envelope::Aad::raw(b"test");
        let ctx = citadel_envelope::Context::raw(b"test");
        let result = ks
            .encrypt_authorized(&auth_ctx, b"test plaintext", &aad, &ctx)
            .await;

        assert!(
            result.is_err(),
            "P384: keystore without bound StateEnforcer must reject encrypt_authorized — got Ok instead of Err"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no bound StateEnforcer") || err_msg.contains("with_enforcer"),
            "P384: error message must explain the misconfiguration, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_key_graph_render() {
        let graph = KeyGraph::build(&[]);
        let rendered = graph.render();
        assert!(rendered.contains("no keys") || rendered.is_empty() || rendered.contains("└"));
    }
}
