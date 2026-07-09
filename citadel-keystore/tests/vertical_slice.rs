// SPDX-License-Identifier: AGPL-3.0-or-later
//! P064 — Vertical slice test: full key lifecycle end-to-end.
//!
//! Proves that every seam in the system holds together:
//!
//!   generate Root → Domain KEK → Project KEK → DEK (4-level hierarchy)
//!   activate all keys
//!   encrypt with DEK → decrypt succeeds
//!   rotate KEK → old ciphertext still decrypts (old version accessible)
//!   rewrap DEK under new KEK version → old ciphertext still decrypts
//!   revoke KEK → DEK decrypt now fails with hierarchy error
//!   audit log contains all expected events

use citadel_envelope::{Aad, Context};
use citadel_keystore::{
    AuditSinkSync, InMemoryAuditSink, InMemoryBackend, KeyId, KeyState, KeyType, Keystore,
    StorageBackend,
};
use std::sync::Arc;

// P298: Process-global env vars are not thread-safe across parallel async tests.
// Any test that calls std::env::set_var/remove_var must hold this lock for its
// entire duration to prevent races with other tests doing the same.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ─── Setup helpers ────────────────────────────────────────────────────────────

fn test_store_and_audit() -> (Arc<InMemoryBackend>, Arc<InMemoryAuditSink>) {
    (
        Arc::new(InMemoryBackend::new()),
        Arc::new(InMemoryAuditSink::new()),
    )
}

#[allow(dead_code)]
fn test_keystore(storage: Arc<InMemoryBackend>, audit: Arc<InMemoryAuditSink>) -> Keystore {
    // Use a fixed 32-byte master key so wrapping is real (not plaintext).
    let master_key = [0xDE_u8; 32];
    Keystore::with_master_key(
        storage as Arc<dyn StorageBackend>,
        audit as Arc<dyn AuditSinkSync>,
        master_key,
    )
}

// ─── The vertical slice ───────────────────────────────────────────────────────

// ─── Test helpers for pub(crate) encrypt/decrypt ─────────────────────────────
// P384: These helpers now share a SINGLE StateEnforcer instance with the keystore.
// The same enforcer that issues AuthorizedContexts must be the one that validates them
// inside the keystore (validate_authz now fail-closed — no enforcer = Err, not Ok).
//
// Pattern matches production:
//   enforcer issues auth_ctx → keystore.validate_authz checks enforcer.issued_tokens
//
// Previous pattern (WRONG): local ephemeral enforcer issued token,
//   keystore had no enforcer bound → validate_authz silently passed without checking.

use citadel_core::StateEnforcer;
use tokio::sync::RwLock;

type SharedEnforcer = Arc<RwLock<StateEnforcer>>;

/// Create a test keystore bound to a shared StateEnforcer.
/// Returns (keystore, enforcer) — the enforcer must be used to issue all auth contexts.
fn test_keystore_with_enforcer(
    storage: Arc<InMemoryBackend>,
    audit: Arc<InMemoryAuditSink>,
) -> (Keystore, SharedEnforcer) {
    let master_key = [0xDE_u8; 32];
    let enforcer = Arc::new(RwLock::new(StateEnforcer::new()));
    let ks = Keystore::with_master_key(
        storage as Arc<dyn StorageBackend>,
        audit as Arc<dyn AuditSinkSync>,
        master_key,
    )
    .with_enforcer(Arc::clone(&enforcer));
    (ks, enforcer)
}

async fn ks_encrypt(
    ks: &Keystore,
    enforcer: &SharedEnforcer,
    key_id: &KeyId,
    plaintext: &[u8],
    aad: &Aad,
    ctx: &Context,
) -> citadel_keystore::EncryptedBlob {
    let mut enf = enforcer.write().await;
    enf.register_key(key_id.to_string(), None);
    let auth_ctx = match enf.authorize_encrypt(&key_id.to_string(), None, None) {
        Ok(ctx) => ctx,
        Err(r) => panic!("ks_encrypt: authorize_encrypt denied: {:?}", r),
    };
    drop(enf); // release write lock before async call — keystore read-locks enforcer
    ks.encrypt_authorized(&auth_ctx, plaintext, aad, ctx)
        .await
        .expect("ks_encrypt: encrypt_authorized failed")
}

async fn ks_decrypt(
    ks: &Keystore,
    enforcer: &SharedEnforcer,
    blob: &citadel_keystore::EncryptedBlob,
    aad: &Aad,
    ctx: &Context,
) -> Vec<u8> {
    let mut enf = enforcer.write().await;
    enf.register_key(blob.key_id.clone(), None);
    let auth_ctx = match enf.authorize_decrypt(&blob.key_id, None) {
        Ok(ctx) => ctx,
        Err(r) => panic!("ks_decrypt: authorize_decrypt denied: {:?}", r),
    };
    drop(enf);
    ks.decrypt_authorized(&auth_ctx, blob, aad, ctx)
        .await
        .expect("ks_decrypt: decrypt_authorized failed")
}

async fn ks_encrypt_result(
    ks: &Keystore,
    enforcer: &SharedEnforcer,
    key_id: &KeyId,
    plaintext: &[u8],
    aad: &Aad,
    ctx: &Context,
) -> Result<citadel_keystore::EncryptedBlob, citadel_keystore::EncryptError> {
    let mut enf = enforcer.write().await;
    enf.register_key(key_id.to_string(), None);
    let auth_ctx = match enf.authorize_encrypt(&key_id.to_string(), None, None) {
        Ok(ctx) => ctx,
        Err(r) => {
            return Err(citadel_keystore::EncryptError(format!(
                "enforcer denied: {:?}",
                r
            )))
        }
    };
    drop(enf);
    ks.encrypt_authorized(&auth_ctx, plaintext, aad, ctx).await
}

async fn ks_decrypt_result(
    ks: &Keystore,
    enforcer: &SharedEnforcer,
    blob: &citadel_keystore::EncryptedBlob,
    aad: &Aad,
    ctx: &Context,
) -> Result<Vec<u8>, citadel_keystore::DecryptError> {
    let mut enf = enforcer.write().await;
    enf.register_key(blob.key_id.clone(), None);
    let auth_ctx = match enf.authorize_decrypt(&blob.key_id, None) {
        Ok(ctx) => ctx,
        Err(r) => {
            return Err(citadel_keystore::DecryptError(format!(
                "enforcer denied: {:?}",
                r
            )))
        }
    };
    drop(enf);
    ks.decrypt_authorized(&auth_ctx, blob, aad, ctx).await
}

#[tokio::test]
async fn vertical_slice_full_lifecycle() {
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage.clone(), audit.clone());

    let aad = Aad::raw(b"vertical-slice-aad");
    let ctx = Context::raw(b"vertical-slice-ctx");

    // ── 1. Generate 4-level hierarchy ────────────────────────────────────────

    let root_id = ks
        .generate("default-root", KeyType::Root, None, None)
        .await
        .expect("generate Root");

    let domain_id = ks
        .generate(
            "default-domain",
            KeyType::Domain,
            None,
            Some(root_id.clone()),
        )
        .await
        .expect("generate Domain KEK");

    let kek_id = ks
        .generate(
            "project-kek",
            KeyType::KeyEncrypting,
            None,
            Some(domain_id.clone()),
        )
        .await
        .expect("generate KEK");

    let dek_id = ks
        .generate(
            "data-key",
            KeyType::DataEncrypting,
            None,
            Some(kek_id.clone()),
        )
        .await
        .expect("generate DEK");

    // ── 2. Activate all keys ─────────────────────────────────────────────────

    for id in &[&root_id, &domain_id, &kek_id, &dek_id] {
        ks.activate(id).await.expect("activate");
    }

    // Verify all active.
    for id in &[&root_id, &domain_id, &kek_id, &dek_id] {
        let meta = ks.get(id).await.unwrap();
        assert_eq!(
            meta.state,
            KeyState::Active,
            "key {} should be Active",
            meta.name
        );
    }

    // ── 3. Encrypt and decrypt ────────────────────────────────────────────────

    let blob = ks_encrypt(&ks, &enforcer, &dek_id, b"hello vertical slice", &aad, &ctx).await;

    let pt = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx)
        .await
        .unwrap();
    assert_eq!(pt, b"hello vertical slice", "roundtrip failed");

    // ── 4. Rotate KEK ────────────────────────────────────────────────────────
    // After rotation, a fresh encryption+decryption must work (DEK still accessible,
    // wrapped by old KEK version). We use a fresh blob because the original was
    // already decrypted once (replay protection would block a second decrypt).

    let new_kek_id = ks.rotate(&kek_id).await.expect("rotate KEK");

    // Fresh blob: proves DEK is still accessible via old KEK version after rotation.
    let blob_post_rotate =
        ks_encrypt(&ks, &enforcer, &dek_id, b"post-rotate data", &aad, &ctx).await;
    let pt_after_rotate = ks_decrypt_result(&ks, &enforcer, &blob_post_rotate, &aad, &ctx)
        .await
        .unwrap();
    assert_eq!(pt_after_rotate, b"post-rotate data");

    // ── 5. Rewrap DEK under new KEK version ──────────────────────────────────

    ks.rewrap(&dek_id, Some(&new_kek_id))
        .await
        .expect("rewrap DEK under new KEK");

    // Fresh blob: proves DEK is still usable after rewrap (same keypair, new wrapping).
    let blob_post_rewrap =
        ks_encrypt(&ks, &enforcer, &dek_id, b"post-rewrap check", &aad, &ctx).await;
    let pt_after_rewrap = ks_decrypt_result(&ks, &enforcer, &blob_post_rewrap, &aad, &ctx)
        .await
        .unwrap();
    assert_eq!(pt_after_rewrap, b"post-rewrap check");

    // New encryption also works.
    let blob2 = ks_encrypt(&ks, &enforcer, &dek_id, b"post-rewrap data", &aad, &ctx).await;
    let pt2 = ks_decrypt(&ks, &enforcer, &blob2, &aad, &ctx).await;
    assert_eq!(pt2, b"post-rewrap data");

    // ── 6. Revoke KEK → DEK decrypt must fail ────────────────────────────────

    // Revoke the NEW KEK (which is now the DEK's wrapping parent).
    ks.revoke(&new_kek_id, "security incident — vertical slice test")
        .await
        .expect("revoke new KEK");

    let revoked_meta = ks.get(&new_kek_id).await.unwrap();
    assert_eq!(revoked_meta.state, KeyState::Revoked);

    // DEK decrypt must now fail because its parent KEK is revoked.
    // Use the original first blob (which hasn't been replayed yet in this flow).
    let blob_for_revoke_test =
        ks_encrypt(&ks, &enforcer, &dek_id, b"revoke test data", &aad, &ctx).await;
    let result = ks_decrypt_result(&ks, &enforcer, &blob_for_revoke_test, &aad, &ctx).await;
    assert!(
        result.is_err(),
        "decrypt must fail when parent KEK is revoked — hierarchy must cascade"
    );
    // keystore.rs's decrypt() already collapses all internal failures to a single opaque
    // DecryptError("operation failed") (pre-existing P004 fix, oracle-safety). This test
    // predates that and asserted on message content that no longer exists. The failure
    // itself, asserted above, is what proves the hierarchy cascade actually worked.

    // ── 7. Rewrap DEK under domain KEK directly → decrypt resumes ─────────────
    // (recovery: skip the revoked KEK, wrap directly under domain)

    ks.rewrap(&dek_id, Some(&domain_id))
        .await
        .expect("rewrap DEK directly under domain KEK");

    let blob_recovery = ks_encrypt(&ks, &enforcer, &dek_id, b"recovery data", &aad, &ctx).await;
    let pt_recovered = ks_decrypt_result(&ks, &enforcer, &blob_recovery, &aad, &ctx)
        .await
        .unwrap();
    assert_eq!(pt_recovered, b"recovery data");

    // ── 8. Audit log completeness ─────────────────────────────────────────────

    let events = audit.events().await;
    let actions: Vec<String> = events.iter().map(|e| format!("{:?}", e.action)).collect();
    let all = actions.join(", ");

    // Must contain at least: 4 generates, 4 activates, 2 encrypts, multiple decrypts,
    // 1 rotate, 2 rewraps, 1 revoke, 1 hierarchy violation.
    let generated = actions
        .iter()
        .filter(|a| a.contains("KeyGenerated"))
        .count();
    let activated = actions
        .iter()
        .filter(|a| a.contains("KeyActivated"))
        .count();
    let encrypted = actions
        .iter()
        .filter(|a| a.contains("EncryptionPerformed"))
        .count();
    let rotated = actions.iter().filter(|a| a.contains("KeyRotated")).count();
    let rewrapped = actions
        .iter()
        .filter(|a| a.contains("KeyRewrapped"))
        .count();
    let revoked = actions.iter().filter(|a| a.contains("KeyRevoked")).count();
    let violations = actions
        .iter()
        .filter(|a| a.contains("HierarchyViolation"))
        .count();

    assert!(
        generated >= 4,
        "expected ≥4 KeyGenerated, got {generated}. Log: {all}"
    );
    assert!(
        activated >= 4,
        "expected ≥4 KeyActivated, got {activated}. Log: {all}"
    );
    assert!(
        encrypted >= 1,
        "expected ≥1 EncryptionPerformed, got {encrypted}. Log: {all}"
    );
    assert!(
        rotated >= 1,
        "expected ≥1 KeyRotated, got {rotated}. Log: {all}"
    );
    assert!(
        rewrapped >= 2,
        "expected ≥2 KeyRewrapped, got {rewrapped}. Log: {all}"
    );
    assert!(
        revoked >= 1,
        "expected ≥1 KeyRevoked, got {revoked}. Log: {all}"
    );
    assert!(
        violations >= 1,
        "expected ≥1 HierarchyViolation, got {violations}. Log: {all}"
    );
}

// ─── Focused: revocation cascade ─────────────────────────────────────────────

#[tokio::test]
async fn revoked_kek_blocks_dek_decrypt() {
    // P290: use full hierarchy — P211 rejects flat KEKs.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let kek_id = h.kek;
    let dek_id = h.dek;

    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let blob = ks_encrypt(&ks, &enforcer, &dek_id, b"secret", &aad, &ctx).await;

    // Verify decrypt works before revocation.
    ks_decrypt(&ks, &enforcer, &blob, &aad, &ctx).await; // ks_decrypt panics on failure;

    // Revoke KEK.
    ks.revoke(&kek_id, "test revocation").await.unwrap();

    // Decrypt must now fail.
    let err = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert!(err.is_err(), "decrypt must fail after KEK revocation");
}

// ─── Focused: rewrap restores access ─────────────────────────────────────────

#[tokio::test]
async fn rewrap_restores_decrypt_after_parent_rotation() {
    // P290: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let kek_id = h.kek;
    let dek_id = h.dek;

    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let blob = ks_encrypt(&ks, &enforcer, &dek_id, b"data", &aad, &ctx).await;

    // Rotate KEK → get new version.
    let new_kek = ks.rotate(&kek_id).await.unwrap();

    // Rewrap DEK under new KEK version.
    ks.rewrap(&dek_id, Some(&new_kek))
        .await
        .expect("rewrap must succeed");

    // Old ciphertext still decrypts (same DEK keypair).
    let pt = ks_decrypt(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert_eq!(pt, b"data");
}

// ─── Focused: destroyed KEK also blocks children ─────────────────────────────

#[tokio::test]
async fn destroyed_kek_blocks_dek_decrypt() {
    // P290: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let kek_id = h.kek;
    let dek_id = h.dek;

    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let blob = ks_encrypt(&ks, &enforcer, &dek_id, b"sensitive", &aad, &ctx).await;

    // Destroy KEK (more severe than revoke).
    ks.revoke(&kek_id, "destroy-test").await.unwrap();
    ks.destroy(&kek_id).await.unwrap();

    // DEK decrypt must fail — hierarchy cascade.
    let err = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert!(err.is_err(), "decrypt must fail after KEK destruction");
}

// ─── Focused: production preflight blocks broken config ──────────────────────

#[test]
fn production_gate_in_create_keystore_documented() {
    // P152: try_new_production() removed — production preflight lives in
    // citadel-api/src/main.rs::create_keystore() which checks CITADEL_MASTER_KEY,
    // CITADEL_ENV, and CITADEL_REPLAY_STORE with specific [FATAL] messages.
    //
    // The keystore layer itself enforces the master key requirement at the point
    // of each generate() call — if master key is missing, generate() returns Err.
    // This test verifies that behaviour.
    // P302: Hold ENV_LOCK — removes CITADEL_MASTER_KEY and CITADEL_ALLOW_PLAINTEXT_KEYS.
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("CITADEL_MASTER_KEY");
    std::env::remove_var("CITADEL_ALLOW_PLAINTEXT_KEYS");

    let storage = Arc::new(InMemoryBackend::new());
    let audit = Arc::new(InMemoryAuditSink::new());
    let ks = Keystore::new(
        storage as Arc<dyn StorageBackend>,
        audit as Arc<dyn AuditSinkSync>,
    );

    // generate() must fail without a master key or explicit dev override
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(ks.generate("test-dek", KeyType::DataEncrypting, None, None));
    assert!(
        result.is_err(),
        "generate must fail when CITADEL_MASTER_KEY is not set and dev mode is off"
    );
}

// ─── Focused: plaintext mode is audited ──────────────────────────────────────

#[tokio::test]
async fn plaintext_mode_emits_audit_event() {
    // P302: Hold ENV_LOCK — sets/removes CITADEL_ALLOW_PLAINTEXT_KEYS and CITADEL_ENV.
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("CITADEL_ALLOW_PLAINTEXT_KEYS", "1");
    std::env::set_var("CITADEL_ENV", "development");

    let storage = Arc::new(InMemoryBackend::new());
    let audit = Arc::new(InMemoryAuditSink::new());
    let _ks = Keystore::new(
        storage as Arc<dyn StorageBackend>,
        audit.clone() as Arc<dyn AuditSinkSync>,
    );

    let events = audit.events().await;
    let has_plaintext_event = events.iter().any(|e| {
        matches!(
            &e.action,
            citadel_keystore::audit::AuditAction::PlaintextModeActivated { .. }
        )
    });
    assert!(
        has_plaintext_event,
        "Keystore::new() must emit PlaintextModeActivated when plaintext mode is active"
    );

    std::env::remove_var("CITADEL_ALLOW_PLAINTEXT_KEYS");
    std::env::remove_var("CITADEL_ENV");
}

// ─── P063: DEK without KEK parent is rejected ─────────────────────────────────

#[tokio::test]
async fn p063_flat_dek_requires_parent_unless_override() {
    // Default: creating a DEK without a parent must fail (hierarchy enforcement).
    // P302: Hold ENV_LOCK — calls remove_var("CITADEL_ALLOW_FLAT_DEKS").
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage, audit);

    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");

    let result = ks
        .generate("flat-dek", KeyType::DataEncrypting, None, None)
        .await;
    assert!(
        result.is_err(),
        "DataEncrypting key with no parent must be rejected (P063 hierarchy enforcement)"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("hierarchy") || err.contains("parent"),
        "error must mention hierarchy or parent requirement, got: {err}"
    );

    // HybridIdentity must also require a parent.
    let result2 = ks
        .generate("flat-identity", KeyType::HybridIdentity, None, None)
        .await;
    assert!(
        result2.is_err(),
        "HybridIdentity key with no parent must also be rejected"
    );
}

#[tokio::test]
async fn p184_dek_under_root_is_rejected() {
    // P184: DEK with Root as parent must be rejected even when parent_id is provided.
    // The hierarchy requires Root -> Domain -> KEK -> DEK.
    // Previously the check only caught parent_id=None, not wrong parent type.
    // P302: Hold ENV_LOCK — calls remove_var("CITADEL_ALLOW_FLAT_DEKS").
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");

    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage, audit);

    let root = ks
        .generate("root", KeyType::Root, None, None)
        .await
        .unwrap();
    ks.activate(&root).await.unwrap();

    // Attempt to create a DEK with Root as parent -- must be rejected
    let result = ks
        .generate(
            "dek-under-root",
            KeyType::DataEncrypting,
            None,
            Some(root.clone()),
        )
        .await;
    assert!(
        result.is_err(),
        "DEK with Root parent must be rejected (P184 hierarchy enforcement)"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("hierarchy") || err.contains("parent"),
        "error must mention hierarchy or parent requirement, got: {err}"
    );

    // Correct full hierarchy: Root → Domain → KEK → DEK must all succeed.
    // P211: Root→KEK is now invalid (fixed). The full four-level chain is required.
    // can_wrap() accepts each step, so no CITADEL_ALLOW_FLAT_DEKS override is needed.
    let domain = ks
        .generate("domain", KeyType::Domain, None, Some(root.clone()))
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
        .await;
    assert!(
        dek.is_ok(),
        "DEK under KEK under Domain under Root must succeed: {:?}",
        dek
    );
}

#[tokio::test]
async fn p063_flat_dek_override_flag_allows_parentless() {
    // P292: P214 requires BOTH CITADEL_ALLOW_FLAT_DEKS=1 AND CITADEL_ENV=development.
    // P298: Env vars are process-global. Hold ENV_LOCK for the entire test to prevent
    // races with other parallel tests that also mutate env vars.
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    std::env::set_var("CITADEL_ALLOW_FLAT_DEKS", "1");
    std::env::set_var("CITADEL_ENV", "development");

    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage, audit);

    let result = ks
        .generate("flat-dek-override", KeyType::DataEncrypting, None, None)
        .await;
    assert!(
        result.is_ok(),
        "CITADEL_ALLOW_FLAT_DEKS=1 + CITADEL_ENV=development must permit parentless DEK: {:?}",
        result.err()
    );

    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
    std::env::remove_var("CITADEL_ENV");
    // _env_guard drops here, releasing the lock
}

// ─── P064: revoke_cascade() suspends all descendants ─────────────────────────

#[tokio::test]
async fn p064_revoke_cascade_suspends_children() {
    // P290: use full hierarchy; create two DEKs under h.kek to test cascade.
    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage.clone(), audit);
    let h = build_hierarchy(&ks).await;
    let kek_id = h.kek.clone();
    // Create a second DEK under the same KEK for cascade testing.
    let dek1 = h.dek;
    let dek2 = ks
        .generate("dek2", KeyType::DataEncrypting, None, Some(kek_id.clone()))
        .await
        .expect("generate dek2 under kek");
    ks.activate(&dek2).await.expect("activate dek2");

    // Cascade revoke: KEK revoked, both DEKs should become Suspended.
    let (revoked_count, suspended_count, errors) = ks
        .revoke_cascade(&kek_id, "p064 cascade test")
        .await
        .expect("revoke_cascade must succeed");

    assert_eq!(revoked_count, 1, "exactly 1 key revoked (the KEK itself)");
    assert_eq!(suspended_count, 2, "2 DEK children must be Suspended");
    assert!(errors.is_empty(), "no errors expected: {:?}", errors);

    // Confirm states.
    let kek_meta = ks.get(&kek_id).await.unwrap();
    assert_eq!(kek_meta.state, KeyState::Revoked, "KEK must be Revoked");

    let dek1_meta = ks.get(&dek1).await.unwrap();
    assert_eq!(
        dek1_meta.state,
        KeyState::Suspended,
        "dek1 must be Suspended"
    );

    let dek2_meta = ks.get(&dek2).await.unwrap();
    assert_eq!(
        dek2_meta.state,
        KeyState::Suspended,
        "dek2 must be Suspended"
    );
}

#[tokio::test]
async fn p064_suspended_dek_cannot_encrypt_or_decrypt() {
    // P290/P291: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let kek_id = h.kek;
    let dek_id = h.dek;

    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    // Encrypt before cascade (creates a blob we'll try to decrypt later).
    let blob = ks_encrypt(&ks, &enforcer, &dek_id, b"data", &aad, &ctx).await;

    // Cascade suspend.
    ks.revoke_cascade(&kek_id, "test").await.unwrap();

    // Encrypt with Suspended DEK must fail.
    let enc_result = ks_encrypt_result(&ks, &enforcer, &dek_id, b"more data", &aad, &ctx).await;
    assert!(
        enc_result.is_err(),
        "Suspended DEK must not allow encryption"
    );

    // Decrypt with Suspended DEK must also fail (can_decrypt returns false for Suspended).
    let dec_result = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert!(
        dec_result.is_err(),
        "Suspended DEK must not allow decryption"
    );
}

// ─── P065: rotate() is atomic — single put ───────────────────────────────────

#[tokio::test]
async fn p065_rotate_leaves_key_active_not_rotated_state() {
    // After rotate(), the key must be Active (not stuck in Rotated state).
    // Verifies the atomic single-put: no transient Rotated state written to storage.
    // P299: use full hierarchy — P211 rejects flat KEKs. Rotate the KEK from the hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage.clone(), audit);
    let h = build_hierarchy(&ks).await;
    let kek_id = h.kek;

    let new_id = ks.rotate(&kek_id).await.expect("rotate must succeed");
    assert_eq!(new_id, kek_id, "rotate returns same key ID");

    // Key must be Active with the new version — never stuck in Rotated.
    let meta = ks.get(&kek_id).await.unwrap();
    assert_eq!(
        meta.state,
        KeyState::Active,
        "key must be Active after rotate (P065 atomic)"
    );
    assert_eq!(
        meta.current_version, 2,
        "must be on version 2 after first rotation"
    );
    assert!(
        meta.rotated_at.is_some(),
        "rotated_at timestamp must be set"
    );
    // Both versions must be present (old version needed for decryption grace period).
    assert_eq!(
        meta.versions.len(),
        2,
        "must have 2 versions: original + rotated"
    );
}

// ─── P066: fail-closed replay store ──────────────────────────────────────────

#[tokio::test]
async fn p066_fail_closed_replay_store_denies_decrypt() {
    use citadel_keystore::{ReplayError, ReplayStore};
    use std::time::Duration;

    // A store that always returns Err — simulates Redis outage.
    struct AlwaysFailStore;
    impl ReplayStore for AlwaysFailStore {
        fn claim(&self, _key: &[u8], _ttl: Duration) -> Result<bool, ReplayError> {
            Err(ReplayError::new("simulated outage"))
        }
        fn release(&self, _key: &[u8]) -> Result<(), ReplayError> {
            Err(ReplayError::new("simulated outage"))
        }
    }

    // P290: build hierarchy first, then set failing replay store.
    // generate/activate don't use the replay store; only decrypt does.
    let (storage, audit) = test_store_and_audit();
    // P424: use test_keystore_with_enforcer so enforcer is defined for ks_encrypt/ks_decrypt_result
    let (ks_raw, enforcer) = test_keystore_with_enforcer(storage, audit);
    let mut ks = ks_raw;
    let h = build_hierarchy(&ks).await;
    let dek_id = h.dek;
    ks.set_replay_store(Box::new(AlwaysFailStore));

    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let blob = ks_encrypt(&ks, &enforcer, &dek_id, b"secret", &aad, &ctx).await;

    // Decrypt must fail: replay store returns Err → fail-closed → deny.
    let result = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert!(
        result.is_err(),
        "decrypt must fail when replay store is unavailable (fail-closed, P066)"
    );
    // keystore.rs's decrypt() already collapses all internal failures to a single opaque
    // DecryptError("operation failed") (pre-existing P004 fix, oracle-safety). This test
    // predates that and asserted on message content that no longer exists. The failure
    // itself, asserted above, is what proves fail-closed behavior actually held.
}

// ─── P068: doctor surfaces active children under revoked parent ───────────────

#[tokio::test]
async fn p068_doctor_detects_active_child_under_revoked_parent() {
    // P290: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage.clone(), audit);
    let h = build_hierarchy(&ks).await;
    let kek_id = h.kek;
    let dek_id = h.dek;

    // Revoke KEK but do NOT cascade (simulates pre-P064 scenario or partial failure).
    ks.revoke(&kek_id, "test-revoke-no-cascade").await.unwrap();

    // DEK is still Active while its parent KEK is Revoked.
    let dek_meta = ks.get(&dek_id).await.unwrap();
    assert_eq!(dek_meta.state, KeyState::Active);

    let keys = storage.list().unwrap();
    let report = citadel_keystore::run_all_checks("/tmp", true, &keys, &[], "memory");

    let violation_check = report
        .checks
        .iter()
        .find(|c| c.name == "no-active-children-under-revoked")
        .expect("check must be present");

    assert_eq!(
        violation_check.status,
        citadel_keystore::CheckStatus::Fail,
        "doctor must surface Fail when Active child has Revoked parent"
    );
    assert!(
        violation_check.detail.contains("Active") || violation_check.detail.contains("Revoked"),
        "detail must mention the violation: {}",
        violation_check.detail
    );
}

// ─── P089: Redis poisoning — corrupted ciphertext must not block legitimate one ───

#[tokio::test]
async fn p089_corrupted_ciphertext_does_not_poison_replay_slot() {
    // This test proves the anti-poisoning guarantee holds with claim()/release():
    // A corrupted ciphertext (same nonce + same tag) fails decrypt but does NOT
    // permanently block the legitimate ciphertext.
    //
    // Uses a mock store that simulates the correct behavior:
    //   claim()   = atomically reserves the slot (replay rejected if already claimed)
    //   release() = called only on decrypt failure (ciphertext poisoning prevention)
    use citadel_keystore::{ReplayError, ReplayStore};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    // Mock store: atomic claim/release — tracks claimed keys and call counts.
    #[derive(Clone)]
    struct TrackingStore {
        claimed_keys: Arc<Mutex<std::collections::HashSet<Vec<u8>>>>,
        claim_called: Arc<Mutex<usize>>,
        release_called: Arc<Mutex<usize>>,
    }
    impl ReplayStore for TrackingStore {
        fn claim(&self, key: &[u8], _ttl: Duration) -> Result<bool, ReplayError> {
            *self.claim_called.lock().unwrap() += 1;
            let mut keys = self.claimed_keys.lock().unwrap();
            if keys.contains(key) {
                return Ok(false); // replay detected
            }
            keys.insert(key.to_vec());
            Ok(true) // slot claimed
        }
        fn release(&self, key: &[u8]) -> Result<(), ReplayError> {
            *self.release_called.lock().unwrap() += 1;
            self.claimed_keys.lock().unwrap().remove(key);
            Ok(())
        }
    }

    let claimed_keys = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let claim_called = Arc::new(Mutex::new(0usize));
    let release_called = Arc::new(Mutex::new(0usize));
    let tracking = TrackingStore {
        claimed_keys: claimed_keys.clone(),
        claim_called: claim_called.clone(),
        release_called: release_called.clone(),
    };

    // P290: build hierarchy before setting tracking store (generate/activate don't use replay).
    let (storage, audit) = test_store_and_audit();
    // P424: use test_keystore_with_enforcer so enforcer is defined for ks_encrypt/ks_decrypt_result
    let (ks_raw, enforcer) = test_keystore_with_enforcer(storage, audit);
    let mut ks = ks_raw;
    let h = build_hierarchy(&ks).await;
    let dek_id = h.dek;
    ks.set_replay_store(Box::new(tracking));

    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let blob = ks_encrypt(&ks, &enforcer, &dek_id, b"important secret", &aad, &ctx).await;

    // Simulate a corrupted ciphertext: flip a byte in the encrypted body.
    // (Preserves key_id, key_version, nonce, and tag — only body is corrupted.)
    let mut corrupted_blob = blob.clone();
    let ct_hex = &corrupted_blob.ciphertext_hex;
    let mut ct_bytes = hex::decode(ct_hex).unwrap();
    // Corrupt a byte in the middle of the AEAD ciphertext body (after nonce, before tag)
    let mid = 1126 + 6; // nonce_offset + some bytes into body
    if mid < ct_bytes.len().saturating_sub(16) {
        ct_bytes[mid] ^= 0xFF;
    }
    corrupted_blob.ciphertext_hex = hex::encode(&ct_bytes);

    // Attempt decrypt with corrupted ciphertext — must fail (AEAD auth fails).
    let corrupted_result = ks_decrypt_result(&ks, &enforcer, &corrupted_blob, &aad, &ctx).await;
    assert!(
        corrupted_result.is_err(),
        "corrupted ciphertext must fail decryption"
    );

    // P319: With claim+release, corrupted decrypt claims the slot then releases it on failure.
    // release() must have been called once (slot freed so legitimate blob can proceed).
    assert_eq!(
        *release_called.lock().unwrap(),
        1,
        "release must be called exactly once after failed decrypt — slot freed for legitimate blob"
    );

    // Legitimate ciphertext must still decrypt successfully (slot was released).
    let legit_result = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert!(
        legit_result.is_ok(),
        "legitimate ciphertext must succeed after corrupted-ciphertext attempt: {:?}",
        legit_result
    );
    assert_eq!(legit_result.unwrap(), b"important secret");

    // claim was called twice total (once for corrupted, once for legitimate).
    // release was called once (only for the corrupted/failed decrypt).
    assert_eq!(
        *claim_called.lock().unwrap(),
        2,
        "claim must be called twice: once for corrupted blob, once for legitimate blob"
    );
    assert_eq!(
        *release_called.lock().unwrap(),
        1,
        "release must be called exactly once — only on the failed corrupt decrypt"
    );

    // True replay of the same blob must be rejected (slot is claimed, not released).
    let replay_result = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert!(
        replay_result.is_err(),
        "true replay must be rejected — slot still claimed"
    );
}

// ─── P326: Concurrent keystore replay atomicity — real proof under load ──────

#[tokio::test]
async fn p089_keystore_concurrent_replay_atomicity_1000() {
    // P326/P424: Prove ReplayStore::claim() is atomic under 1000 concurrent decrypts.
    // Exactly 1 of 1000 concurrent attempts must succeed; all others must be denied.
    use std::sync::Arc;
    use tokio::task;

    let (storage, audit) = test_store_and_audit();
    // P424: Use test_keystore_with_enforcer — enforcer must be bound (P384 fail-closed).
    let (ks_inner, enforcer) = test_keystore_with_enforcer(storage, audit);
    let ks = Arc::new(ks_inner);
    // enforcer is already SharedEnforcer = Arc<RwLock<StateEnforcer>> — do NOT re-wrap

    let h = build_hierarchy(&ks).await;
    let dek_id = h.dek;

    let aad = Aad::raw(b"concurrent-replay-aad");
    let ctx = Context::raw(b"concurrent-replay-ctx");
    let blob = Arc::new(
        ks_encrypt(
            &ks,
            &enforcer,
            &dek_id,
            b"concurrent-replay-secret",
            &aad,
            &ctx,
        )
        .await,
    );

    let mut handles = vec![];
    for _ in 0..1000 {
        let ks_clone = Arc::clone(&ks);
        let enforcer_clone = Arc::clone(&enforcer);
        let blob_clone = Arc::clone(&blob);
        handles.push(task::spawn(async move {
            ks_decrypt_result(
                &ks_clone,
                &enforcer_clone,
                &*blob_clone,
                &Aad::raw(b"concurrent-replay-aad"),
                &Context::raw(b"concurrent-replay-ctx"),
            )
            .await
            .is_ok()
        }));
    }

    let mut success_count = 0usize;
    for handle in handles {
        if handle.await.unwrap() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 1,
        "P326: ReplayStore::claim() must be atomic — exactly 1 of 1000 concurrent decrypts must succeed, got {}.",
        success_count
    );
}

// ─── P091: Production replay enforcement ─────────────────────────────────────

#[test]
fn p091_production_env_requires_persistent_replay_store() {
    // Verify the logic: CITADEL_ENV=production without CITADEL_REPLAY_STORE
    // is treated as a configuration error. We can't call process::exit in tests,
    // so we check the condition that would trigger it.
    let env_is_production = std::env::var("CITADEL_ENV").as_deref() == Ok("production");
    let replay_store_set = std::env::var("CITADEL_REPLAY_STORE").is_ok();

    // In a correctly configured production deployment:
    // if env_is_production && !replay_store_set → should exit(1)
    // We verify the condition is detectable, not that exit() is called.
    if env_is_production && !replay_store_set {
        // This is the condition that triggers the fatal error in create_keystore().
        // If we're somehow running tests with production env and no replay store,
        // that itself is a misconfiguration.
        panic!("Test environment has CITADEL_ENV=production without CITADEL_REPLAY_STORE — misconfiguration");
    }
    // If not in production, or replay store is set, the condition is not triggered.
    // This test documents the requirement and passes in normal test environments.
}

// ─── P092/P093: Migration planner named hierarchy and CLI pre-resolution ──────

#[tokio::test]
async fn p093_migration_planner_checks_named_hierarchy() {
    use citadel_keystore::{migration::MigrationOptions, plan_migration};

    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage.clone(), audit);

    // P293: P211 requires KEK to have a Domain parent.
    // Create other-root → other-domain → other-kek.
    // None of these names match the migration target names, preserving test intent.
    let other_root = ks
        .generate("other-root", KeyType::Root, None, None)
        .await
        .expect("generate other-root");
    ks.activate(&other_root).await.unwrap();

    let other_domain = ks
        .generate(
            "other-domain",
            KeyType::Domain,
            None,
            Some(other_root.clone()),
        )
        .await
        .expect("generate other-domain");
    ks.activate(&other_domain).await.unwrap();

    // other-kek under other-domain (satisfies P211, does NOT satisfy "default-kek" name check).
    let other_kek = ks
        .generate(
            "other-kek",
            KeyType::KeyEncrypting,
            None,
            Some(other_domain),
        )
        .await
        .expect("generate other-kek");
    ks.activate(&other_kek).await.unwrap();

    let all_keys = storage.list().unwrap();
    let opts = MigrationOptions::default(); // wants "default-root", "default-domain", "default-kek"

    let plan = plan_migration(&all_keys, &opts);

    // With P093 fix: planner checks by name, so "other-root" does NOT satisfy
    // the requirement for "default-root". The plan must create all three.
    assert!(
        plan.keys_to_create.iter().any(|k| k.name == "default-root"),
        "plan must create 'default-root' even though 'other-root' exists"
    );
    assert!(
        plan.keys_to_create.iter().any(|k| k.name == "default-kek"),
        "plan must create 'default-kek' even though 'other-kek' exists"
    );
}

#[tokio::test]
async fn p093_migration_planner_skips_creation_when_named_key_exists() {
    use citadel_keystore::{migration::MigrationOptions, plan_migration};

    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage.clone(), audit);

    // Create EXACTLY the named target hierarchy.
    let opts = MigrationOptions::default();
    let root = ks
        .generate(&opts.root_name, KeyType::Root, None, None)
        .await
        .unwrap();
    ks.activate(&root).await.unwrap();
    let domain = ks
        .generate(&opts.domain_name, KeyType::Domain, None, Some(root.clone()))
        .await
        .unwrap();
    ks.activate(&domain).await.unwrap();
    let kek = ks
        .generate(
            &opts.kek_name,
            KeyType::KeyEncrypting,
            None,
            Some(domain.clone()),
        )
        .await
        .unwrap();
    ks.activate(&kek).await.unwrap();

    let all_keys = storage.list().unwrap();
    let plan = plan_migration(&all_keys, &opts);

    // Named keys exist → nothing to create.
    assert!(
        plan.keys_to_create.is_empty(),
        "plan must not create new keys when named hierarchy already exists: {:?}",
        plan.keys_to_create
    );
}

// ─── P162: Keystore-layer adversarial tests ──────────────────────────────────

#[tokio::test]
async fn p162_malformed_ciphertext_hex_returns_err_not_panic() {
    // Decrypting a blob with a truncated or invalid ciphertext_hex must return
    // Err, not panic. Fuzz-safety at the keystore layer (not just envelope).
    // P290/P291: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let dek = h.dek;

    let aad = Aad::raw(b"test");
    let ctx = Context::raw(b"ctx");
    let real_blob = ks_encrypt(&ks, &enforcer, &dek, b"hello", &aad, &ctx).await;

    // Truncated ciphertext
    let mut truncated = real_blob.clone();
    truncated.ciphertext_hex = truncated.ciphertext_hex[..10].to_string();
    let result = ks_decrypt_result(&ks, &enforcer, &truncated, &aad, &ctx).await;
    assert!(result.is_err(), "truncated ciphertext must return Err");

    // Not valid hex at all
    let mut garbage = real_blob.clone();
    garbage.ciphertext_hex = "not-hex-at-all-!!!".to_string();
    let result = ks_decrypt_result(&ks, &enforcer, &garbage, &aad, &ctx).await;
    assert!(result.is_err(), "non-hex ciphertext_hex must return Err");

    // Empty ciphertext
    let mut empty = real_blob.clone();
    empty.ciphertext_hex = "".to_string();
    let result = ks_decrypt_result(&ks, &enforcer, &empty, &aad, &ctx).await;
    assert!(result.is_err(), "empty ciphertext_hex must return Err");
}

#[tokio::test]
async fn p162_wrong_key_id_returns_err_not_panic() {
    // Decrypting with a key_id that doesn't exist must return Err, not panic or crash.
    // P290/P291: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let dek = h.dek;

    let aad = Aad::raw(b"test");
    let ctx = Context::raw(b"ctx");
    let mut blob = ks_encrypt(&ks, &enforcer, &dek, b"hello", &aad, &ctx).await;

    // Wrong key ID
    blob.key_id = "totally-wrong-key-id".to_string();
    let result = ks_decrypt_result(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert!(result.is_err(), "wrong key_id must return Err");
}

#[tokio::test]
async fn p162_wrong_aad_returns_err_not_panic() {
    // Decrypting with wrong AAD must return authenticated decryption failure.
    // Must not panic or leak plaintext.
    // P290/P291: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let dek = h.dek;

    let aad_seal = Aad::raw(b"correct-aad");
    let aad_open = Aad::raw(b"wrong-aad");
    let ctx = Context::raw(b"ctx");

    let blob = ks_encrypt(&ks, &enforcer, &dek, b"secret", &aad_seal, &ctx).await;
    let result = ks_decrypt_result(&ks, &enforcer, &blob, &aad_open, &ctx).await;
    assert!(result.is_err(), "wrong AAD must return Err");
}

#[tokio::test]
async fn p162_random_bytes_as_ciphertext_never_returns_plaintext() {
    // Pure random bytes as ciphertext_hex must always fail — never produce
    // valid-looking output. Probabilistic: failure probability 1 - 2^-128.
    // P290/P291: use full hierarchy.
    let (storage, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(storage, audit);
    let h = build_hierarchy(&ks).await;
    let dek = h.dek;

    let aad = Aad::raw(b"test");
    let ctx = Context::raw(b"ctx");
    let real_blob = ks_encrypt(&ks, &enforcer, &dek, b"hello", &aad, &ctx).await;

    use getrandom::getrandom;
    for _ in 0..20 {
        let mut random_ct = vec![0u8; 1200];
        getrandom(&mut random_ct).unwrap();
        let mut garbage = real_blob.clone();
        garbage.ciphertext_hex = hex::encode(&random_ct);
        let result = ks_decrypt_result(&ks, &enforcer, &garbage, &aad, &ctx).await;
        assert!(
            result.is_err(),
            "random bytes as ciphertext must always fail authenticated decryption"
        );
    }
}

// ─── P160: Adversarial keystore tests ────────────────────────────────────────

#[tokio::test]
async fn p160_truncated_blob_must_fail_not_panic() {
    // P291: replace flat DEK with full hierarchy — P225 domain resolution fires at encrypt time.
    let (store, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(store, audit);
    let h = build_hierarchy(&ks).await;
    let dek = h.dek;

    let aad = Aad::raw(b"test");
    let ctx = Context::raw(b"ctx");
    let real_blob = ks_encrypt(&ks, &enforcer, &dek, b"hello", &aad, &ctx).await;

    // Truncate the ciphertext hex to just 10 characters
    let mut truncated = real_blob.clone();
    truncated.ciphertext_hex =
        real_blob.ciphertext_hex[..10.min(real_blob.ciphertext_hex.len())].to_string();
    let result = ks_decrypt_result(&ks, &enforcer, &truncated, &aad, &ctx).await;
    assert!(result.is_err(), "truncated ciphertext must fail, not panic");

    // Empty ciphertext
    let mut empty = real_blob.clone();
    empty.ciphertext_hex = String::new();
    let result = ks_decrypt_result(&ks, &enforcer, &empty, &aad, &ctx).await;
    assert!(result.is_err(), "empty ciphertext must fail, not panic");
}

#[tokio::test]
async fn p160_non_hex_ciphertext_must_fail_not_panic() {
    // P291: replace flat DEK with full hierarchy.
    let (store, audit) = test_store_and_audit();
    let (ks, enforcer) = test_keystore_with_enforcer(store, audit);
    let h = build_hierarchy(&ks).await;
    let dek = h.dek;

    let aad = Aad::raw(b"test");
    let ctx = Context::raw(b"ctx");
    let real_blob = ks_encrypt(&ks, &enforcer, &dek, b"hello", &aad, &ctx).await;

    // Non-hex garbage in ciphertext field
    let mut garbage = real_blob.clone();
    garbage.ciphertext_hex = "not-hex-at-all!@#$%^&*()".to_string();
    let result = ks_decrypt_result(&ks, &enforcer, &garbage, &aad, &ctx).await;
    assert!(result.is_err(), "non-hex ciphertext must fail, not panic");

    // Valid hex but for a different key
    garbage.ciphertext_hex = "deadbeef".repeat(150);
    let result = ks_decrypt_result(&ks, &enforcer, &garbage, &aad, &ctx).await;
    assert!(
        result.is_err(),
        "wrong-length hex must fail authenticated decryption"
    );
}

// ─── P211 — Strict hierarchy enforcement tests ────────────────────────────────
//
// These tests verify that generate() rejects every invalid parent/child
// relationship using can_wrap(). No CITADEL_ALLOW_FLAT_DEKS override is set,
// so the strict enforcement path runs.

/// P290/P291: Shared hierarchy fixture for tests that need to call encrypt().
///
/// P211 enforces Root→Domain→KEK→DEK at generate time.
/// P225 resolves domain ancestor at encrypt time.
/// Flat KEKs/DEKs fail at one or both gates.
/// All tests that create real blobs must use this fixture.
#[allow(dead_code)]
struct TestHierarchy {
    root: KeyId,
    domain: KeyId,
    kek: KeyId,
    dek: KeyId,
}

async fn build_hierarchy(ks: &Keystore) -> TestHierarchy {
    let root = ks
        .generate("root", KeyType::Root, None, None)
        .await
        .expect("build_hierarchy: generate root");
    ks.activate(&root)
        .await
        .expect("build_hierarchy: activate root");

    let domain = ks
        .generate("domain", KeyType::Domain, None, Some(root.clone()))
        .await
        .expect("build_hierarchy: generate domain");
    ks.activate(&domain)
        .await
        .expect("build_hierarchy: activate domain");

    let kek = ks
        .generate("kek", KeyType::KeyEncrypting, None, Some(domain.clone()))
        .await
        .expect("build_hierarchy: generate kek");
    ks.activate(&kek)
        .await
        .expect("build_hierarchy: activate kek");

    let dek = ks
        .generate("dek", KeyType::DataEncrypting, None, Some(kek.clone()))
        .await
        .expect("build_hierarchy: generate dek");
    ks.activate(&dek)
        .await
        .expect("build_hierarchy: activate dek");

    TestHierarchy {
        root,
        domain,
        kek,
        dek,
    }
}

fn strict_keystore() -> Keystore {
    // No CITADEL_ALLOW_FLAT_DEKS — strict mode.
    // Still need CITADEL_MASTER_KEY for key wrapping.
    let master_key = [0xAB_u8; 32];
    let storage = Arc::new(InMemoryBackend::new());
    let audit = Arc::new(InMemoryAuditSink::new());
    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
    Keystore::with_master_key(
        storage as Arc<dyn StorageBackend>,
        audit as Arc<dyn AuditSinkSync>,
        master_key,
    )
}

#[tokio::test]
async fn p211_root_with_parent_is_rejected() {
    // Root must have no parent. Giving it any parent is a hierarchy violation.
    // To create a parent we use flat_override, then try to create Root under it.
    //
    // P305: P214 requires BOTH CITADEL_ALLOW_FLAT_DEKS=1 AND CITADEL_ENV=development.
    // The original test only set ALLOW_FLAT_DEKS, so fake_parent creation failed before
    // reaching the actual assertion. Also hold ENV_LOCK (P302) for env var safety.
    // P305/PoisonFix: Drop ENV_LOCK before async generate() — std::sync::Mutex must not
    // be held across .await. Set vars, drop lock, generate, re-acquire to clean up.
    {
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("CITADEL_ALLOW_FLAT_DEKS", "1");
        std::env::set_var("CITADEL_ENV", "development");
    } // lock released before await points

    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage, audit);

    // Create a Domain key that we'll (wrongly) use as a Root parent.
    let fake_parent = ks
        .generate("fake-parent", KeyType::Domain, None, None)
        .await
        .unwrap();

    // Re-acquire to clean up env vars
    {
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
        std::env::remove_var("CITADEL_ENV");
    }

    let result = ks
        .generate("bad-root", KeyType::Root, None, Some(fake_parent))
        .await;
    assert!(
        result.is_err(),
        "Root with a parent must be rejected — nothing can_wrap Root"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("hierarchy") || msg.contains("cannot be a child"),
        "error must name the hierarchy violation, got: {}",
        msg
    );
}

#[tokio::test]
async fn p211_kek_under_root_is_rejected() {
    // Root→KEK is the core gap identified by the reviewer.
    // can_wrap() says only Root→DomainKek and DomainKek→Kek are valid.
    // Root→Kek must be rejected in strict mode.
    std::env::set_var("CITADEL_ALLOW_FLAT_DEKS", "1");
    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage, audit);

    let root = ks
        .generate("root", KeyType::Root, None, None)
        .await
        .unwrap();
    ks.activate(&root).await.unwrap();

    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
    let result = ks
        .generate("bad-kek", KeyType::KeyEncrypting, None, Some(root))
        .await;
    assert!(
        result.is_err(),
        "KEK under Root must be rejected — Root can only wrap Domain"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("hierarchy") || msg.contains("cannot be a child"),
        "error must name the hierarchy violation, got: {}",
        msg
    );
}

#[tokio::test]
async fn p211_domain_under_kek_is_rejected() {
    // KEK→Domain is invalid. Domain must hang under Root.
    std::env::set_var("CITADEL_ALLOW_FLAT_DEKS", "1");
    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage, audit);

    let root = ks
        .generate("root", KeyType::Root, None, None)
        .await
        .unwrap();
    ks.activate(&root).await.unwrap();
    let domain = ks
        .generate("domain", KeyType::Domain, None, Some(root.clone()))
        .await
        .unwrap();
    ks.activate(&domain).await.unwrap();
    let kek = ks
        .generate("kek", KeyType::KeyEncrypting, None, Some(domain.clone()))
        .await
        .unwrap();
    ks.activate(&kek).await.unwrap();

    // Try Domain under KEK — structurally wrong
    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
    let result = ks
        .generate("bad-domain", KeyType::Domain, None, Some(kek))
        .await;
    assert!(
        result.is_err(),
        "Domain under KEK must be rejected — only Root can wrap Domain"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("hierarchy") || msg.contains("cannot be a child"),
        "error must name the hierarchy violation, got: {}",
        msg
    );
}

#[tokio::test]
async fn p211_dek_under_domain_directly_is_rejected() {
    // DEK under Domain skips the KEK level. can_wrap() requires Kek→Dek only.
    // The previous code allowed Domain as a DEK parent (line 718: KeyEncrypting | Domain).
    // That is now rejected.
    std::env::set_var("CITADEL_ALLOW_FLAT_DEKS", "1");
    let (storage, audit) = test_store_and_audit();
    let (ks, _enforcer) = test_keystore_with_enforcer(storage, audit);

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

    // DEK directly under Domain — skips KEK level
    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
    let result = ks
        .generate("bad-dek", KeyType::DataEncrypting, None, Some(domain))
        .await;
    assert!(
        result.is_err(),
        "DEK under Domain must be rejected — only KEK can wrap DEK"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("hierarchy") || msg.contains("cannot be a child"),
        "error must name the hierarchy violation, got: {}",
        msg
    );
}

#[tokio::test]
async fn p211_correct_full_hierarchy_is_accepted() {
    // Root→Domain→KEK→DEK must all succeed without any override flag.
    // This is the positive case proving the fix doesn't over-restrict.
    let ks = strict_keystore();
    // P434: strict_keystore() returns no enforcer — bind one so ks_encrypt/ks_decrypt work.
    let enforcer = Arc::new(RwLock::new(StateEnforcer::new()));
    let ks = ks.with_enforcer(Arc::clone(&enforcer));

    let root = ks
        .generate("root", KeyType::Root, None, None)
        .await
        .expect("Root with no parent must succeed");
    ks.activate(&root).await.unwrap();

    let domain = ks
        .generate("domain", KeyType::Domain, None, Some(root.clone()))
        .await
        .expect("Domain under Root must succeed");
    ks.activate(&domain).await.unwrap();

    let kek = ks
        .generate("kek", KeyType::KeyEncrypting, None, Some(domain.clone()))
        .await
        .expect("KEK under Domain must succeed");
    ks.activate(&kek).await.unwrap();

    let dek = ks
        .generate("dek", KeyType::DataEncrypting, None, Some(kek.clone()))
        .await
        .expect("DEK under KEK must succeed");
    ks.activate(&dek).await.unwrap();

    // Verify the hierarchy is actually functional end-to-end
    let aad = Aad::raw(b"p211-aad");
    let ctx = Context::raw(b"p211-ctx");
    let blob = ks_encrypt(&ks, &enforcer, &dek, b"strict hierarchy works", &aad, &ctx).await;
    let pt = ks_decrypt(&ks, &enforcer, &blob, &aad, &ctx).await;
    assert_eq!(pt, b"strict hierarchy works");
}

// P220: resolve_domain_for_key() helper
// P286: Fixed get_keystore() → strict_keystore() and corrected generate() arity (4 args).
#[tokio::test]
async fn p220_resolve_domain_for_key_works() {
    let ks = strict_keystore();

    // Create hierarchy: Root → Domain → KEK → DEK
    // generate(name, key_type, policy_id, parent_id)
    let root = ks
        .generate("root-key", KeyType::Root, None, None)
        .await
        .unwrap();
    ks.activate(&root).await.unwrap();

    let domain = ks
        .generate("domain-key", KeyType::Domain, None, Some(root.clone()))
        .await
        .unwrap();
    ks.activate(&domain).await.unwrap();

    let kek = ks
        .generate(
            "kek-key",
            KeyType::KeyEncrypting,
            None,
            Some(domain.clone()),
        )
        .await
        .unwrap();
    ks.activate(&kek).await.unwrap();

    let dek = ks
        .generate("dek-key", KeyType::DataEncrypting, None, Some(kek.clone()))
        .await
        .unwrap();
    ks.activate(&dek).await.unwrap();

    // Test: Domain resolves to itself
    let resolved = ks.resolve_domain_for_key(&domain).await.unwrap();
    assert_eq!(resolved, domain);

    // Test: KEK resolves to its parent Domain
    let resolved = ks.resolve_domain_for_key(&kek).await.unwrap();
    assert_eq!(resolved, domain);

    // Test: DEK resolves to Domain (walks DEK → KEK → Domain)
    let resolved = ks.resolve_domain_for_key(&dek).await.unwrap();
    assert_eq!(resolved, domain);

    // Test: Root has no Domain ancestor (should error)
    let result = ks.resolve_domain_for_key(&root).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Root key has no Domain ancestor"));
}
