//! P217 — multi-tenant domain isolation tests (Phase 1: crypto-layer boundary).
//!
//! Verifies that an operation authorized for one Domain cannot touch a key in
//! another Domain, at BOTH enforcement layers:
//!   1. StateEnforcer — authorization for a key claiming the wrong domain is denied.
//!   2. Keystore (defense in depth) — even a context that passed the enforcer is
//!      refused if the key's REAL hierarchy Domain differs from the authorized one.

use std::sync::Arc;

use citadel_core::StateEnforcer;
use citadel_envelope::{Aad, Context};
use citadel_keystore::{
    AuditSinkSync, InMemoryAuditSink, InMemoryBackend, KeyId, KeyType, Keystore, StorageBackend,
};
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

type Enf = Arc<RwLock<StateEnforcer>>;

fn make() -> (Keystore, Enf) {
    let storage = Arc::new(InMemoryBackend::new());
    let audit = Arc::new(InMemoryAuditSink::new());
    let enf = Arc::new(RwLock::new(StateEnforcer::new()));
    let ks = Keystore::with_master_key(
        storage as Arc<dyn StorageBackend>,
        audit as Arc<dyn AuditSinkSync>,
        [0x11_u8; 32],
    )
    .with_enforcer(Arc::clone(&enf));
    (ks, enf)
}

/// Build Root -> Domain -> KEK -> DEK; activate the DEK. Returns (domain_id, dek_id).
async fn chain(ks: &Keystore, tag: &str) -> (KeyId, KeyId) {
    let root = ks
        .generate(format!("{tag}-root"), KeyType::Root, None, None)
        .await
        .unwrap();
    let dom = ks
        .generate(
            format!("{tag}-dom"),
            KeyType::Domain,
            None,
            Some(root.clone()),
        )
        .await
        .unwrap();
    let kek = ks
        .generate(
            format!("{tag}-kek"),
            KeyType::KeyEncrypting,
            None,
            Some(dom.clone()),
        )
        .await
        .unwrap();
    let dek = ks
        .generate(
            format!("{tag}-dek"),
            KeyType::DataEncrypting,
            None,
            Some(kek.clone()),
        )
        .await
        .unwrap();
    ks.activate(&dek).await.unwrap();
    (dom, dek)
}

/// Layer 1: the enforcer denies authorizing a domain-B key under domain A.
#[test]
fn enforcer_rejects_cross_domain_authorization() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
        let (ks, enf) = make();
        let (dom_a, dek_a) = chain(&ks, "a").await;
        let (dom_b, dek_b) = chain(&ks, "b").await;
        let (da, db) = (dom_a.to_string(), dom_b.to_string());
        let (dka, dkb) = (dek_a.to_string(), dek_b.to_string());

        {
            let mut e = enf.write().await;
            e.register_key(dka.clone(), Some(da.clone()));
            e.register_key(dkb.clone(), Some(db.clone()));
        }
        let e = enf.read().await;
        // DEK_B authorized under Domain A must be denied.
        assert!(
            e.authorize_encrypt(&dkb, Some(&da), None).is_err(),
            "cross-domain authorization (domain-B key under domain A) must be denied"
        );
        // The same-domain authorization is allowed.
        assert!(
            e.authorize_encrypt(&dka, Some(&da), None).is_ok(),
            "same-domain authorization must be allowed"
        );
    });
}

/// Layer 2: the keystore refuses a context whose domain != the key's real Domain,
/// even though the (deliberately mis-populated) enforcer authorized it.
#[test]
fn keystore_rejects_domain_mismatch() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
        let (ks, enf) = make();
        let (_dom_a, dek_a) = chain(&ks, "a").await;
        let dka = dek_a.to_string();

        // Enforcer is told DEK_A is in "fake-domain" (a wrong/malicious claim); it
        // then authorizes under that fake domain.
        let ctx = {
            let mut e = enf.write().await;
            e.register_key(dka.clone(), Some("fake-domain".to_string()));
            e.authorize_encrypt(&dka, Some("fake-domain"), None)
                .unwrap()
        };

        // The keystore independently resolves DEK_A's REAL Domain and rejects.
        let aad = Aad::raw(b"a");
        let cx = Context::raw(b"c");
        let r = ks.encrypt_authorized(&ctx, b"pt", &aad, &cx).await;
        assert!(
            r.is_err(),
            "keystore must reject a context whose domain != key's real hierarchy domain"
        );
        let msg = format!("{:?}", r.err().unwrap()).to_lowercase();
        assert!(
            msg.contains("domain"),
            "rejection should be domain-related: {msg}"
        );
    });
}

/// A correctly domain-scoped operation still succeeds (no false rejection).
#[test]
fn matched_domain_operation_succeeds() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
        let (ks, enf) = make();
        let (dom_a, dek_a) = chain(&ks, "a").await;
        let (da, dka) = (dom_a.to_string(), dek_a.to_string());

        let ctx = {
            let mut e = enf.write().await;
            e.register_key(dka.clone(), Some(da.clone()));
            e.authorize_encrypt(&dka, Some(&da), None).unwrap()
        };

        let aad = Aad::raw(b"a");
        let cx = Context::raw(b"c");
        let r = ks.encrypt_authorized(&ctx, b"pt", &aad, &cx).await;
        assert!(
            r.is_ok(),
            "same-domain authorized encrypt must succeed: {:?}",
            r.err()
        );
    });
}
