use citadel_core::StateEnforcer;
use citadel_envelope::{Aad, Context};
use citadel_keystore::{
    AuditSinkSync, InMemoryAuditSink, InMemoryBackend, KeyId, KeyState, KeyType, Keystore,
    StorageBackend,
};
use proptest::prelude::*;
/// Property-based state-machine test for the Citadel key lifecycle.
///
/// Randomly generates sequences of key operations and asserts invariants after
/// each step. If any invariant fails, proptest shrinks to the minimal failing
/// operation sequence.
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

type SharedEnforcer = Arc<RwLock<StateEnforcer>>;

fn make_ks() -> (Keystore, SharedEnforcer) {
    let storage = Arc::new(InMemoryBackend::new());
    let audit = Arc::new(InMemoryAuditSink::new());
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

async fn try_encrypt(
    ks: &Keystore,
    enforcer: &SharedEnforcer,
    key_id: &str,
) -> Result<citadel_keystore::EncryptedBlob, String> {
    let _kid = KeyId::new(key_id);
    let aad = Aad::raw(b"sm-aad");
    let ctx = Context::raw(b"sm-ctx");
    let mut enf = enforcer.write().await;
    enf.register_key(key_id.to_string(), None);
    let auth_ctx = enf
        .authorize_encrypt(key_id, None, None)
        .map_err(|r| format!("{:?}", r))?;
    drop(enf);
    ks.encrypt_authorized(&auth_ctx, b"sm-payload", &aad, &ctx)
        .await
        .map_err(|e| e.to_string())
}

async fn try_decrypt(
    ks: &Keystore,
    enforcer: &SharedEnforcer,
    blob: &citadel_keystore::EncryptedBlob,
) -> Result<Vec<u8>, String> {
    let aad = Aad::raw(b"sm-aad");
    let ctx = Context::raw(b"sm-ctx");
    let mut enf = enforcer.write().await;
    enf.register_key(blob.key_id.clone(), None);
    let auth_ctx = enf
        .authorize_decrypt(&blob.key_id, None)
        .map_err(|r| format!("{:?}", r))?;
    drop(enf);
    ks.decrypt_authorized(&auth_ctx, blob, &aad, &ctx)
        .await
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone)]
enum Op {
    CreateRoot,
    CreateDomain,
    CreateKek,
    CreateDek,
    Activate(usize),
    Rotate(usize),
    Revoke(usize),
    Destroy(usize),
    TryEncrypt(usize),
    TryDecrypt,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => Just(Op::CreateRoot),
        3 => Just(Op::CreateDomain),
        3 => Just(Op::CreateKek),
        5 => Just(Op::CreateDek),
        8 => (0..20usize).prop_map(Op::Activate),
        3 => (0..20usize).prop_map(Op::Rotate),
        4 => (0..20usize).prop_map(Op::Revoke),
        2 => (0..20usize).prop_map(Op::Destroy),
        10 => (0..20usize).prop_map(Op::TryEncrypt),
        5 => Just(Op::TryDecrypt),
    ]
}

struct Model {
    keys: Vec<(String, KeyType, KeyState)>,
    root_id: Option<String>,
    domain_id: Option<String>,
    kek_id: Option<String>,
    last_blob: Option<citadel_keystore::EncryptedBlob>,
}

fn run_ops(ops: Vec<Op>) {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        std::env::set_var("CITADEL_ALLOW_PLAINTEXT_KEYS", "1");
        std::env::set_var("CITADEL_ENV", "development");

        let (ks, enforcer) = make_ks();
        let mut m = Model {
            keys: vec![],
            root_id: None,
            domain_id: None,
            kek_id: None,
            last_blob: None,
        };

        for op in &ops {
            match op {
                Op::CreateRoot if m.root_id.is_none() => {
                    if let Ok(id) = ks.generate("r", KeyType::Root, None, None).await {
                        let s = id.to_string();
                        m.keys.push((s.clone(), KeyType::Root, KeyState::Pending));
                        m.root_id = Some(s);
                    }
                }
                Op::CreateDomain if m.domain_id.is_none() => {
                    if let Some(ref r) = m.root_id {
                        if let Ok(id) = ks
                            .generate("d", KeyType::Domain, None, Some(KeyId::new(r)))
                            .await
                        {
                            let s = id.to_string();
                            m.keys.push((s.clone(), KeyType::Domain, KeyState::Pending));
                            m.domain_id = Some(s);
                        }
                    }
                }
                Op::CreateKek if m.kek_id.is_none() => {
                    if let Some(ref d) = m.domain_id {
                        if let Ok(id) = ks
                            .generate("k", KeyType::KeyEncrypting, None, Some(KeyId::new(d)))
                            .await
                        {
                            let s = id.to_string();
                            m.keys
                                .push((s.clone(), KeyType::KeyEncrypting, KeyState::Pending));
                            m.kek_id = Some(s);
                        }
                    }
                }
                Op::CreateDek => {
                    if let Some(ref k) = m.kek_id {
                        if let Ok(id) = ks
                            .generate("dek", KeyType::DataEncrypting, None, Some(KeyId::new(k)))
                            .await
                        {
                            let s = id.to_string();
                            m.keys.push((s, KeyType::DataEncrypting, KeyState::Pending));
                        }
                    }
                }
                Op::Activate(i) => {
                    if m.keys.is_empty() {
                        continue;
                    }
                    let i = *i % m.keys.len();
                    let kid = KeyId::new(&m.keys[i].0);
                    if ks.activate(&kid).await.is_ok() {
                        m.keys[i].2 = KeyState::Active;
                        enforcer
                            .write()
                            .await
                            .register_key(m.keys[i].0.clone(), None);
                    }
                }
                Op::Rotate(i) => {
                    if m.keys.is_empty() {
                        continue;
                    }
                    let i = *i % m.keys.len();
                    let kid = KeyId::new(&m.keys[i].0);
                    let _ = ks.rotate(&kid).await; // state stays Active
                }
                Op::Revoke(i) => {
                    if m.keys.is_empty() {
                        continue;
                    }
                    let i = *i % m.keys.len();
                    let kid = KeyId::new(&m.keys[i].0);
                    if ks.revoke(&kid, "proptest").await.is_ok() {
                        m.keys[i].2 = KeyState::Revoked;
                        enforcer.write().await.revoke_key(&m.keys[i].0);
                    }
                }
                Op::Destroy(i) => {
                    if m.keys.is_empty() {
                        continue;
                    }
                    let i = *i % m.keys.len();
                    let kid = KeyId::new(&m.keys[i].0);
                    if ks.destroy(&kid).await.is_ok() {
                        m.keys[i].2 = KeyState::Destroyed;
                        enforcer.write().await.revoke_key(&m.keys[i].0);
                    }
                }
                Op::TryEncrypt(i) => {
                    if m.keys.is_empty() {
                        continue;
                    }
                    let i = *i % m.keys.len();
                    let (ref kid, ref ktype, ref kstate) = m.keys[i];

                    let result = try_encrypt(&ks, &enforcer, kid).await;

                    // INVARIANTS
                    if *ktype != KeyType::DataEncrypting && *ktype != KeyType::HybridIdentity {
                        assert!(
                            result.is_err(),
                            "INVARIANT: {} key in {:?} state must NOT encrypt, but it did (key={})",
                            ktype,
                            kstate,
                            kid
                        );
                    }
                    if matches!(
                        kstate,
                        KeyState::Revoked | KeyState::Destroyed | KeyState::Pending
                    ) {
                        assert!(
                            result.is_err(),
                            "INVARIANT: {:?} key must NOT encrypt, but it did (key={}, type={})",
                            kstate,
                            kid,
                            ktype
                        );
                    }
                    if let Ok(blob) = result {
                        m.last_blob = Some(blob);
                    }
                }
                Op::TryDecrypt => {
                    if let Some(ref blob) = m.last_blob {
                        // Find this key's model entry
                        if let Some(entry) = m.keys.iter().find(|(k, _, _)| *k == blob.key_id) {
                            let result = try_decrypt(&ks, &enforcer, blob).await;
                            match entry.2 {
                                KeyState::Destroyed => {
                                    assert!(
                                        result.is_err(),
                                        "INVARIANT: Destroyed key must NOT decrypt (key={})",
                                        entry.0
                                    );
                                }
                                KeyState::Revoked => {
                                    assert!(
                                        result.is_err(),
                                        "INVARIANT: Revoked key must NOT decrypt (key={})",
                                        entry.0
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn lifecycle_random_ops(ops in prop::collection::vec(op_strategy(), 5..30)) {
        run_ops(ops);
    }
}
