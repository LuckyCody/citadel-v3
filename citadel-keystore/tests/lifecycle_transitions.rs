//! Stronger key-lifecycle state-machine test.
//!
//! The existing `lifecycle_statemachine.rs` drives random ops but tracks its own
//! model of state — so a bug that (say) reactivates a Revoked key or resurrects a
//! Destroyed one could slip through, because the model just follows the code's
//! result. This test instead uses the keystore's OWN declared state machine
//! (`KeyState::valid_transitions`) as the oracle: it reads the REAL state back
//! after every operation and asserts the code never makes an undeclared
//! transition, never resurrects a terminal key, and never reactivates a revoked
//! one — and that the Root->Domain->KEK->DEK hierarchy cannot be escaped.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use citadel_keystore::{
    AuditSinkSync, InMemoryAuditSink, InMemoryBackend, KeyId, KeyState, KeyType, Keystore,
    StorageBackend,
};
use proptest::prelude::*;
use tokio::runtime::Runtime;

fn make_ks() -> Keystore {
    let storage = Arc::new(InMemoryBackend::new());
    let audit = Arc::new(InMemoryAuditSink::new());
    Keystore::with_master_key(
        storage as Arc<dyn StorageBackend>,
        audit as Arc<dyn AuditSinkSync>,
        [0x5A_u8; 32],
    )
}

async fn state_of(ks: &Keystore, id: &KeyId) -> Option<KeyState> {
    ks.get(id).await.ok().map(|m| m.state)
}

/// Build the canonical valid hierarchy Root -> Domain -> KEK -> DEK.
async fn build_chain(ks: &Keystore) -> Vec<KeyId> {
    let root = ks
        .generate("root", KeyType::Root, None, None)
        .await
        .unwrap();
    let domain = ks
        .generate("domain", KeyType::Domain, None, Some(root.clone()))
        .await
        .unwrap();
    let kek = ks
        .generate("kek", KeyType::KeyEncrypting, None, Some(domain.clone()))
        .await
        .unwrap();
    let dek = ks
        .generate("dek", KeyType::DataEncrypting, None, Some(kek.clone()))
        .await
        .unwrap();
    vec![root, domain, kek, dek]
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Activate,
    Rotate,
    Revoke,
    Expire,
    Destroy,
}

fn op_strategy() -> impl Strategy<Value = (usize, Op)> {
    (
        0..4usize,
        prop_oneof![
            Just(Op::Activate),
            Just(Op::Rotate),
            Just(Op::Revoke),
            Just(Op::Expire),
            Just(Op::Destroy),
        ],
    )
}

/// Drive the real keystore through the op sequence. Returns Some(message) on the
/// first invariant violation, else None.
async fn run(ops: Vec<(usize, Op)>) -> Option<String> {
    // Hierarchy enforcement must be ON (the dev override needs this env var).
    std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");

    let ks = make_ks();
    let chain = build_chain(&ks).await;

    let mut ever_destroyed: HashSet<String> = HashSet::new();
    let mut ever_revoked: HashSet<String> = HashSet::new();
    let mut _last: HashMap<String, KeyState> = HashMap::new();

    for (idx, op) in ops {
        let id = &chain[idx % chain.len()];
        let key = id.to_string();
        let before = state_of(&ks, id).await;

        match op {
            Op::Activate => {
                let _ = ks.activate(id).await;
            }
            Op::Rotate => {
                let _ = ks.rotate(id).await;
            }
            Op::Revoke => {
                let _ = ks.revoke(id, "prop").await;
            }
            Op::Expire => {
                let _ = ks.expire(id).await;
            }
            Op::Destroy => {
                let _ = ks.destroy(id).await;
            }
        }

        let after = state_of(&ks, id).await;

        if let (Some(b), Some(a)) = (before, after) {
            // INVARIANT 1: any state change must be a declared-valid transition.
            if b != a && !b.can_transition_to(a) {
                return Some(format!(
                    "ILLEGAL TRANSITION {b:?} -> {a:?} on key {key} via {op:?}"
                ));
            }
            if a == KeyState::Destroyed {
                ever_destroyed.insert(key.clone());
            }
            if a == KeyState::Revoked {
                ever_revoked.insert(key.clone());
            }
            // INVARIANT 2: Destroyed is terminal — never observed otherwise again.
            if ever_destroyed.contains(&key) && a != KeyState::Destroyed {
                return Some(format!("RESURRECTION: destroyed key {key} observed {a:?}"));
            }
            // INVARIANT 3: a Revoked key is never reactivated to Active.
            if ever_revoked.contains(&key) && a == KeyState::Active {
                return Some(format!("REACTIVATION: revoked key {key} became Active"));
            }
            _last.insert(key, a);
        }
    }
    None
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// The real keystore never violates its own declared state machine, never
    /// resurrects a Destroyed key, and never reactivates a Revoked one.
    #[test]
    fn transitions_obey_declared_machine(
        ops in prop::collection::vec(op_strategy(), 5..40)
    ) {
        let rt = Runtime::new().unwrap();
        let violation = rt.block_on(run(ops));
        prop_assert!(violation.is_none(), "{}", violation.unwrap_or_default());
    }
}

/// The Root -> Domain -> KEK -> DEK hierarchy cannot be escaped at generation.
#[test]
fn hierarchy_escape_is_rejected() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
        let ks = make_ks();

        // The valid chain succeeds.
        let root = ks
            .generate("root", KeyType::Root, None, None)
            .await
            .unwrap();
        let domain = ks
            .generate("domain", KeyType::Domain, None, Some(root.clone()))
            .await
            .unwrap();
        let kek = ks
            .generate("kek", KeyType::KeyEncrypting, None, Some(domain.clone()))
            .await
            .unwrap();

        // Illegal parent/child pairings must be rejected.
        assert!(
            ks.generate("bad", KeyType::DataEncrypting, None, Some(root.clone()))
                .await
                .is_err(),
            "DEK directly under Root must be rejected"
        );
        assert!(
            ks.generate("bad", KeyType::Domain, None, None)
                .await
                .is_err(),
            "Domain with no parent must be rejected"
        );
        assert!(
            ks.generate("bad", KeyType::Root, None, Some(domain.clone()))
                .await
                .is_err(),
            "Root with a parent must be rejected"
        );
        assert!(
            ks.generate("bad", KeyType::KeyEncrypting, None, Some(kek.clone()))
                .await
                .is_err(),
            "KEK under a KEK must be rejected"
        );
    });
}

/// Revoked and Destroyed are terminal: no operation resurrects or reactivates.
#[test]
fn revoked_and_destroyed_are_terminal() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        std::env::remove_var("CITADEL_ALLOW_FLAT_DEKS");
        let ks = make_ks();
        let r = ks.generate("r", KeyType::Root, None, None).await.unwrap();

        ks.activate(&r).await.unwrap();
        ks.revoke(&r, "test").await.unwrap();
        assert_eq!(state_of(&ks, &r).await, Some(KeyState::Revoked));

        // Attempt reactivation — must NOT become Active.
        let _ = ks.activate(&r).await;
        assert_ne!(
            state_of(&ks, &r).await,
            Some(KeyState::Active),
            "revoked key must not be reactivatable"
        );

        // Revoked -> Destroyed is the only declared exit; then it is terminal.
        ks.destroy(&r).await.unwrap();
        assert_eq!(state_of(&ks, &r).await, Some(KeyState::Destroyed));
        let _ = ks.activate(&r).await;
        let _ = ks.rotate(&r).await;
        assert_eq!(
            state_of(&ks, &r).await,
            Some(KeyState::Destroyed),
            "destroyed key must stay destroyed"
        );
    });
}
