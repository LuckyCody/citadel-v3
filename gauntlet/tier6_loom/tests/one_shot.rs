// Tier 6 — Loom exhaustive interleaving check of the one-shot capability nonce.
//
// Models citadel-core `state_enforcer`: issued capability nonces live in a
// Mutex-guarded set; `validate` removes the nonce and succeeds iff it was
// present, making each token single-use. Loom explores EVERY thread
// interleaving (not a probabilistic stress run) and checks the invariants.
//
// Run:  RUSTFLAGS="--cfg loom" cargo test --release

use loom::sync::{Arc, Mutex};
use loom::thread;
use std::collections::HashSet;

/// Two threads validate the SAME issued token concurrently.
/// Invariant: EXACTLY ONE succeeds — no double-spend, no lost token, no deadlock.
#[test]
fn one_shot_nonce_no_double_spend() {
    loom::model(|| {
        let issued = Arc::new(Mutex::new(HashSet::<u128>::new()));
        issued.lock().unwrap().insert(0xC0FFEE);

        let i1 = issued.clone();
        let t1 = thread::spawn(move || i1.lock().unwrap().remove(&0xC0FFEE));
        let i2 = issued.clone();
        let t2 = thread::spawn(move || i2.lock().unwrap().remove(&0xC0FFEE));

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // XOR: exactly one consumed the token.
        assert!(r1 ^ r2, "one-shot violated: r1={r1} r2={r2}");
        // And the token is gone afterward.
        assert!(!issued.lock().unwrap().contains(&0xC0FFEE));
    });
}

/// A concurrent issuer and validator of DISTINCT tokens must never interfere:
/// the validator's token must remain consumable regardless of interleaving.
#[test]
fn concurrent_issue_and_validate_distinct() {
    loom::model(|| {
        let issued = Arc::new(Mutex::new(HashSet::<u128>::new()));
        issued.lock().unwrap().insert(1u128);

        let i1 = issued.clone();
        let issuer = thread::spawn(move || {
            i1.lock().unwrap().insert(2u128);
        });
        let i2 = issued.clone();
        let validator = thread::spawn(move || i2.lock().unwrap().remove(&1u128));

        issuer.join().unwrap();
        let consumed = validator.join().unwrap();
        assert!(consumed, "validator lost its own token under interleaving");
    });
}
