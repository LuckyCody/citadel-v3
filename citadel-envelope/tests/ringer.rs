// SPDX-License-Identifier: AGPL-3.0-or-later
//! Packet 059 — adversarial "ringer" suite (feature `ringer`, test-only, no shipping change).
//!
//! Runs on whichever backend is compiled:
//!   `--features ringer`        → RustCrypto (default backend)
//!   `--features ringer,fips`   → AWS-LC (FIPS module)   [needs clang, release]
//!
//! Volume knobs (env) let the outside gate crank it hard without recompiling:
//!   RINGER_ROUNDTRIP_CASES              (default 2000)
//!   RINGER_NONCE_SEALS                  (default 20000)
//!   RINGER_CROSS_CASES                  (default 300)
//!   RINGER_MALLEABILITY_MUTS_PER_BYTE   (default 3)
//!
//! Compiles empty without `--features ringer`.
#![cfg(feature = "ringer")]

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use citadel_envelope::{Aad, Citadel, CitadelP384, Context, OpenError};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Every single-byte mutation and several truncations of a VALID envelope must make `open`
/// return `Err` — never panic, never accept ANY plaintext. Every envelope byte is authenticated
/// (header[..86] is bound in the AEAD associated data; the 12-byte nonce is GCM-authenticated;
/// kem_ct feeds decapsulation; body+tag are AES-GCM), so an accepted mutation is a
/// malleability/auth-bypass finding and a panic is a parse-robustness finding.
fn assert_no_malleability(
    name: &str,
    valid: &[u8],
    expect_pt: &[u8],
    open: impl Fn(&[u8]) -> Result<Vec<u8>, OpenError>,
) {
    match open(valid) {
        Ok(pt) => assert_eq!(
            pt, expect_pt,
            "{name}: pristine envelope opened to the WRONG plaintext"
        ),
        Err(_) => panic!("{name}: pristine envelope failed to open"),
    }
    let muts_per_byte = env_usize("RINGER_MALLEABILITY_MUTS_PER_BYTE", 3);
    let (mut accepted, mut panicked, mut checked) = (0usize, 0usize, 0usize);

    for i in 0..valid.len() {
        for m in 0..muts_per_byte {
            let mut e = valid.to_vec();
            let orig = e[i];
            e[i] = match m {
                0 => orig ^ 0x01,
                1 => orig.wrapping_add(1),
                _ => orig ^ 0xFF,
            };
            if e[i] == orig {
                continue;
            }
            checked += 1;
            match catch_unwind(AssertUnwindSafe(|| open(&e))) {
                Ok(Ok(_)) => {
                    accepted += 1;
                    eprintln!("{name}: ACCEPTED single-byte mutation at offset {i} (mut {m}) — malleability/auth-bypass");
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    panicked += 1;
                    eprintln!(
                        "{name}: PANIC on mutation at offset {i} (mut {m}) — parse robustness"
                    );
                }
            }
        }
    }
    for cut in [
        1usize,
        2,
        3,
        16,
        valid.len() / 3,
        valid.len() / 2,
        valid.len().saturating_sub(1),
    ] {
        if cut == 0 || cut >= valid.len() {
            continue;
        }
        let e = valid[..valid.len() - cut].to_vec();
        checked += 1;
        match catch_unwind(AssertUnwindSafe(|| open(&e))) {
            Ok(Ok(_)) => {
                accepted += 1;
                eprintln!("{name}: ACCEPTED a truncation (-{cut} bytes)");
            }
            Ok(Err(_)) => {}
            Err(_) => {
                panicked += 1;
                eprintln!("{name}: PANIC on truncation (-{cut} bytes)");
            }
        }
    }
    assert_eq!(
        accepted, 0,
        "{name}: {accepted}/{checked} tampered envelopes were ACCEPTED (malleability/auth-bypass)"
    );
    assert_eq!(
        panicked, 0,
        "{name}: {panicked}/{checked} tampered envelopes caused a PANIC (parse robustness)"
    );
    eprintln!(
        "{name} malleability: {checked} tampered envelopes, all rejected (0 accepted, 0 panics)"
    );
}

#[test]
fn malleability_sweep_a3() {
    let c = Citadel::new();
    let (pk, sk) = c.generate_keypair();
    let aad = Aad::raw(b"ringer/aad");
    let ctx = Context::raw(b"ringer/ctx");
    let pt = b"ringer malleability a3 canary plaintext";
    let env = c.seal(&pk, pt, &aad, &ctx).expect("seal a3");
    assert_no_malleability("a3", &env, pt, |e| c.open(&sk, e, &aad, &ctx));
}

#[test]
fn malleability_sweep_a4() {
    let c = CitadelP384::new();
    let (pk, sk) = c.generate_keypair();
    let aad = Aad::raw(b"ringer/aad");
    let ctx = Context::raw(b"ringer/ctx");
    let pt = b"ringer malleability a4 canary plaintext";
    let env = c.seal(&pk, pt, &aad, &ctx).expect("seal a4");
    assert_no_malleability("a4", &env, pt, |e| c.open(&sk, e, &aad, &ctx));
}

#[test]
fn metamorphic_roundtrip_a3() {
    let n = env_usize("RINGER_ROUNDTRIP_CASES", 2000);
    let mut rng = StdRng::seed_from_u64(0x0C17_ADE1);
    let c = Citadel::new();
    let (pk, sk) = c.generate_keypair();
    let mut big = 0usize;
    for i in 0..n {
        let ptlen = if rng.next_u32() % 100 == 0 {
            big += 1;
            (rng.next_u32() as usize) % 65_536
        } else {
            (rng.next_u32() as usize) % 512
        };
        let mut pt = vec![0u8; ptlen];
        rng.fill_bytes(&mut pt);
        let mut ab = vec![0u8; (rng.next_u32() as usize) % 64];
        rng.fill_bytes(&mut ab);
        let mut cb = vec![0u8; (rng.next_u32() as usize) % 64];
        rng.fill_bytes(&mut cb);
        let aad = Aad::raw(&ab);
        let ctx = Context::raw(&cb);
        let env = c
            .seal(&pk, &pt, &aad, &ctx)
            .unwrap_or_else(|_| panic!("seal failed at case {i}"));
        let got = c
            .open(&sk, &env, &aad, &ctx)
            .unwrap_or_else(|_| panic!("open failed at case {i}"));
        assert_eq!(got, pt, "a3 roundtrip mismatch at case {i}");
        let env2 = c.seal(&pk, &pt, &aad, &ctx).expect("seal2");
        assert_ne!(
            env, env2,
            "a3 two seals identical at case {i} (nonce reuse!)"
        );
        let mut wrong = ab.clone();
        wrong.push(0xAB);
        assert!(
            c.open(&sk, &env, &Aad::raw(&wrong), &ctx).is_err(),
            "a3 wrong-aad accepted at case {i}"
        );
    }
    eprintln!("a3 metamorphic: {n} roundtrips ok ({big} large payloads)");
}

#[test]
fn metamorphic_roundtrip_a4() {
    let n = env_usize("RINGER_ROUNDTRIP_CASES", 2000);
    let mut rng = StdRng::seed_from_u64(0x0C17_ADE4);
    let c = CitadelP384::new();
    let (pk, sk) = c.generate_keypair();
    let mut big = 0usize;
    for i in 0..n {
        let ptlen = if rng.next_u32() % 100 == 0 {
            big += 1;
            (rng.next_u32() as usize) % 65_536
        } else {
            (rng.next_u32() as usize) % 512
        };
        let mut pt = vec![0u8; ptlen];
        rng.fill_bytes(&mut pt);
        let mut ab = vec![0u8; (rng.next_u32() as usize) % 64];
        rng.fill_bytes(&mut ab);
        let mut cb = vec![0u8; (rng.next_u32() as usize) % 64];
        rng.fill_bytes(&mut cb);
        let aad = Aad::raw(&ab);
        let ctx = Context::raw(&cb);
        let env = c
            .seal(&pk, &pt, &aad, &ctx)
            .unwrap_or_else(|_| panic!("seal failed at case {i}"));
        let got = c
            .open(&sk, &env, &aad, &ctx)
            .unwrap_or_else(|_| panic!("open failed at case {i}"));
        assert_eq!(got, pt, "a4 roundtrip mismatch at case {i}");
        let env2 = c.seal(&pk, &pt, &aad, &ctx).expect("seal2");
        assert_ne!(
            env, env2,
            "a4 two seals identical at case {i} (nonce reuse!)"
        );
        let mut wrong = cb.clone();
        wrong.push(0xCD);
        assert!(
            c.open(&sk, &env, &aad, &Context::raw(&wrong)).is_err(),
            "a4 wrong-ctx accepted at case {i}"
        );
    }
    eprintln!("a4 metamorphic: {n} roundtrips ok ({big} large payloads)");
}

/// Nonce-uniqueness at scale. On the fips build this exercises the approved GCM IV **Scenario 2**
/// path (`RandomizedNonceKey`, module DRBG) — a repeated IV would be a catastrophic AES-GCM
/// failure. On the default build it exercises the getrandom nonce. Either way, N seals must yield
/// N distinct, non-zero nonces at header[86..98].
#[test]
fn nonce_uniqueness_at_scale_a4() {
    let n = env_usize("RINGER_NONCE_SEALS", 20_000);
    let c = CitadelP384::new();
    let (pk, _sk) = c.generate_keypair();
    let aad = Aad::raw(b"n");
    let ctx = Context::raw(b"n");
    let mut seen: HashSet<[u8; 12]> = HashSet::with_capacity(n);
    let mut zero = 0usize;
    for i in 0..n {
        let env = c.seal(&pk, b"x", &aad, &ctx).expect("seal");
        let nonce: [u8; 12] = env[86..98].try_into().expect("nonce slice");
        if nonce == [0u8; 12] {
            zero += 1;
        }
        assert!(
            seen.insert(nonce),
            "NONCE COLLISION after {} unique seals (case {i})",
            seen.len()
        );
    }
    assert_eq!(
        seen.len(),
        n,
        "expected {n} unique nonces, got {}",
        seen.len()
    );
    assert_eq!(zero, 0, "all-zero nonce observed {zero}x");
    eprintln!("a4 nonce-uniqueness: {n} seals, all distinct and non-zero");
}

/// A 0xA3 envelope must never open under a 0xA4 key (or handle), and vice versa — the codec's
/// cross-suite rejection, over random inputs. Correct-suite opens must still succeed.
#[test]
fn cross_suite_reject_matrix() {
    let n = env_usize("RINGER_CROSS_CASES", 300);
    let a3 = Citadel::new();
    let a4 = CitadelP384::new();
    let mut rng = StdRng::seed_from_u64(0xA3A4_0059);
    for i in 0..n {
        let (pk3, sk3) = a3.generate_keypair();
        let (pk4, sk4) = a4.generate_keypair();
        let mut pt = vec![0u8; (rng.next_u32() as usize) % 200];
        rng.fill_bytes(&mut pt);
        let aad = Aad::raw(b"x");
        let ctx = Context::raw(b"y");
        let e3 = a3.seal(&pk3, &pt, &aad, &ctx).expect("seal a3");
        let e4 = a4.seal(&pk4, &pt, &aad, &ctx).expect("seal a4");
        assert!(
            a4.open(&sk4, &e3, &aad, &ctx).is_err(),
            "a3 envelope opened under a4 key (case {i})"
        );
        assert!(
            a3.open(&sk3, &e4, &aad, &ctx).is_err(),
            "a4 envelope opened under a3 key (case {i})"
        );
        assert_eq!(a3.open(&sk3, &e3, &aad, &ctx).expect("open a3"), pt);
        assert_eq!(a4.open(&sk4, &e4, &aad, &ctx).expect("open a4"), pt);
    }
    eprintln!(
        "cross-suite reject matrix: {n} cases, all cross-opens rejected, all correct opens ok"
    );
}
