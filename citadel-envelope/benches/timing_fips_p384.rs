// SPDX-License-Identifier: AGPL-3.0-or-later
//! NFR3 (packet 049): P-384 ECDH timing differential, RustCrypto vs AWS-LC.
//!
//! Packet 036 asked an ABSOLUTE question dudect cannot answer (is the shipped
//! P-384 path constant-time?) and resolved it only to a source-level ceiling,
//! with the well-powered key-material screen straddling the threshold
//! (6.67 / 6.83 / 2.18 / 3.88, no growth with n) on a box that provably detects
//! ML-KEM's real signal. This bench asks a RELATIVE question instead: on the
//! same box, in ONE process, with identical sample construction and iteration
//! counts, does the AWS-LC path show a different |t| profile than the
//! RustCrypto path? PRD NFR3 predicted AWS-LC's assembly-optimized P-384 would
//! improve the story. Measure, do not assume.
//!
//! Thresholds and the full decision table are PRE-REGISTERED in
//! `work_packets/049_nfr3_timing_differential/TASK.md`, written before any data
//! existed. |t| >= 4.5 is "detected"; straddling counts as noise floor; all
//! four runs per arm are reported, never the best. Editing those thresholds
//! after seeing numbers voids the packet.
//!
//! DECLARED ASYMMETRY - this compares SHIPPED CALL SHAPES, not bare primitives:
//! the RustCrypto arm parses the peer point then agrees with an already-parsed
//! scalar, while the AWS-LC arm checks tag/length, IMPORTS the raw scalar on
//! every call, then agrees. The import genuinely sits in the fips decapsulate
//! path (packet 043's provider calls this function per open), so including it
//! is faithful - but do not cite this as a primitive benchmark.
//!
//! Diagnostics only: nothing here is evidence of correctness, and dudect is
//! one-sided (it can reject constant-timeness, never prove it).

use std::hint::black_box;

use citadel_envelope::backend_awslc::AwsLcEcdhP384;
use citadel_envelope::{
    timing_diagnostics, CitadelP384, P384MlKem1024PublicKey, P384MlKem1024SecretKey,
};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;

/// Matches the 036 screen exactly.
const SAMPLE_PAIRS: usize = 4096;
/// 1M samples: the 036 well-powered figure, kept identical so the arms are
/// comparable to each other AND to the historical baseline. This is the
/// PRE-REGISTERED value and the default; `NFR3_ITERATIONS` may lower it ONLY
/// for plumbing smoke runs, whose numbers are inadmissible for the verdict
/// table (VALIDATION.md T2) and must be recorded as such in the receipt.
const ITERATIONS: usize = 1_000_000;

fn iterations() -> usize {
    match std::env::var("NFR3_ITERATIONS") {
        Ok(value) => value
            .parse()
            .expect("NFR3_ITERATIONS must be a positive integer"),
        Err(_) => ITERATIONS,
    }
}

/// Uncompressed SEC1 point length; the ECDH input slice of a `0xA4` kem_ct.
const P384_POINT_BYTES: usize = 97;

fn fixture_kem_ct(pk: &P384MlKem1024PublicKey, label: &str, index: usize) -> Vec<u8> {
    let (_, kem_ct) = timing_diagnostics::p384_encapsulate(pk)
        .unwrap_or_else(|_| panic!("{label} p384 encapsulation failed at index {index}"));
    assert_eq!(kem_ct.len(), 1665, "{label} kem ct length at index {index}");
    kem_ct
}

/// The static P-384 scalar as raw bytes: the `0xA4` secret key is
/// `p384_scalar[48] || mlkem_seed[64]`, and AWS-LC's ECDH takes the scalar.
fn scalar_of(sk_bytes: &[u8; 112]) -> [u8; 48] {
    let mut scalar = [0u8; 48];
    scalar.copy_from_slice(&sk_bytes[..48]);
    scalar
}

// ---------------------------------------------------------------------------
// Arm 1/2: RustCrypto (the 036 screen and its control, construction verbatim)
// ---------------------------------------------------------------------------

fn bench_rustcrypto_key_a_vs_key_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = CitadelP384::new();
    let (pk_a, sk_a) = cit.generate_keypair();
    let (pk_b, sk_b) = cit.generate_keypair();
    let sk_a_bytes = sk_a.to_bytes();
    let sk_b_bytes = sk_b.to_bytes();
    let mut samples = Vec::new();
    for i in 0..SAMPLE_PAIRS {
        let sk = P384MlKem1024SecretKey::from_bytes(&sk_a_bytes).unwrap();
        samples.push((Class::Left, sk, fixture_kem_ct(&pk_a, "rc-key-a", i)));
        let sk = P384MlKem1024SecretKey::from_bytes(&sk_b_bytes).unwrap();
        samples.push((Class::Right, sk, fixture_kem_ct(&pk_b, "rc-key-b", i)));
    }
    for _ in 0..iterations() {
        let sample = &samples[rng.gen_range(0..samples.len())];
        runner.run_one(sample.0, || {
            let _ = black_box(timing_diagnostics::p384_ecdh_only(
                &sample.1,
                black_box(&sample.2),
            ));
        });
    }
}

/// Null control: ONE key, two independent ciphertext pools split Left/Right. If
/// this reaches |t| >= 4.5 the paired screen is confounded by pool/layout
/// effects and NO timing claim may be made for this arm.
fn bench_rustcrypto_same_key_pool_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = CitadelP384::new();
    let (pk, sk) = cit.generate_keypair();
    let sk_bytes = sk.to_bytes();
    let mut samples = Vec::new();
    for i in 0..SAMPLE_PAIRS {
        let sk_l = P384MlKem1024SecretKey::from_bytes(&sk_bytes).unwrap();
        samples.push((Class::Left, sk_l, fixture_kem_ct(&pk, "rc-pool-a", i)));
        let sk_r = P384MlKem1024SecretKey::from_bytes(&sk_bytes).unwrap();
        samples.push((Class::Right, sk_r, fixture_kem_ct(&pk, "rc-pool-b", i)));
    }
    for _ in 0..iterations() {
        let sample = &samples[rng.gen_range(0..samples.len())];
        runner.run_one(sample.0, || {
            let _ = black_box(timing_diagnostics::p384_ecdh_only(
                &sample.1,
                black_box(&sample.2),
            ));
        });
    }
}

// ---------------------------------------------------------------------------
// Arm 3/4: AWS-LC, identical construction, only the ECDH call differs
// ---------------------------------------------------------------------------

fn bench_awslc_key_a_vs_key_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = CitadelP384::new();
    let (pk_a, sk_a) = cit.generate_keypair();
    let (pk_b, sk_b) = cit.generate_keypair();
    let scalar_a = scalar_of(&sk_a.to_bytes());
    let scalar_b = scalar_of(&sk_b.to_bytes());
    let mut samples = Vec::new();
    for i in 0..SAMPLE_PAIRS {
        samples.push((Class::Left, scalar_a, fixture_kem_ct(&pk_a, "lc-key-a", i)));
        samples.push((Class::Right, scalar_b, fixture_kem_ct(&pk_b, "lc-key-b", i)));
    }
    for _ in 0..iterations() {
        let sample = &samples[rng.gen_range(0..samples.len())];
        runner.run_one(sample.0, || {
            let _ = black_box(AwsLcEcdhP384::ecdh(
                &sample.1,
                black_box(&sample.2[..P384_POINT_BYTES]),
            ));
        });
    }
}

/// Null control for the AWS-LC arm, same rule as the RustCrypto control.
fn bench_awslc_same_key_pool_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = CitadelP384::new();
    let (pk, sk) = cit.generate_keypair();
    let scalar = scalar_of(&sk.to_bytes());
    let mut samples = Vec::new();
    for i in 0..SAMPLE_PAIRS {
        samples.push((Class::Left, scalar, fixture_kem_ct(&pk, "lc-pool-a", i)));
        samples.push((Class::Right, scalar, fixture_kem_ct(&pk, "lc-pool-b", i)));
    }
    for _ in 0..iterations() {
        let sample = &samples[rng.gen_range(0..samples.len())];
        runner.run_one(sample.0, || {
            let _ = black_box(AwsLcEcdhP384::ecdh(
                &sample.1,
                black_box(&sample.2[..P384_POINT_BYTES]),
            ));
        });
    }
}

ctbench_main!(
    bench_rustcrypto_key_a_vs_key_b,
    bench_rustcrypto_same_key_pool_control,
    bench_awslc_key_a_vs_key_b,
    bench_awslc_same_key_pool_control
);
