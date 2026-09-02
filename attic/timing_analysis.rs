// SPDX-License-Identifier: AGPL-3.0-or-later
//! Timing analysis for Citadel Envelope decryption
//!
//! This tool measures decryption timing across different failure modes
//! to detect potential timing side-channels.
//!
//! Run with: `cargo run --release --example timing_analysis`

use citadel_envelope::{HybridEnvelope, HybridSecretKey};
use std::time::{Duration, Instant};

const ITERATIONS: usize = 1000;
const WARMUP_ITERATIONS: usize = 100;

struct TestCases {
    envelope: HybridEnvelope,
    sk: HybridSecretKey,
    valid_ciphertext: Vec<u8>,
    aad: Vec<u8>,
    context: Vec<u8>,
}

impl TestCases {
    fn new() -> Self {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();
        
        let plaintext = b"Test message for timing analysis";
        let aad = b"test-aad".to_vec();
        let context = b"test-context".to_vec();
        
        let valid_ciphertext = envelope.encrypt(&pk, plaintext, &aad, &context).unwrap();
        
        Self {
            envelope,
            sk,
            valid_ciphertext,
            aad,
            context,
        }
    }
    
    fn measure(&self, name: &str, f: impl Fn() -> bool) -> TimingResult {
        // Warmup
        for _ in 0..WARMUP_ITERATIONS {
            let _ = f();
        }
        
        // Measure
        let mut times = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let _ = f();
            times.push(start.elapsed());
        }
        
        TimingResult::from_durations(name, &times)
    }
}

struct TimingResult {
    name: String,
    mean: Duration,
    std_dev: Duration,
    min: Duration,
    max: Duration,
    median: Duration,
}

impl TimingResult {
    fn from_durations(name: &str, times: &[Duration]) -> Self {
        let mut sorted: Vec<_> = times.to_vec();
        sorted.sort();
        
        let sum: Duration = times.iter().sum();
        let mean = sum / times.len() as u32;
        
        let variance: f64 = times.iter()
            .map(|t| {
                let diff = t.as_nanos() as f64 - mean.as_nanos() as f64;
                diff * diff
            })
            .sum::<f64>() / times.len() as f64;
        
        let std_dev = Duration::from_nanos(variance.sqrt() as u64);
        let median = sorted[sorted.len() / 2];
        
        Self {
            name: name.to_string(),
            mean,
            std_dev,
            min: sorted[0],
            max: sorted[sorted.len() - 1],
            median,
        }
    }
    
    fn mean_micros(&self) -> f64 {
        self.mean.as_nanos() as f64 / 1000.0
    }
    
    fn std_dev_micros(&self) -> f64 {
        self.std_dev.as_nanos() as f64 / 1000.0
    }
}

fn main() {
    println!("Citadel Envelope Timing Analysis");
    println!("Iterations per test: {}", ITERATIONS);
    println!("Warmup iterations: {}", WARMUP_ITERATIONS);
    println!();
    
    let cases = TestCases::new();
    let mut results = Vec::new();
    
    // Valid decryption (baseline)
    println!("Running: valid_decrypt...");
    results.push(cases.measure("valid_decrypt", || {
        cases.envelope.decrypt(&cases.sk, &cases.valid_ciphertext, &cases.aad, &cases.context).is_ok()
    }));
    
    // Truncated ciphertext
    println!("Running: truncated...");
    let truncated = cases.valid_ciphertext[..100].to_vec();
    results.push(cases.measure("truncated", || {
        cases.envelope.decrypt(&cases.sk, &truncated, &cases.aad, &cases.context).is_err()
    }));
    
    // Wrong version byte
    println!("Running: wrong_version...");
    let mut wrong_version = cases.valid_ciphertext.clone();
    wrong_version[0] = 0xFF;
    results.push(cases.measure("wrong_version", || {
        cases.envelope.decrypt(&cases.sk, &wrong_version, &cases.aad, &cases.context).is_err()
    }));
    
    // Wrong KEM suite
    println!("Running: wrong_kem_suite...");
    let mut wrong_kem = cases.valid_ciphertext.clone();
    wrong_kem[1] = 0xA2;
    results.push(cases.measure("wrong_kem_suite", || {
        cases.envelope.decrypt(&cases.sk, &wrong_kem, &cases.aad, &cases.context).is_err()
    }));
    
    // Corrupted X25519 ciphertext
    println!("Running: corrupted_x25519...");
    let mut corrupted_x25519 = cases.valid_ciphertext.clone();
    corrupted_x25519[10] ^= 0xFF;
    results.push(cases.measure("corrupted_x25519", || {
        cases.envelope.decrypt(&cases.sk, &corrupted_x25519, &cases.aad, &cases.context).is_err()
    }));
    
    // Corrupted ML-KEM ciphertext
    println!("Running: corrupted_mlkem...");
    let mut corrupted_mlkem = cases.valid_ciphertext.clone();
    corrupted_mlkem[500] ^= 0xFF;
    results.push(cases.measure("corrupted_mlkem", || {
        cases.envelope.decrypt(&cases.sk, &corrupted_mlkem, &cases.aad, &cases.context).is_err()
    }));
    
    // Corrupted nonce
    println!("Running: corrupted_nonce...");
    let mut corrupted_nonce = cases.valid_ciphertext.clone();
    corrupted_nonce[1130] ^= 0xFF;
    results.push(cases.measure("corrupted_nonce", || {
        cases.envelope.decrypt(&cases.sk, &corrupted_nonce, &cases.aad, &cases.context).is_err()
    }));
    
    // Corrupted tag
    println!("Running: corrupted_tag...");
    let mut corrupted_tag = cases.valid_ciphertext.clone();
    let last = corrupted_tag.len() - 1;
    corrupted_tag[last] ^= 0xFF;
    results.push(cases.measure("corrupted_tag", || {
        cases.envelope.decrypt(&cases.sk, &corrupted_tag, &cases.aad, &cases.context).is_err()
    }));
    
    // Wrong AAD
    println!("Running: wrong_aad...");
    results.push(cases.measure("wrong_aad", || {
        cases.envelope.decrypt(&cases.sk, &cases.valid_ciphertext, b"wrong_aad", &cases.context).is_err()
    }));
    
    // Wrong context
    println!("Running: wrong_context...");
    results.push(cases.measure("wrong_context", || {
        cases.envelope.decrypt(&cases.sk, &cases.valid_ciphertext, &cases.aad, b"wrong_ctx").is_err()
    }));
    
    // Print results
    println!();
    println!("===========================================================================");
    println!("TIMING ANALYSIS RESULTS");
    println!("===========================================================================");
    println!();
    println!("{:<25} {:>12} {:>12} {:>12} {:>12} {:>12}",
             "Test Case", "Mean (µs)", "StdDev", "Min (µs)", "Max (µs)", "Median (µs)");
    println!("{:-<85}", "");
    
    let baseline = results[0].mean_micros();
    
    for r in &results {
        println!("{:<25} {:>12.2} {:>12.2} {:>12.2} {:>12.2} {:>12.2}",
                 r.name,
                 r.mean_micros(),
                 r.std_dev_micros(),
                 r.min.as_nanos() as f64 / 1000.0,
                 r.max.as_nanos() as f64 / 1000.0,
                 r.median.as_nanos() as f64 / 1000.0);
    }
    
    println!();
    println!("{:-<85}", "");
    println!("Timing ratios (relative to valid decrypt):");
    println!();
    
    for r in results.iter().skip(1) {
        let ratio = r.mean_micros() / baseline;
        let deviation = ((ratio - 1.0) * 100.0).abs();
        let status = if deviation < 25.0 { "✓ OK" } else { "⚠ INVESTIGATE" };
        println!("    {:<25} ratio={:.3}x  deviation={:>5.1}%  {}",
                 r.name, ratio, deviation, status);
    }
    
    println!();
    println!("===========================================================================");
    println!("INTERPRETATION GUIDE");
    println!("===========================================================================");
    println!();
    println!("• Ratios close to 1.0 indicate similar timing (good for security)");
    println!("• Large deviations (>25%) may indicate timing side-channels");
    println!("• Failure paths should ideally be similar to or slower than success");
    println!("• Fast failure paths can leak information about why decryption failed");
    println!();
    println!("Note: This is a basic timing analysis. Production security requires:");
    println!("  - Statistical hypothesis testing (t-test, Welch's test)");
    println!("  - Multiple runs across different machines/conditions");
    println!("  - dudect-style constant-time testing");
    println!("  - Professional cryptographic audit");
}
