// SPDX-License-Identifier: AGPL-3.0-or-later
use std::hint::black_box;
use std::time::Instant;

use citadel_envelope::{Aad, Citadel, Context};

fn time_it<F: FnMut()>(label: &str, iters: usize, mut f: F) {
    // warmup
    for _ in 0..(iters / 10).max(10) {
        f();
    }

    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();

    let per_iter = elapsed / (iters as u32);
    println!("{:<16} total={:?}  per_iter={:?}", label, elapsed, per_iter);
}

fn main() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let plaintext = vec![0x42u8; 1024];
    let aad_good = Aad::raw(b"aad-good");
    let aad_bad = Aad::raw(b"aad-bad");
    let ctx_good = Context::raw(b"ctx-good");
    let ctx_bad = Context::raw(b"ctx-bad");

    let ct = cit.seal(&pk, &plaintext, &aad_good, &ctx_good).unwrap();

    // Create a tampered ciphertext
    let mut ct_tampered = ct.clone();
    let ct_len = ct_tampered.len();
    ct_tampered[ct_len - 1] ^= 0x01;

    // Iters: keep reasonable, adjust as needed
    let iters = 5_000;

    time_it("valid", iters, || {
        let pt = cit.open(&sk, black_box(&ct), &aad_good, &ctx_good).unwrap();
        black_box(pt);
    });

    time_it("wrong_aad", iters, || {
        let r = cit.open(&sk, black_box(&ct), &aad_bad, &ctx_good);
        black_box(r.err());
    });

    time_it("wrong_ctx", iters, || {
        let r = cit.open(&sk, black_box(&ct), &aad_good, &ctx_bad);
        black_box(r.err());
    });

    time_it("tampered", iters, || {
        let r = cit.open(&sk, black_box(&ct_tampered), &aad_good, &ctx_good);
        black_box(r.err());
    });

    time_it("short", iters, || {
        let r = cit.open(&sk, black_box(b"short"), &aad_good, &ctx_good);
        black_box(r.err());
    });

    println!("\nDone.");
}
