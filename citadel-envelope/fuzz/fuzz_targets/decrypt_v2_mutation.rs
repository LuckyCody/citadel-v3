// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]

use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;

struct Fixture {
    engine: citadel_envelope::Citadel,
    secret: citadel_envelope::SecretKey,
    ciphertext: Vec<u8>,
    aad: citadel_envelope::Aad,
    context: citadel_envelope::Context,
}

static FIXTURE: Lazy<Fixture> = Lazy::new(|| {
    let engine = citadel_envelope::Citadel::new();
    let (public, secret) = engine.generate_keypair();
    let aad = citadel_envelope::Aad::raw(b"fuzz/v2/aad");
    let context = citadel_envelope::Context::raw(b"fuzz/v2/context");
    let ciphertext = engine
        .seal(&public, b"valid v2 mutation seed", &aad, &context)
        .expect("seed seal");
    Fixture {
        engine,
        secret,
        ciphertext,
        aad,
        context,
    }
});

fuzz_target!(|data: &[u8]| {
    let fixture = &*FIXTURE;
    let mut candidate = fixture.ciphertext.clone();

    // Each three input bytes choose an offset and XOR mask. This preserves a
    // near-valid v2 structure often enough to reach KEM and AEAD failure paths.
    for chunk in data.chunks(3) {
        if chunk.len() < 3 {
            break;
        }
        let offset = u16::from_be_bytes([chunk[0], chunk[1]]) as usize % candidate.len();
        candidate[offset] ^= chunk[2];
    }

    // Also allow length mutation using the final byte.
    if let Some(last) = data.last() {
        let trim = (*last as usize) % (candidate.len() + 1);
        candidate.truncate(candidate.len() - trim);
    }

    let _ = fixture
        .engine
        .open(&fixture.secret, &candidate, &fixture.aad, &fixture.context);
});
