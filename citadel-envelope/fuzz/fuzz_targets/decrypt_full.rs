// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
#![no_main]

use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;

static KEYPAIR: Lazy<(citadel_envelope::PublicKey, citadel_envelope::SecretKey)> =
    Lazy::new(|| {
        let citadel = citadel_envelope::Citadel::new();
        citadel.generate_keypair()
    });

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let a = (data[0] as usize) % (data.len() + 1);
    let b = if data.len() > 1 {
        (data[1] as usize) % (data.len() + 1)
    } else {
        0
    };
    let (i, j) = if a <= b { (a, b) } else { (b, a) };

    let ct = &data[..i];
    let aad = citadel_envelope::Aad::raw(&data[i..j]);
    let ctx = citadel_envelope::Context::raw(&data[j..]);

    let citadel = citadel_envelope::Citadel::new();
    let (_pk, sk) = &*KEYPAIR;

    let _ = citadel.open(sk, ct, &aad, &ctx);
});
