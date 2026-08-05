// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise both arbitrary dispatch and a forced v2-magic parse. The forced
    // branch prevents coverage from depending on random discovery of four magic
    // bytes while retaining attacker control over every following byte.
    let _ = citadel_envelope::inspect(data);

    let mut forced = Vec::with_capacity(4 + data.len());
    forced.extend_from_slice(b"CTD2");
    forced.extend_from_slice(data);
    let _ = citadel_envelope::inspect(&forced);
});
