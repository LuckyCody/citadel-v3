// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = citadel_envelope::wire::decode_wire(data);
});
