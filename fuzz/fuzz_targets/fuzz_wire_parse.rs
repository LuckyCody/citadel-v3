// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fuzz target for wire format parsing
//!
//! This target exercises the `decode_hybrid_wire` function with arbitrary input.
//! Goal: Find panics, hangs, or unexpected behavior in the parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use citadel_envelope::wire::decode_wire;

fuzz_target!(|data: &[u8]| {
    // decode_wire should never panic, regardless of input
    // It should return Ok(parts) or Err(DecryptionError)
    let _ = decode_wire(data);
});
