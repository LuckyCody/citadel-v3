//! Tier 5 — Kani bounded-model-checking proofs for Citadel's wire parsers.
//!
//! These prove (not sample) that the attacker-facing parse functions never
//! panic and exhibit no undefined behavior — no out-of-bounds slice, no
//! arithmetic overflow, no unreachable — for EVERY input up to MAX bytes.
//!
//! Run:  cargo kani            (from this directory)
//!
//! Bound rationale: MAX straddles the short/truncated-input guard region, which
//! is the bug-prone zone for length-checked parsers. Full-length inputs are
//! covered by coverage-guided fuzzing (Tier 3); Kani exhaustively covers the
//! boundary region here.
#![allow(unused)]

#[cfg(kani)]
mod proofs {
    use citadel_envelope::{inspect, wire};

    // Raise gradually toward MIN_* as long as CBMC still terminates.
    const MAX: usize = 256;

    /// v1 wire decoder: panic-free / no-UB for all inputs of length ≤ MAX.
    #[kani::proof]
    fn decode_wire_v1_never_panics() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let _ = wire::decode_wire(&buf[..len]);
    }

    /// Public `inspect` (v1/v2 header parse): panic-free / no-UB for length ≤ MAX.
    #[kani::proof]
    fn inspect_never_panics() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let _ = inspect(&buf[..len]);
    }
}
