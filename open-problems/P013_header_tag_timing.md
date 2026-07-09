# P013 - V3 Header Tag Uses Non-Constant-Time Comparison

**Layer:** citadel-envelope | **Severity:** HIGH  
**Files:** citadel-envelope/src/stream_v3.rs (line 346)

**Evidence (from independent security review):**
```
Review finding: "Header tag comparison is non-constant-time. 
`expected_tag != header_tag` is used in V3 stream header verification. 
It should use constant-time comparison. Your own reviewer criteria 
explicitly calls out timing comparisons."

Code at line 346:
if expected_tag != header_tag {
    return Err(DecryptionError);
}
```

**Root cause:**
Rust's default `!=` operator on byte slices is NOT constant-time.  
It short-circuits on first differing byte.

Attacker can measure timing differences to learn information about the 
expected tag byte-by-byte.

**Attack scenario:**
1. Attacker sends many modified headers
2. Measures response time differences
3. When guess matches first N bytes, comparison takes longer
4. Reveals tag bytes one at a time (timing oracle)

This is a known attack on CBC-mode (Bleichenbacher, Lucky13, BEAST).  
AES-GCM is theoretically resistant but constant-time comparison is 
still best practice.

**Required fix:**
Use `subtle::ConstantTimeEq` from the `subtle` crate:
```rust
use subtle::ConstantTimeEq;

// Change from:
if expected_tag != header_tag {
    return Err(DecryptionError);
}

// To:
if expected_tag.ct_eq(header_tag).into() {
    // Tags match - continue
} else {
    return Err(DecryptionError);
}
```

Or use existing constant-time utilities if already in dependencies.

**Status:** OPEN
