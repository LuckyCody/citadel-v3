# P018 - Nested Zeroizing Wrappers After P011 Fix

**Layer:** citadel-envelope | **Severity:** MEDIUM  
**Files:** citadel-envelope/src/lib.rs, citadel-envelope/src/stream.rs, citadel-envelope/src/stream_v3.rs

**Evidence (from independent security review):**
```
"You fixed KEM return types, but callers still do this:

let shared_secret = Zeroizing::new(ss_raw);

where `ss_raw` is already `Zeroizing<Vec<u8>>`.

That creates nested zeroizing wrappers and makes the code harder to audit."
```

**Root cause:**
P011 changed KEM functions to return `Zeroizing<Vec<u8>>`.
Callers written before P011 still wrap the result in `Zeroizing::new()`.

This creates `Zeroizing<Zeroizing<Vec<u8>>>` which is:
- Redundant
- Harder to audit
- Not harmful but sloppy

**Required fix:**
In files that call KEM decapsulate/encapsulate, change:
```rust
// Before
let ss_raw = KemProvider::decapsulate(sk, kem_ct)?;
let shared_secret = Zeroizing::new(ss_raw);

// After
let shared_secret = KemProvider::decapsulate(sk, kem_ct)?;
```

**Files to fix:**
- citadel-envelope/src/lib.rs
- citadel-envelope/src/stream.rs
- citadel-envelope/src/stream_v3.rs

**Status:** OPEN
