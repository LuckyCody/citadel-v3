# P023 - Capability Tokens Use Counter/Timestamp Not CSPRNG

**Layer:** citadel-core | **Severity:** HIGH  
**Files:** citadel-core/src/state_enforcer.rs

**Evidence (from independent security review - Round 4):**
```
"The capability issuance system is better architecturally than most projects.

But the actual token generation still appears to rely on:
* counters
* timestamps
* registry validation

That is fine for:
* internal Rust capability enforcement

It is NOT equivalent to:
* cryptographic bearer capabilities

The comments/documentation still drift too close to 'unforgeable.'"
```

**Root cause:**
Same as P020 (not yet implemented).
CapabilityToken uses predictable counter + timestamp.
Registry validation provides security, but tokens themselves aren't cryptographically random.

**Required fix:**
Use OS randomness for token generation:

```rust
use rand_core::RngCore;

let mut bytes = [0u8; 16]; // 128-bit minimum
rand_core::OsRng.fill_bytes(&mut bytes);
let unique_nonce = u128::from_le_bytes(bytes);
```

Keep registry validation as defense-in-depth.

**Status:** OPEN
