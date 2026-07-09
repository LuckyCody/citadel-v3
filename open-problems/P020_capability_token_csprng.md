# P020 - Capability Tokens Use Counter Not CSPRNG

**Layer:** citadel-core | **Severity:** MEDIUM  
**Files:** citadel-core/src/state_enforcer.rs

**Evidence (from independent security review):**
```
"Current token generation uses counter + timestamp. Because the token 
is crate-private and registry-checked, this is not catastrophic.

But do not call it 'unforgeable' cryptographically."
```

**Root cause:**
CapabilityToken generation uses predictable values (counter, timestamp).
Registry check provides security, but calling it "unforgeable" 
overstates cryptographic strength.

**Attack scenario:**
If registry check bypassed (code bug), predictable tokens could be forged.

**Required fix:**
Use cryptographically secure random nonce:
```rust
use rand_core::RngCore;

let mut bytes = [0u8; 16];
rand_core::OsRng.fill_bytes(&mut bytes);
let unique_nonce = u128::from_le_bytes(bytes);
```

Then register that nonce.

This makes tokens actually unforgeable, not just registry-checked.

**Status:** OPEN
