# P022 - Signing Authorization Length-Bound Not Content-Bound

**Layer:** citadel-core, citadel-keystore | **Severity:** HIGH  
**Files:** citadel-core/src/state_enforcer.rs, citadel-keystore/src/keystore.rs

**Evidence (from independent security review - Round 4):**
```
"You improved:
* payload length enforcement

But not:
* payload identity enforcement

Right now this still appears possible:
1. authorize signing for payload length 1024
2. sign any 1024-byte message during authorization TTL

That is weaker than the comments imply."
```

**Root cause:**
P017 fixed authorization to check `payload_bytes` (length).
But authorization is still reusable for ANY message of that length during TTL.

**Attack scenario:**
1. Get authorization to sign 1KB legitimate message
2. During TTL (60 seconds), sign DIFFERENT 1KB malicious message
3. Authorization accepts it (same length)
4. Bypass intended message-specific authorization

**Required fix:**
Bind authorization to message hash, not just length:

```rust
// In authorize_sign()
OperationParams::Sign {
    payload_hash: sha2::Sha256::digest(message).into()
}

// In require_sign_for_payload()
sha2::Sha256::digest(message) == payload_hash
```

This makes authorization single-use for specific message content.

**Status:** RESOLVED (verified 2026-07-15) — payload-hash binding coverage passed in the locked Ubuntu API/core suite; see ev_004 and the packet-003 receipt.
