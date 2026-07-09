# P025 - AuthorizedContext Cloneable Semantics Unclear

**Layer:** citadel-core | **Severity:** MEDIUM  
**Files:** citadel-core/src/state_enforcer.rs, documentation

**Evidence (from independent security review - Round 4):**
```
"`AuthorizedContext` still appears cloneable.

That means:
* same authorization can be reused multiple times during TTL

Potentially acceptable.

But then docs/comments must describe them as:
* short-lived reusable capabilities

not:
* one-shot authorizations

Because they are not one-shot."
```

**Root cause:**
AuthorizedContext is cloneable (derives Clone).
Can be used multiple times during TTL.

Documentation doesn't clarify: are they one-shot or reusable?

**Required fix:**
Either:

**Option A**: Document as reusable
```rust
/// Short-lived reusable capability valid for TTL duration.
/// Same authorization can be used multiple times until expiration.
/// For single-use semantics, implement nonce consumption.
```

**Option B**: Make single-use
```rust
// Add nonce tracking in StateEnforcer
used_nonces: Mutex<HashSet<u128>>

// In validate_authz, mark as used
if !self.used_nonces.insert(authz.capability.nonce) {
    return Err("authorization already consumed");
}
```

**Status:** OPEN
