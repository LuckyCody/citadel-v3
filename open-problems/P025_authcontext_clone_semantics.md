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

**Root cause (historical):**
AuthorizedContext derived Clone and capability validation checked registry membership
without consuming the nonce, allowing repeated execution during TTL.

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

**Status:** RESOLVED (implementation, 2026-07-15) — AuthorizedContext no longer
implements Clone, and successful Keystore-boundary validation atomically removes the
issued nonce. A second validation fails. See the fail-before/pass-after evidence in
`citadel/eem/002_attempt_5.md`; full packet closeout remains pending.
