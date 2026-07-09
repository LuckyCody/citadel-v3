# P015 - PolicyVerdict::Expired Not Handled in Keystore

**Layer:** citadel-keystore | **Severity:** CRITICAL  
**Files:** citadel-keystore/src/keystore.rs

**Evidence (from independent security review):**
```
"In `citadel-keystore/src/policy.rs`, `PolicyVerdict` has:
* Compliant
* RotationNeeded
* Warning
* UsageLimitExceeded
* Expired

But `citadel-keystore/src/keystore.rs` has a match during encryption 
that does not handle `Expired`."
```

**Root cause:**
P005 added `PolicyVerdict::Expired` variant, but did not update all match 
statements in keystore.rs to handle it.

This causes:
- **Compile failure** if exhaustive matching enabled
- **Runtime panic** if match falls through to unreachable
- **Policy bypass** if match has catch-all that doesn't block

**Required fix:**
Add match arm in encrypt operations:
```rust
policy::PolicyVerdict::Expired { age_days, limit_days } => {
    self.audit.record(AuditEvent::key_event(
        key_id,
        meta.key_type,
        meta.state,
        AuditAction::PolicyEvaluated {
            verdict: format!("BLOCKED: expired age={}d limit={}d", age_days, limit_days),
        },
    ));
    return Err(EncryptError(format!(
        "policy violation: key expired after {} days; limit is {} days. Rotate key before encrypting.",
        age_days, limit_days
    )));
}
```

Search entire codebase for `match.*PolicyVerdict` and ensure ALL handle Expired.

**Status:** OPEN
