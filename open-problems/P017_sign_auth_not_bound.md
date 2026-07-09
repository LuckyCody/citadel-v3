# P017 - Signing Authorization Not Bound to Message

**Layer:** citadel-core | **Severity:** HIGH  
**Files:** citadel-core/src/state_enforcer.rs, citadel-keystore/src/keystore.rs

**Evidence (from independent security review):**
```
"Right now `authorize_sign()` records `payload_bytes`, but `sign_authorized()` 
does not enforce it against `message.len()`.

So a valid short-lived signing authorization could potentially be reused 
for a different message with the same key."
```

**Root cause:**
AuthorizedContext stores payload_bytes in OperationParams::Sign, but 
`require_sign_for()` only checks operation type, not payload size.

**Attack scenario:**
1. Get authorization to sign 10-byte message
2. Use same authorization to sign 10MB message
3. Authorization context doesn't detect mismatch
4. Bypass intended authorization scope

**Required fix (minimum):**
Add method to AuthorizedContext:
```rust
pub fn require_sign_for_payload(
    &self,
    key_id: &str,
    payload_bytes: usize,
) -> Result<(), String> {
    self.require_sign_for(key_id)?;
    match &self.params {
        OperationParams::Sign { payload_bytes: expected } 
            if *expected == payload_bytes => Ok(()),
        OperationParams::Sign { payload_bytes: expected } => 
            Err(format!(
                "payload size mismatch: expected {} bytes, got {}",
                expected, payload_bytes
            )),
        _ => Err("wrong operation type".into()),
    }
}
```

**Better fix:**
Bind to SHA256(message) instead of just length.

**Status:** OPEN
