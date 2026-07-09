# P016 - Replay Slot Poisoned by Post-Claim Failures

**Layer:** citadel-keystore | **Severity:** HIGH  
**Files:** citadel-keystore/src/keystore.rs (decrypt function)

**Evidence (from independent security review):**
```
"Right now decrypt claims the replay slot, but only releases it if 
AEAD decrypt fails.

Problem: if key unwrap fails or secret-key parsing fails **after the claim**, 
the replay slot stays poisoned."
```

**Root cause:**
Decrypt flow:
1. `cache.claim()` - reserves replay slot
2. `unwrap_key_version()` - might fail
3. `SecretKey::from_bytes()` - might fail
4. `envelope.open()` - releases on AEAD failure only

If steps 2 or 3 fail, slot is NEVER released.

**Attack scenario:**
1. Attacker sends malformed ciphertext C1
2. Decrypt fails at key unwrap (after claim)
3. Replay slot permanently poisoned for C1
4. Legitimate replay of C1 (if valid) now blocked forever

**Required fix:**
Add release helper after claim:
```rust
let release_replay_claim = || {
    if let Ok(cache) = self.replay_cache.lock() {
        if let Err(e) = cache.release(&cache_key) {
            tracing::warn!(
                err = %e,
                key_id = %key_id,
                "replay store release() failed after decrypt path error"
            );
        }
    }
};
```

Call it on ALL failures after claim:
- `unwrap_key_version()` failure
- `SecretKey::from_bytes()` failure  
- `envelope.open()` failure (already done)

**Status:** OPEN
