# P014 - FileReplayStore Durability Claims Need Qualification

**Layer:** citadel-keystore | **Severity:** MEDIUM  
**Files:** citadel-keystore/src/replay_store.rs (documentation/comments)

**Evidence (from independent security review):**
```
Review finding: "FileReplayStore has a durability gap. Claims are batched 
and may remain memory-only until flush thresholds. A crash before flush 
can allow replay after restart. The code documents this as batching, but 
reviewer wording claiming restart-safe needs qualification."

Current P001 fix implements batching:
- Flush every 100 operations OR
- Flush every 5 seconds OR
- Flush at 10K entries

Between flushes, claims exist only in memory.
```

**Root cause:**
P001 fix (write batching) creates an inherent durability gap:
- Claims are added to in-memory HashMap
- flush() called when thresholds met
- If process crashes BEFORE flush, unflushed claims are LOST
- After restart, those ciphertexts can be decrypted AGAIN (replay)

This is NOT a bug - it's a documented trade-off for performance.  
But existing documentation may not make this clear enough.

**Attack scenario:**
1. Attacker sends ciphertext C1
2. Decrypt succeeds, claim added to memory (not yet flushed)
3. Attacker crashes the service (DoS)
4. Service restarts
5. Attacker sends C1 again
6. Decrypt succeeds AGAIN (replay window)

The window is small (max 5 seconds or 100 ops) but exists.

**Required fix:**
Update documentation in replay_store.rs to clearly state:

```rust
/// P001/P014: Write batching for performance.
///
/// Claims are batched in memory and flushed when:
/// - 100 operations accumulated, OR
/// - 5 seconds elapsed, OR  
/// - 10,000 entries reached
///
/// **DURABILITY GUARANTEE**: Claims are durable ONLY after flush().
/// Unflushed claims are lost on crash. This creates a replay window
/// of up to 5 seconds or 100 operations.
///
/// **For strict replay protection**: Use RedisReplayStore with AOF,
/// or call force_flush() after every critical operation (performance cost).
///
/// **Crash window mitigation**: Implement graceful shutdown with
/// force_flush() in SIGTERM handler (see P010 documentation).
```

Also update DEPLOYMENT_NOTES.md to explain the trade-off clearly.

**Status:** OPEN
