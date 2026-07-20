# P024 - Replay Persistence Documentation Oversells Reality

**Layer:** Documentation | **Severity:** HIGH  
**Files:** All documentation mentioning replay guarantees

**Evidence (from independent security review - Round 4):**
```
"The code is much better documented now, but the architecture still 
fundamentally has:

claim → memory → periodic flush

That means:
* crash-before-flush remains possible
* recent claims can disappear after hard failure

This is acceptable IF honestly documented.

But several docs still emotionally imply:
* 'replay-safe across restart'

without consistently qualifying:
* 'after flush durability boundary'"
```

**Root cause:**
P014 updated FileReplayStore docs.
But other documentation still implies stronger guarantees than batching provides.

**Required fix:**
Add clear trust statement to all replay documentation:

```markdown
## Replay Guarantees

Replay protection guarantees depend on backend durability mode:

1. **MemoryReplayStore**: Lost on restart (development only)
2. **FileReplayStore (batched)**: Durable after flush only
   - Crash window: up to 5 seconds OR 100 operations
   - Use force_flush() in SIGTERM handler
3. **FileReplayStore (strict)**: Durable immediately (set CITADEL_REPLAY_FLUSH_MODE=immediate)
4. **RedisReplayStore**: Depends on Redis persistence (AOF/RDB)

Choose based on threat model and performance requirements.
```

**Status:** RESOLVED (documentation, 2026-07-15) — replay guarantees are backend-specific and crash/storage limitations are explicit. Operational durability remains a deployment gate.
