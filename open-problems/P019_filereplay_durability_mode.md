# P019 - FileReplayStore Durability Claims vs Batching Behavior

**Layer:** citadel-keystore | **Severity:** MEDIUM  
**Files:** citadel-keystore/src/replay_store.rs

**Evidence (from independent security review):**
```
"The implementation batches flushes. That means a crash before flush 
can lose replay claims.

So either change the docs or change the behavior."
```

**Root cause:**
P001 added write batching for performance.
P014 updated documentation to mention batching.

But reviewer suggests either:
1. Add strict mode with immediate flush, OR
2. Further strengthen documentation

**Recommended fix:**
Add strict flush mode via environment variable:
```rust
CITADEL_REPLAY_FLUSH_MODE=immediate
```

When set, call `force_flush()` or fsync after EVERY claim.

This gives operators the choice:
- Default: batched (fast, small replay window)
- Strict: immediate (slower, no replay window)

**Alternative fix:**
Update docs from "restart-safe replay store" to 
"batched persistent replay store; claims are restart-safe after flush, 
but hard crash before flush can lose recent claims."

**Status:** OPEN
