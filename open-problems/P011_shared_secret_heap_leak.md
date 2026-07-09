# P011 - Shared Secret Heap Leak in Hybrid KEM

**Layer:** citadel-envelope | **Severity:** HIGH  
**Files:** citadel-envelope/src/kem.rs (lines 196, 234)

**Evidence (from independent security review):**
```
Review finding: "secret zeroization is incomplete. The stack buffer is 
`Zeroizing`, but `combined_raw.to_vec()` copies the 64-byte shared secret 
into a normal heap `Vec`. So the comment 'wiped on drop' is only partially 
true. The returned shared-secret `Vec` depends on callers wrapping it correctly."

Code at line 196:
let combined_ss = combined_raw.to_vec(); // copies to heap; combined_raw zeroized on drop

Code at line 234:
let combined_ss = combined_raw.to_vec(); // copies to heap; combined_raw zeroized on drop
```

**Root cause:**
`Zeroizing::new([0u8; SHARED_SECRET_BYTES * 2])` creates zeroizing stack buffer.
`.to_vec()` copies to **normal heap Vec<u8>** which is NOT zeroized.
Comment claims "combined_raw zeroized on drop" but that only applies to the 
**stack copy**, not the **heap copy** that gets returned.

Shared secret remains in heap memory until Vec is dropped AND allocator 
overwrites it (non-deterministic timing).

**Required fix:**
Return `Zeroizing<Vec<u8>>` instead of `Vec<u8>` from:
- `encapsulate()` 
- `decapsulate()`

This forces callers to handle a zeroizing type and ensures heap cleanup.

Alternative: Wrap the returned Vec in Zeroizing at call site before returning.

**Status:** OPEN
