# Citadel FFI — Memory Ownership Rules

## Who allocates

All buffers returned through output pointer parameters (`*mut *mut u8`) are allocated
by the Citadel library using the system allocator. The caller does **not** allocate
these buffers.

## Who frees

The caller is responsible for freeing every buffer returned by the library using
`citadel_free(ptr, len)`. The `len` must exactly match the value written to the
corresponding `*len` output parameter.

## Zero-before-free

`citadel_free()` zeroes the buffer contents before returning the memory to the
allocator. This is required because the library returns secret key material
(from `citadel_keygen`) and decrypted plaintext (from `citadel_open`).
Callers should not access the buffer after calling `citadel_free`.

## Double-free

Double-free via this API is not possible through normal usage because:
- Each allocation produces exactly one pointer.
- The caller calls `citadel_free` once per pointer.
- `citadel_free(null, _)` is a safe no-op.

If you alias a pointer and call `citadel_free` twice on the same address, that is
undefined behavior. Do not do this.

## Ownership transfer summary

| Function | Returns | Caller frees |
|----------|---------|--------------|
| `citadel_keygen` | `pk_out`, `sk_out` | Both |
| `citadel_seal` | `ct_out` | Yes |
| `citadel_open` | `pt_out` | Yes |
| `citadel_error_string` | static string | **No** — do not free |

## After citadel_free

The pointer is invalid after `citadel_free`. Do not read, write, or pass it to
any function again. Set it to NULL after freeing if you need a sentinel value.

## Double-free and reused-freed-pointer

**Both are undefined behavior.** Rust's allocator does not protect against them.

Mitigation: `citadel_free()` zeros the buffer before deallocating. An accidental
read of a freed buffer (use-after-free) will see zeros rather than secret key material.
This limits information leakage but does NOT prevent memory corruption.

**Rules to prevent double-free:**
1. Set your pointer to NULL immediately after calling `citadel_free`.
2. Check for NULL before calling `citadel_free` (it is a no-op on NULL).
3. Never alias a pointer returned by this library — use exactly one owner.

## Concurrent access

`citadel_keygen`, `citadel_seal`, and `citadel_open` are thread-safe. Each call
allocates its own output buffer with no shared mutable state.

`citadel_free` is thread-safe for different buffers. Calling it concurrently on
the SAME pointer is undefined behavior (same as double-free).
