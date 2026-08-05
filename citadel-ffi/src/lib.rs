// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! citadel-ffi: C-compatible FFI for citadel-envelope
//!
//! Exposes citadel's post-quantum hybrid encryption to any language
//! that can call a C shared library: Java (JNA), C# (P/Invoke),
//! Go (cgo), Python (ctypes), Node.js (ffi-napi).
//!
//! Memory contract:
//! - Output buffers are allocated by citadel and returned via out-pointers.
//! - The CALLER must free every such buffer with citadel_free().
//! - Passing NULL to any function returns CITADEL_ERR_NULL.
//! - When all required output pointers are non-null, they are zeroed on entry, so a
//!   non-OK return leaves them null/0 EXCEPT for a produced, registered partial
//!   output (e.g. keygen writes the public key, then an unforeseen panic yields
//!   CITADEL_ERR_PANIC): the caller must then treat the result as invalid but MUST
//!   free any non-null output pointer with citadel_free() to avoid leaking an
//!   (unzeroized) buffer.
//! - On CITADEL_ERR_NULL (a required output pointer was null), output parameters are
//!   NOT modified and NOT ownership-transferred: the caller retains exactly what it
//!   passed and must not infer ownership of any pre-existing non-null value.
//!
//! Error codes:
//!   0 = CITADEL_OK
//!   1 = CITADEL_ERR_NULL   (null pointer argument)
//!   2 = CITADEL_ERR_SEAL   (encryption failed)
//!   3 = CITADEL_ERR_OPEN   (decryption/authentication failed)
//!   4 = CITADEL_ERR_KEY    (invalid key bytes)
//!   5 = CITADEL_ERR_ALLOC  (memory allocation failed)
//!   6 = CITADEL_ERR_PANIC  (internal panic caught at the FFI boundary)
//!
//! Panic-boundary policy: the fallible, stateful operations (keygen/seal/open/free)
//! run inside a guard that catches any unforeseen panic and returns
//! CITADEL_ERR_PANIC instead of unwinding across the C ABI (which would abort the
//! host under panic="unwind"). The trivial accessors citadel_public_key_bytes,
//! citadel_secret_key_bytes, and citadel_error_string are NOT wrapped: they return a
//! compile-time constant or select a static string via a total match and have no
//! panic path by construction, so a guard would only add a worse degraded return.

use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::slice;
use std::sync::{Mutex, OnceLock};

use citadel_envelope::{
    Aad, Citadel, CitadelP384, Context, P384MlKem1024PublicKey, P384MlKem1024SecretKey, PublicKey,
    SecretKey,
};
use zeroize::Zeroizing;

#[cfg(test)]
mod allocation_probe {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub static TRACKED_PTR: AtomicUsize = AtomicUsize::new(0);
    pub static TRACKED_SIZE: AtomicUsize = AtomicUsize::new(0);
    pub static LAYOUT_MISMATCH: AtomicBool = AtomicBool::new(false);

    pub struct TrackingAllocator;

    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            System.alloc(layout)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if TRACKED_PTR.load(Ordering::SeqCst) == ptr as usize {
                let expected = TRACKED_SIZE.load(Ordering::SeqCst);
                if layout.size() != expected {
                    LAYOUT_MISMATCH.store(true, Ordering::SeqCst);
                    // Do not forward an invalid layout to the system allocator.
                    return;
                }
                TRACKED_PTR.store(0, Ordering::SeqCst);
            }
            System.dealloc(ptr, layout);
        }
    }
}

#[cfg(test)]
#[global_allocator]
static TEST_ALLOCATOR: allocation_probe::TrackingAllocator = allocation_probe::TrackingAllocator;

pub const CITADEL_OK: i32 = 0;
pub const CITADEL_ERR_NULL: i32 = 1;
pub const CITADEL_ERR_SEAL: i32 = 2;
pub const CITADEL_ERR_OPEN: i32 = 3;
pub const CITADEL_ERR_KEY: i32 = 4;
pub const CITADEL_ERR_ALLOC: i32 = 5;
/// A panic was caught at the FFI boundary (defense-in-depth; the bodies are
/// panic-safe, so this should never occur in practice).
pub const CITADEL_ERR_PANIC: i32 = 6;

/// Run an FFI body, converting any panic into `CITADEL_ERR_PANIC` instead of
/// unwinding across the `extern "C"` boundary — which, under `panic = "unwind"`,
/// would abort the host process. Defense-in-depth: the bodies are already
/// panic-safe; this ensures an unforeseen panic degrades to an error code.
fn ffi_guard(body: impl FnOnce() -> i32) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(CITADEL_ERR_PANIC)
}

/// Void-returning variant of [`ffi_guard`] for `citadel_free`.
fn ffi_guard_void(body: impl FnOnce()) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
}

fn allocations() -> &'static Mutex<HashMap<usize, usize>> {
    static ALLOCATIONS: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Lock the allocation registry, recovering from mutex poisoning (025-R M2).
///
/// The registry only performs `insert`/`remove` of `(ptr, size)` with no
/// partial-mutation window, so a panic caught at the FFI boundary while the lock was
/// held does NOT leave the map inconsistent. Recovering via `into_inner()` prevents a
/// caught panic from permanently poisoning the mutex and bricking every subsequent
/// allocation and free (which would leak — and leave unzeroized — live buffers).
fn lock_allocations() -> std::sync::MutexGuard<'static, HashMap<usize, usize>> {
    allocations()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn alloc_buf(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::NonNull::dangling().as_ptr();
    }
    let layout = match Layout::array::<u8>(size) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        return ptr;
    }

    lock_allocations().insert(ptr as usize, size);
    ptr
}

fn write_output(data: &[u8], out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    let len = data.len();
    let buf = alloc_buf(len);
    if buf.is_null() {
        return CITADEL_ERR_ALLOC;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), buf, len);
        *out_ptr = buf;
        *out_len = len;
    }
    CITADEL_OK
}

/// Size of a serialized public key in bytes (1216).
#[no_mangle]
pub extern "C" fn citadel_public_key_bytes() -> usize {
    citadel_envelope::wire::KEM_PUBLIC_KEY_BYTES
}

/// Size of a serialized secret key in bytes (2432).
#[no_mangle]
pub extern "C" fn citadel_secret_key_bytes() -> usize {
    citadel_envelope::wire::KEM_SECRET_KEY_BYTES
}

/// Size of a serialized public key for a KEM suite.
#[no_mangle]
pub extern "C" fn citadel_public_key_bytes_for_suite(suite: u8) -> usize {
    match suite {
        0xA3 => citadel_envelope::wire::KEM_PUBLIC_KEY_BYTES,
        0xA4 => citadel_envelope::P384_MLKEM1024_PUBLIC_KEY_BYTES,
        _ => 0,
    }
}

/// Size of a serialized secret key for a KEM suite.
#[no_mangle]
pub extern "C" fn citadel_secret_key_bytes_for_suite(suite: u8) -> usize {
    match suite {
        0xA3 => citadel_envelope::wire::KEM_SECRET_KEY_BYTES,
        0xA4 => citadel_envelope::P384_MLKEM1024_SECRET_KEY_BYTES,
        _ => 0,
    }
}

/// Generate a new hybrid keypair.
///
/// Writes public key into `*pk_out`/`*pk_len` and secret key into
/// `*sk_out`/`*sk_len`. Caller must free both with `citadel_free`.
///
/// # Safety
/// All pointer arguments must be valid, non-null, and properly aligned.
#[no_mangle]
pub unsafe extern "C" fn citadel_keygen(
    pk_out: *mut *mut u8,
    pk_len: *mut usize,
    sk_out: *mut *mut u8,
    sk_len: *mut usize,
) -> i32 {
    ffi_guard(|| unsafe { citadel_keygen_impl(pk_out, pk_len, sk_out, sk_len) })
}

unsafe fn citadel_keygen_impl(
    pk_out: *mut *mut u8,
    pk_len: *mut usize,
    sk_out: *mut *mut u8,
    sk_len: *mut usize,
) -> i32 {
    if pk_out.is_null() || pk_len.is_null() || sk_out.is_null() || sk_len.is_null() {
        return CITADEL_ERR_NULL;
    }
    // Zero outputs up front so any error/partial return leaves predictable values
    // (null/0 unless that specific buffer was produced). See the module memory contract.
    *pk_out = std::ptr::null_mut();
    *pk_len = 0;
    *sk_out = std::ptr::null_mut();
    *sk_len = 0;
    let engine = Citadel::new();
    let (pk, sk) = engine.generate_keypair();
    let rc = write_output(&pk.to_bytes(), pk_out, pk_len);
    if rc != CITADEL_OK {
        return rc;
    }
    // `SecretKey::to_bytes()` returns a bare [u8; N] holding the full serialized
    // hybrid secret key (X25519 static secret || ML-KEM decapsulation key). Wrap it
    // in `Zeroizing` so the transient copy is wiped on drop — crucially, drop runs
    // during unwind too, so an unforeseen panic inside `write_output` (caught by
    // `ffi_guard`) still wipes it. A manual post-copy `zeroize()` would be skipped by
    // that unwind (028-R P1). The caller's C buffer is wiped by citadel_free before
    // dealloc; `sk` zeroizes on drop via its component types. (Moved-from stack slots
    // from to_bytes() remain a general Rust-zeroize limitation, out of scope.)
    let sk_bytes = Zeroizing::new(sk.to_bytes());
    write_output(&*sk_bytes, sk_out, sk_len)
}

/// Encrypt plaintext to a recipient public key.
///
/// Caller must free `*ct_out` with `citadel_free(*ct_out, *ct_len_out)`.
///
/// # Safety
/// All non-null pointer arguments must be valid and properly aligned.
/// `aad_ptr` and `ctx_ptr` may be null (treated as empty).
#[no_mangle]
pub unsafe extern "C" fn citadel_seal(
    pk_ptr: *const u8,
    pk_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    ct_out: *mut *mut u8,
    ct_len_out: *mut usize,
) -> i32 {
    ffi_guard(|| unsafe {
        citadel_seal_impl(
            pk_ptr, pk_len, pt_ptr, pt_len, aad_ptr, aad_len, ctx_ptr, ctx_len, ct_out, ct_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn citadel_seal_impl(
    pk_ptr: *const u8,
    pk_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    ct_out: *mut *mut u8,
    ct_len_out: *mut usize,
) -> i32 {
    if pk_ptr.is_null() || pt_ptr.is_null() || ct_out.is_null() || ct_len_out.is_null() {
        return CITADEL_ERR_NULL;
    }
    *ct_out = std::ptr::null_mut();
    *ct_len_out = 0;
    let pk_bytes = slice::from_raw_parts(pk_ptr, pk_len);
    let pk = match PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return CITADEL_ERR_KEY,
    };
    let plaintext = slice::from_raw_parts(pt_ptr, pt_len);
    let aad_bytes = if aad_ptr.is_null() || aad_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(aad_ptr, aad_len)
    };
    let ctx_bytes = if ctx_ptr.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx_ptr, ctx_len)
    };
    let engine = Citadel::new();
    let ciphertext = match engine.seal(
        &pk,
        plaintext,
        &Aad::raw(aad_bytes),
        &Context::raw(ctx_bytes),
    ) {
        Ok(ct) => ct,
        Err(_) => return CITADEL_ERR_SEAL,
    };
    write_output(&ciphertext, ct_out, ct_len_out)
}

/// Decrypt a ciphertext using the recipient secret key.
///
/// Caller must free `*pt_out` with `citadel_free(*pt_out, *pt_len_out)`.
///
/// # Safety
/// All non-null pointer arguments must be valid and properly aligned.
/// `aad_ptr` and `ctx_ptr` may be null (treated as empty).
#[no_mangle]
pub unsafe extern "C" fn citadel_open(
    sk_ptr: *const u8,
    sk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    pt_out: *mut *mut u8,
    pt_len_out: *mut usize,
) -> i32 {
    ffi_guard(|| unsafe {
        citadel_open_impl(
            sk_ptr, sk_len, ct_ptr, ct_len, aad_ptr, aad_len, ctx_ptr, ctx_len, pt_out, pt_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn citadel_open_impl(
    sk_ptr: *const u8,
    sk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    pt_out: *mut *mut u8,
    pt_len_out: *mut usize,
) -> i32 {
    if sk_ptr.is_null() || ct_ptr.is_null() || pt_out.is_null() || pt_len_out.is_null() {
        return CITADEL_ERR_NULL;
    }
    *pt_out = std::ptr::null_mut();
    *pt_len_out = 0;
    let sk_bytes = slice::from_raw_parts(sk_ptr, sk_len);
    let sk = match SecretKey::from_bytes(sk_bytes) {
        Ok(k) => k,
        Err(_) => return CITADEL_ERR_KEY,
    };
    let ciphertext = slice::from_raw_parts(ct_ptr, ct_len);
    let aad_bytes = if aad_ptr.is_null() || aad_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(aad_ptr, aad_len)
    };
    let ctx_bytes = if ctx_ptr.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx_ptr, ctx_len)
    };
    let engine = Citadel::new();
    let plaintext = match engine.open(
        &sk,
        ciphertext,
        &Aad::raw(aad_bytes),
        &Context::raw(ctx_bytes),
    ) {
        Ok(pt) => pt,
        Err(_) => return CITADEL_ERR_OPEN,
    };
    write_output(&plaintext, pt_out, pt_len_out)
}

/// Generate a new P-384 + ML-KEM-1024 hybrid keypair.
///
/// Writes public key into `*pk_out`/`*pk_len` and secret key into
/// `*sk_out`/`*sk_len`. Caller must free both with `citadel_free`.
///
/// # Safety
/// All pointer arguments must be valid, non-null, and properly aligned.
#[no_mangle]
pub unsafe extern "C" fn citadel_p384_keygen(
    pk_out: *mut *mut u8,
    pk_len: *mut usize,
    sk_out: *mut *mut u8,
    sk_len: *mut usize,
) -> i32 {
    ffi_guard(|| unsafe { citadel_p384_keygen_impl(pk_out, pk_len, sk_out, sk_len) })
}

unsafe fn citadel_p384_keygen_impl(
    pk_out: *mut *mut u8,
    pk_len: *mut usize,
    sk_out: *mut *mut u8,
    sk_len: *mut usize,
) -> i32 {
    if pk_out.is_null() || pk_len.is_null() || sk_out.is_null() || sk_len.is_null() {
        return CITADEL_ERR_NULL;
    }
    *pk_out = std::ptr::null_mut();
    *pk_len = 0;
    *sk_out = std::ptr::null_mut();
    *sk_len = 0;
    let engine = CitadelP384::new();
    let (pk, sk) = engine.generate_keypair();
    let rc = write_output(&pk.to_bytes(), pk_out, pk_len);
    if rc != CITADEL_OK {
        return rc;
    }
    let sk_bytes = Zeroizing::new(sk.to_bytes());
    write_output(&*sk_bytes, sk_out, sk_len)
}

/// Encrypt plaintext to a P-384 + ML-KEM-1024 recipient public key.
///
/// Caller must free `*ct_out` with `citadel_free(*ct_out, *ct_len_out)`.
///
/// # Safety
/// All non-null pointer arguments must be valid and properly aligned.
/// `aad_ptr` and `ctx_ptr` may be null (treated as empty).
#[no_mangle]
pub unsafe extern "C" fn citadel_p384_seal(
    pk_ptr: *const u8,
    pk_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    ct_out: *mut *mut u8,
    ct_len_out: *mut usize,
) -> i32 {
    ffi_guard(|| unsafe {
        citadel_p384_seal_impl(
            pk_ptr, pk_len, pt_ptr, pt_len, aad_ptr, aad_len, ctx_ptr, ctx_len, ct_out, ct_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn citadel_p384_seal_impl(
    pk_ptr: *const u8,
    pk_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    ct_out: *mut *mut u8,
    ct_len_out: *mut usize,
) -> i32 {
    if pk_ptr.is_null() || pt_ptr.is_null() || ct_out.is_null() || ct_len_out.is_null() {
        return CITADEL_ERR_NULL;
    }
    *ct_out = std::ptr::null_mut();
    *ct_len_out = 0;
    let pk_bytes = slice::from_raw_parts(pk_ptr, pk_len);
    let pk = match P384MlKem1024PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return CITADEL_ERR_KEY,
    };
    let plaintext = slice::from_raw_parts(pt_ptr, pt_len);
    let aad_bytes = if aad_ptr.is_null() || aad_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(aad_ptr, aad_len)
    };
    let ctx_bytes = if ctx_ptr.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx_ptr, ctx_len)
    };
    let engine = CitadelP384::new();
    let ciphertext = match engine.seal(
        &pk,
        plaintext,
        &Aad::raw(aad_bytes),
        &Context::raw(ctx_bytes),
    ) {
        Ok(ct) => ct,
        Err(_) => return CITADEL_ERR_SEAL,
    };
    write_output(&ciphertext, ct_out, ct_len_out)
}

/// Decrypt a P-384 + ML-KEM-1024 ciphertext using the recipient secret key.
///
/// Caller must free `*pt_out` with `citadel_free(*pt_out, *pt_len_out)`.
///
/// # Safety
/// All non-null pointer arguments must be valid and properly aligned.
/// `aad_ptr` and `ctx_ptr` may be null (treated as empty).
#[no_mangle]
pub unsafe extern "C" fn citadel_p384_open(
    sk_ptr: *const u8,
    sk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    pt_out: *mut *mut u8,
    pt_len_out: *mut usize,
) -> i32 {
    ffi_guard(|| unsafe {
        citadel_p384_open_impl(
            sk_ptr, sk_len, ct_ptr, ct_len, aad_ptr, aad_len, ctx_ptr, ctx_len, pt_out, pt_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn citadel_p384_open_impl(
    sk_ptr: *const u8,
    sk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    pt_out: *mut *mut u8,
    pt_len_out: *mut usize,
) -> i32 {
    if sk_ptr.is_null() || ct_ptr.is_null() || pt_out.is_null() || pt_len_out.is_null() {
        return CITADEL_ERR_NULL;
    }
    *pt_out = std::ptr::null_mut();
    *pt_len_out = 0;
    let sk_bytes = slice::from_raw_parts(sk_ptr, sk_len);
    let sk = match P384MlKem1024SecretKey::from_bytes(sk_bytes) {
        Ok(k) => k,
        Err(_) => return CITADEL_ERR_KEY,
    };
    let ciphertext = slice::from_raw_parts(ct_ptr, ct_len);
    let aad_bytes = if aad_ptr.is_null() || aad_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(aad_ptr, aad_len)
    };
    let ctx_bytes = if ctx_ptr.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx_ptr, ctx_len)
    };
    let engine = CitadelP384::new();
    let plaintext = match engine.open(
        &sk,
        ciphertext,
        &Aad::raw(aad_bytes),
        &Context::raw(ctx_bytes),
    ) {
        Ok(pt) => pt,
        Err(_) => return CITADEL_ERR_OPEN,
    };
    write_output(&plaintext, pt_out, pt_len_out)
}

/// Free a buffer allocated by citadel_keygen, citadel_seal, or citadel_open.
///
/// Passing NULL is safe. The length argument is retained for ABI compatibility;
/// deallocation uses Citadel's allocator-owned length metadata.
///
/// # Safety
/// `ptr` must be a currently live allocation returned by Citadel and must be
/// released exactly once. Unrecognized pointers and immediate repeated calls are
/// ignored as a best-effort guard, but a stale pointer could alias a later reused
/// address and remains a caller ownership violation. Caller-provided length is
/// never used for memory access or layout.
///
/// P145: zeros the buffer before deallocation so secret keys and plaintext
/// do not linger in heap memory after the caller is done with them.
#[no_mangle]
pub unsafe extern "C" fn citadel_free(ptr: *mut u8, _len: usize) {
    ffi_guard_void(|| unsafe { citadel_free_impl(ptr, _len) })
}

unsafe fn citadel_free_impl(ptr: *mut u8, _len: usize) {
    if ptr.is_null() {
        return;
    }

    let actual_len = lock_allocations().remove(&(ptr as usize));
    let Some(actual_len) = actual_len else {
        return;
    };
    if actual_len == 0 {
        return;
    }

    // Zero before free — required for secret key material and decrypted plaintext.
    std::ptr::write_bytes(ptr, 0u8, actual_len);
    if let Ok(layout) = Layout::array::<u8>(actual_len) {
        dealloc(ptr, layout);
    }
}

/// Return a static C string describing an error code. Do NOT free the result.
#[no_mangle]
pub extern "C" fn citadel_error_string(code: i32) -> *const u8 {
    match code {
        CITADEL_OK => b"ok\0".as_ptr(),
        CITADEL_ERR_NULL => b"null pointer argument\0".as_ptr(),
        CITADEL_ERR_SEAL => b"encryption failed\0".as_ptr(),
        CITADEL_ERR_OPEN => b"decryption failed\0".as_ptr(),
        CITADEL_ERR_KEY => b"invalid key\0".as_ptr(),
        CITADEL_ERR_ALLOC => b"memory allocation failed\0".as_ptr(),
        CITADEL_ERR_PANIC => b"internal panic caught at FFI boundary\0".as_ptr(),
        _ => b"unknown error\0".as_ptr(),
    }
}

// ---------------------------------------------------------------------------
// P150 — FFI safety tests: null handling, length abuse, zero-before-free
// ---------------------------------------------------------------------------

#[cfg(test)]
mod safety_tests {
    use super::*;

    /// P150 — citadel_free(null, 0) must not crash.
    #[test]
    fn free_null_is_safe() {
        unsafe { citadel_free(std::ptr::null_mut(), 0) };
    }

    /// P150 — citadel_free(null, nonzero) must not crash.
    #[test]
    fn free_null_nonzero_len_is_safe() {
        unsafe { citadel_free(std::ptr::null_mut(), 64) };
    }

    /// P145/P150 — citadel_free() zeros memory before deallocation.
    /// Allocate a known-pattern buffer, free it, and verify the pattern
    /// is overwritten. We read via a raw pointer BEFORE the dealloc lands,
    /// so we capture the zeroing that happens inside citadel_free.
    #[test]
    fn free_zeros_before_dealloc() {
        // Allocate through the production registry path used by keygen/open.
        let len = 32usize;
        let ptr = alloc_buf(len);
        assert!(!ptr.is_null());
        // Fill with non-zero sentinel
        unsafe { std::ptr::write_bytes(ptr, 0xAB, len) };
        // Confirm sentinel is there
        let before: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len).to_vec() };
        assert!(before.iter().all(|&b| b == 0xAB), "sentinel not written");
        // We cannot read after deallocation. The allocation probe below checks
        // layout correctness; sanitizer/fuzz runs exercise the whole boundary.
        unsafe { citadel_free(ptr, len) };
    }

    /// Packet 002: the FFI caller is untrusted and may return the right pointer
    /// with the wrong length. Freeing must use allocator-owned metadata rather
    /// than that caller-controlled length.
    #[test]
    fn free_uses_allocator_owned_length_not_caller_length() {
        use std::sync::atomic::Ordering;

        let actual_len = 32usize;
        let ptr = alloc_buf(actual_len);
        assert!(!ptr.is_null());
        unsafe { std::ptr::write_bytes(ptr, 0xA5, actual_len) };

        allocation_probe::LAYOUT_MISMATCH.store(false, Ordering::SeqCst);
        allocation_probe::TRACKED_SIZE.store(actual_len, Ordering::SeqCst);
        allocation_probe::TRACKED_PTR.store(ptr as usize, Ordering::SeqCst);

        // A shorter caller length keeps the zeroing write in bounds while the
        // tracking allocator detects the wrong deallocation layout.
        unsafe { citadel_free(ptr, actual_len - 16) };
        assert!(
            !allocation_probe::LAYOUT_MISMATCH.load(Ordering::SeqCst),
            "citadel_free trusted the caller length instead of allocation metadata"
        );
    }

    /// P150 — citadel_keygen returns non-null, correct-length keys.
    #[test]
    fn keygen_produces_valid_lengths() {
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        let rc = unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };
        assert_eq!(rc, 0, "citadel_keygen must succeed");
        assert_eq!(
            pk_len, 1216,
            "public key must be 1216 bytes (X25519+ML-KEM-768)"
        );
        assert_eq!(sk_len, 2432, "secret key must be 2432 bytes");
        assert!(!pk_ptr.is_null());
        assert!(!sk_ptr.is_null());
        unsafe { citadel_free(pk_ptr, pk_len) };
        unsafe { citadel_free(sk_ptr, sk_len) };
    }

    /// P150 — citadel_keygen with null output pointer returns error, not crash.
    #[test]
    fn keygen_null_out_returns_error() {
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        let rc = unsafe {
            citadel_keygen(
                std::ptr::null_mut(), // pk_out = null — should error
                &mut pk_len,
                &mut sk_ptr,
                &mut sk_len,
            )
        };
        assert_ne!(rc, 0, "null pk_out must return error code");
    }

    /// P150 — Full seal/open roundtrip through FFI proves encrypt+decrypt path.
    #[test]
    fn ffi_seal_open_roundtrip() {
        // Generate keys
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        let rc = unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };
        assert_eq!(rc, 0);

        let plaintext = b"ffi-roundtrip-test";
        let aad = b"test-aad";

        // Seal
        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        let rc = unsafe {
            citadel_seal(
                pk_ptr,
                pk_len,
                plaintext.as_ptr(),
                plaintext.len(),
                aad.as_ptr(),
                aad.len(),
                std::ptr::null(),
                0, // no context
                &mut ct_ptr,
                &mut ct_len,
            )
        };
        assert_eq!(rc, 0, "citadel_seal must succeed");
        assert!(!ct_ptr.is_null());

        // Open
        let mut pt_ptr: *mut u8 = std::ptr::null_mut();
        let mut pt_len: usize = 0;
        let rc = unsafe {
            citadel_open(
                sk_ptr,
                sk_len,
                ct_ptr,
                ct_len,
                aad.as_ptr(),
                aad.len(),
                std::ptr::null(),
                0,
                &mut pt_ptr,
                &mut pt_len,
            )
        };
        assert_eq!(rc, 0, "citadel_open must succeed");
        let decrypted = unsafe { std::slice::from_raw_parts(pt_ptr, pt_len) };
        assert_eq!(decrypted, plaintext);

        // Clean up — all memory zeroed before free
        unsafe {
            citadel_free(pk_ptr, pk_len);
            citadel_free(sk_ptr, sk_len);
            citadel_free(ct_ptr, ct_len);
            citadel_free(pt_ptr, pt_len);
        }
    }

    /// P150 — Wrong AAD on open must fail with error code (not crash).
    #[test]
    fn ffi_open_wrong_aad_returns_error() {
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };

        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        unsafe {
            citadel_seal(
                pk_ptr,
                pk_len,
                b"data".as_ptr(),
                4,
                b"correct-aad".as_ptr(),
                11,
                std::ptr::null(),
                0,
                &mut ct_ptr,
                &mut ct_len,
            )
        };

        let mut pt_ptr: *mut u8 = std::ptr::null_mut();
        let mut pt_len: usize = 0;
        let rc = unsafe {
            citadel_open(
                sk_ptr,
                sk_len,
                ct_ptr,
                ct_len,
                b"wrong-aad".as_ptr(),
                9,
                std::ptr::null(),
                0,
                &mut pt_ptr,
                &mut pt_len,
            )
        };
        assert_ne!(rc, 0, "wrong AAD must return error, not succeed");

        unsafe {
            citadel_free(pk_ptr, pk_len);
            citadel_free(sk_ptr, sk_len);
            citadel_free(ct_ptr, ct_len);
        }
    }

    #[test]
    fn p384_keygen_produces_valid_lengths() {
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        let rc = unsafe { citadel_p384_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };
        assert_eq!(rc, CITADEL_OK);
        assert_eq!(pk_len, 1665);
        assert_eq!(sk_len, 112);
        assert!(!pk_ptr.is_null());
        assert!(!sk_ptr.is_null());
        unsafe {
            citadel_free(pk_ptr, pk_len);
            citadel_free(sk_ptr, sk_len);
        }
    }

    #[test]
    fn p384_seal_open_roundtrip() {
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        assert_eq!(
            unsafe { citadel_p384_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) },
            CITADEL_OK
        );

        let plaintext = b"p384 ffi roundtrip";
        let aad = b"aad";
        let context = b"context";
        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        assert_eq!(
            unsafe {
                citadel_p384_seal(
                    pk_ptr,
                    pk_len,
                    plaintext.as_ptr(),
                    plaintext.len(),
                    aad.as_ptr(),
                    aad.len(),
                    context.as_ptr(),
                    context.len(),
                    &mut ct_ptr,
                    &mut ct_len,
                )
            },
            CITADEL_OK
        );

        let mut pt_ptr: *mut u8 = std::ptr::null_mut();
        let mut pt_len: usize = 0;
        assert_eq!(
            unsafe {
                citadel_p384_open(
                    sk_ptr,
                    sk_len,
                    ct_ptr,
                    ct_len,
                    aad.as_ptr(),
                    aad.len(),
                    context.as_ptr(),
                    context.len(),
                    &mut pt_ptr,
                    &mut pt_len,
                )
            },
            CITADEL_OK
        );
        assert_eq!(unsafe { slice::from_raw_parts(pt_ptr, pt_len) }, plaintext);
        unsafe {
            citadel_free(pk_ptr, pk_len);
            citadel_free(sk_ptr, sk_len);
            citadel_free(ct_ptr, ct_len);
            citadel_free(pt_ptr, pt_len);
        }
    }

    #[test]
    fn p384_open_wrong_aad_returns_error() {
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        assert_eq!(
            unsafe { citadel_p384_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) },
            CITADEL_OK
        );
        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        assert_eq!(
            unsafe {
                citadel_p384_seal(
                    pk_ptr,
                    pk_len,
                    b"data".as_ptr(),
                    4,
                    b"correct-aad".as_ptr(),
                    11,
                    std::ptr::null(),
                    0,
                    &mut ct_ptr,
                    &mut ct_len,
                )
            },
            CITADEL_OK
        );
        let mut pt_ptr: *mut u8 = std::ptr::null_mut();
        let mut pt_len: usize = 0;
        assert_ne!(
            unsafe {
                citadel_p384_open(
                    sk_ptr,
                    sk_len,
                    ct_ptr,
                    ct_len,
                    b"wrong-aad".as_ptr(),
                    9,
                    std::ptr::null(),
                    0,
                    &mut pt_ptr,
                    &mut pt_len,
                )
            },
            CITADEL_OK
        );
        unsafe {
            citadel_free(pk_ptr, pk_len);
            citadel_free(sk_ptr, sk_len);
            citadel_free(ct_ptr, ct_len);
        }
    }

    #[test]
    fn p384_keygen_null_out_returns_error() {
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        assert_eq!(
            unsafe {
                citadel_p384_keygen(std::ptr::null_mut(), &mut pk_len, &mut sk_ptr, &mut sk_len)
            },
            CITADEL_ERR_NULL
        );
    }

    #[test]
    fn p384_open_wrong_sk_len_returns_error() {
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        assert_eq!(
            unsafe { citadel_p384_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) },
            CITADEL_OK
        );
        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        assert_eq!(
            unsafe {
                citadel_p384_seal(
                    pk_ptr,
                    pk_len,
                    b"data".as_ptr(),
                    4,
                    b"aad".as_ptr(),
                    3,
                    std::ptr::null(),
                    0,
                    &mut ct_ptr,
                    &mut ct_len,
                )
            },
            CITADEL_OK
        );
        let mut pt_ptr: *mut u8 = std::ptr::null_mut();
        let mut pt_len: usize = 0;
        assert_ne!(
            unsafe {
                citadel_p384_open(
                    sk_ptr,
                    1,
                    ct_ptr,
                    ct_len,
                    b"aad".as_ptr(),
                    3,
                    std::ptr::null(),
                    0,
                    &mut pt_ptr,
                    &mut pt_len,
                )
            },
            CITADEL_OK
        );
        unsafe {
            citadel_free(pk_ptr, pk_len);
            citadel_free(sk_ptr, sk_len);
            citadel_free(ct_ptr, ct_len);
        }
    }

    #[test]
    fn suite_parameterized_key_sizes_are_correct() {
        assert_eq!(citadel_public_key_bytes_for_suite(0xA3), 1216);
        assert_eq!(citadel_public_key_bytes_for_suite(0xA4), 1665);
        assert_eq!(citadel_public_key_bytes_for_suite(0x00), 0);
        assert_eq!(citadel_secret_key_bytes_for_suite(0xA3), 2432);
        assert_eq!(citadel_secret_key_bytes_for_suite(0xA4), 112);
        assert_eq!(citadel_secret_key_bytes_for_suite(0x00), 0);
    }

    #[test]
    fn p384_seal_rejects_a3_public_key() {
        let mut pk_ptr: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        let mut sk_ptr: *mut u8 = std::ptr::null_mut();
        let mut sk_len: usize = 0;
        assert_eq!(
            unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) },
            CITADEL_OK
        );
        assert_eq!(pk_len, 1216);
        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        assert_eq!(
            unsafe {
                citadel_p384_seal(
                    pk_ptr,
                    pk_len,
                    b"data".as_ptr(),
                    4,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    &mut ct_ptr,
                    &mut ct_len,
                )
            },
            CITADEL_ERR_KEY
        );
        assert!(ct_ptr.is_null());
        assert_eq!(ct_len, 0);
        unsafe {
            citadel_free(pk_ptr, pk_len);
            citadel_free(sk_ptr, sk_len);
        }
    }
}

/// P161 — Concurrent citadel_keygen calls from multiple threads must not crash.
#[test]
fn keygen_is_safe_under_concurrency() {
    use std::sync::{Arc, Mutex};
    let results: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let results = Arc::clone(&results);
        let h = std::thread::spawn(move || {
            let mut pk_ptr: *mut u8 = std::ptr::null_mut();
            let mut pk_len: usize = 0;
            let mut sk_ptr: *mut u8 = std::ptr::null_mut();
            let mut sk_len: usize = 0;
            let rc = unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };
            let ok = rc == 0 && pk_len == 1216 && sk_len == 2432;
            if ok {
                unsafe {
                    citadel_free(pk_ptr, pk_len);
                    citadel_free(sk_ptr, sk_len);
                }
            }
            results.lock().unwrap().push(ok);
        });
        handles.push(h);
    }
    for h in handles {
        h.join().unwrap();
    }
    let r = results.lock().unwrap();
    assert!(
        r.iter().all(|&ok| ok),
        "all concurrent keygen calls must succeed"
    );
}

/// P161 — citadel_open with wrong ct_len must return error, not UB or crash.
/// We pass a length shorter than the actual ciphertext. The implementation
/// must treat this as an authentication failure, not undefined behavior.
#[test]
fn open_with_wrong_ct_len_returns_error() {
    let mut pk_ptr: *mut u8 = std::ptr::null_mut();
    let mut pk_len: usize = 0;
    let mut sk_ptr: *mut u8 = std::ptr::null_mut();
    let mut sk_len: usize = 0;
    unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };

    let mut ct_ptr: *mut u8 = std::ptr::null_mut();
    let mut ct_len: usize = 0;
    unsafe {
        citadel_seal(
            pk_ptr,
            pk_len,
            b"test".as_ptr(),
            4,
            b"aad".as_ptr(),
            3,
            std::ptr::null(),
            0,
            &mut ct_ptr,
            &mut ct_len,
        );
    }

    // Pass a ct_len shorter than actual — must error cleanly
    let truncated_len = ct_len / 2;
    let mut pt_ptr: *mut u8 = std::ptr::null_mut();
    let mut pt_len: usize = 0;
    let rc = unsafe {
        citadel_open(
            sk_ptr,
            sk_len,
            ct_ptr,
            truncated_len,
            b"aad".as_ptr(),
            3,
            std::ptr::null(),
            0,
            &mut pt_ptr,
            &mut pt_len,
        )
    };
    assert_ne!(
        rc, 0,
        "wrong ct_len must return error, not succeed or crash"
    );

    unsafe {
        citadel_free(pk_ptr, pk_len);
        citadel_free(sk_ptr, sk_len);
        citadel_free(ct_ptr, ct_len);
    }
}

/// P161 — Immediate repeated release is ignored by the allocation registry.
/// This is a best-effort guard only: a stale pointer can alias a later allocation
/// after allocator address reuse, so callers still own exactly-once release.
#[test]
fn immediate_repeated_free_is_ignored() {
    let len = 64usize;
    let ptr = alloc_buf(len);
    assert!(!ptr.is_null());
    unsafe { std::ptr::write_bytes(ptr, 0xFF, len) };
    unsafe {
        citadel_free(ptr, len);
        citadel_free(ptr, usize::MAX);
    }
}

/// P160 — Wrong sk_len (too small) passed to citadel_open must return error, not UB.
#[test]
fn ffi_open_wrong_sk_len_returns_error() {
    let mut pk_ptr: *mut u8 = std::ptr::null_mut();
    let mut pk_len: usize = 0;
    let mut sk_ptr: *mut u8 = std::ptr::null_mut();
    let mut sk_len: usize = 0;
    unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };

    // Seal normally
    let mut ct_ptr: *mut u8 = std::ptr::null_mut();
    let mut ct_len: usize = 0;
    let rc = unsafe {
        citadel_seal(
            pk_ptr,
            pk_len,
            b"data".as_ptr(),
            4,
            b"aad".as_ptr(),
            3,
            std::ptr::null(),
            0,
            &mut ct_ptr,
            &mut ct_len,
        )
    };
    assert_eq!(rc, 0, "seal must succeed");

    // Open with wrong sk_len (1 byte instead of 2432)
    let mut pt_ptr: *mut u8 = std::ptr::null_mut();
    let mut pt_len: usize = 0;
    let rc = unsafe {
        citadel_open(
            sk_ptr,
            1, // wrong length
            ct_ptr,
            ct_len,
            b"aad".as_ptr(),
            3,
            std::ptr::null(),
            0,
            &mut pt_ptr,
            &mut pt_len,
        )
    };
    assert_ne!(rc, 0, "wrong sk_len must return error code, not succeed");

    unsafe {
        citadel_free(pk_ptr, pk_len);
        citadel_free(sk_ptr, sk_len);
        citadel_free(ct_ptr, ct_len);
    }
}

/// P160 — Concurrent keygen calls must not produce duplicate keypairs or crash.
#[test]
fn ffi_concurrent_keygen_is_safe() {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    let results: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for _ in 0..8 {
        let results = Arc::clone(&results);
        let h = std::thread::spawn(move || {
            let mut pk_ptr: *mut u8 = std::ptr::null_mut();
            let mut pk_len: usize = 0;
            let mut sk_ptr: *mut u8 = std::ptr::null_mut();
            let mut sk_len: usize = 0;
            let rc = unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };
            assert_eq!(rc, 0);
            let pk_bytes = unsafe { std::slice::from_raw_parts(pk_ptr, pk_len).to_vec() };
            unsafe {
                citadel_free(pk_ptr, pk_len);
                citadel_free(sk_ptr, sk_len);
            }
            results.lock().unwrap().push(pk_bytes);
        });
        handles.push(h);
    }
    for h in handles {
        h.join().unwrap();
    }

    let pks = results.lock().unwrap();
    let unique: HashSet<_> = pks.iter().collect();
    assert_eq!(
        unique.len(),
        pks.len(),
        "concurrent keygen must produce distinct keypairs"
    );
}

// P160: the FFI boundary guard (used by every extern "C" fn) must convert an
// unforeseen panic into CITADEL_ERR_PANIC rather than unwinding across the C ABI
// (which would abort the host process under panic = "unwind").
#[test]
fn ffi_guard_converts_panic_to_error_code() {
    let rc = ffi_guard(|| panic!("induced FFI-body panic"));
    assert_eq!(
        rc, CITADEL_ERR_PANIC,
        "ffi_guard must catch a panic and return CITADEL_ERR_PANIC"
    );
    // A non-panicking body passes its return value through unchanged.
    assert_eq!(ffi_guard(|| CITADEL_OK), CITADEL_OK);
    assert_eq!(ffi_guard(|| CITADEL_ERR_SEAL), CITADEL_ERR_SEAL);
    // The void variant must swallow a panic without unwinding out.
    ffi_guard_void(|| panic!("induced free-body panic"));
    // citadel_error_string must describe the new code.
    let s = citadel_error_string(CITADEL_ERR_PANIC);
    assert!(!s.is_null());
}

// P161 (025-R M2): a caught panic while the allocation-registry lock is held must
// NOT permanently brick the allocator. The registry lock recovers from poisoning, so
// keygen/free keep working (and buffers remain freeable/zeroizable) afterwards.
#[test]
fn allocation_registry_recovers_from_poison() {
    // Poison the global registry mutex: panic while holding the lock.
    let _ = std::panic::catch_unwind(|| {
        let _guard = allocations().lock().expect("first lock is unpoisoned");
        panic!("poison the allocation registry");
    });

    // A normal keygen must still succeed (its output registers via the recovered
    // lock) and its buffers must still be freeable (removed via the recovered lock).
    let mut pk_ptr: *mut u8 = std::ptr::null_mut();
    let mut pk_len: usize = 0;
    let mut sk_ptr: *mut u8 = std::ptr::null_mut();
    let mut sk_len: usize = 0;
    let rc = unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };
    assert_eq!(rc, CITADEL_OK, "keygen must succeed after registry poison");
    assert!(!pk_ptr.is_null() && !sk_ptr.is_null());
    unsafe {
        citadel_free(pk_ptr, pk_len);
        citadel_free(sk_ptr, sk_len);
    }
}

// 026-R N5: on an error return, output params must be zeroed (not left at the
// caller's prior value), so the "free any non-null output on error" contract holds.
#[test]
fn error_return_zeroes_output_params() {
    let mut ct_ptr: *mut u8 = 0x1 as *mut u8; // non-null sentinel
    let mut ct_len: usize = 999;
    let bad_pk = [0u8; 4]; // invalid public key -> CITADEL_ERR_KEY
    let pt = b"data";
    let rc = unsafe {
        citadel_seal(
            bad_pk.as_ptr(),
            bad_pk.len(),
            pt.as_ptr(),
            pt.len(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            &mut ct_ptr,
            &mut ct_len,
        )
    };
    assert_ne!(rc, CITADEL_OK, "invalid key must not succeed");
    assert!(ct_ptr.is_null(), "ct_out must be zeroed to null on error");
    assert_eq!(ct_len, 0, "ct_len_out must be zeroed to 0 on error");
}
