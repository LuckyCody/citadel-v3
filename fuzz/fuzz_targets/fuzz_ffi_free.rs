// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fuzz the Citadel-owned FFI allocation release boundary.
//!
//! The caller-provided length is intentionally untrusted. Unknown pointers,
//! interior pointers, null pointers, and repeated frees must be ignored without
//! dereferencing caller-controlled memory or constructing the wrong Layout.

#![no_main]

use arbitrary::Arbitrary;
use citadel::{citadel_free, citadel_keygen, CITADEL_OK};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FreeInput {
    public_claimed_len: u16,
    secret_claimed_len: u16,
    flags: u8,
}

fuzz_target!(|input: FreeInput| {
    let public_claimed_len = if input.flags & 0x10 != 0 {
        usize::MAX
    } else {
        usize::from(input.public_claimed_len)
    };
    let secret_claimed_len = if input.flags & 0x20 != 0 {
        usize::MAX
    } else {
        usize::from(input.secret_claimed_len)
    };
    let mut pk_ptr = std::ptr::null_mut();
    let mut pk_len = 0usize;
    let mut sk_ptr = std::ptr::null_mut();
    let mut sk_len = 0usize;

    let rc = unsafe { citadel_keygen(&mut pk_ptr, &mut pk_len, &mut sk_ptr, &mut sk_len) };
    if rc != CITADEL_OK {
        // Free any partial output defensively; both calls are null-safe.
        unsafe {
            citadel_free(pk_ptr, public_claimed_len);
            citadel_free(sk_ptr, secret_claimed_len);
        }
        return;
    }

    if input.flags & 0x08 != 0 {
        // An interior address was never returned by Citadel and must be ignored.
        unsafe { citadel_free(pk_ptr.wrapping_add(1), public_claimed_len) };
    }

    unsafe {
        if input.flags & 0x01 != 0 {
            citadel_free(sk_ptr, secret_claimed_len);
            citadel_free(pk_ptr, public_claimed_len);
        } else {
            citadel_free(pk_ptr, public_claimed_len);
            citadel_free(sk_ptr, secret_claimed_len);
        }

        if input.flags & 0x02 != 0 {
            citadel_free(pk_ptr, public_claimed_len);
        }
        if input.flags & 0x04 != 0 {
            citadel_free(sk_ptr, secret_claimed_len);
        }
        citadel_free(std::ptr::null_mut(), usize::MAX);
    }
});
