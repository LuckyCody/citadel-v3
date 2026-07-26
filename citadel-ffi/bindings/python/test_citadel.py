#!/usr/bin/env python3
"""
Citadel FFI Python roundtrip test.

Requires the shared library to be built first:
    cargo build --release -p citadel-ffi
    # Linux:   target/release/libcitadel.so
    # macOS:   target/release/libcitadel.dylib
    # Windows: target/release/citadel.dll

Run:
    python3 citadel-ffi/bindings/python/test_citadel.py
"""
import ctypes
import os
import sys
import platform

def load_library():
    """Load the Citadel shared library for this platform."""
    base = os.path.join(os.path.dirname(__file__), '..', '..', '..',
                        'target', 'release')
    if platform.system() == 'Windows':
        path = os.path.join(base, 'citadel.dll')
    elif platform.system() == 'Darwin':
        path = os.path.join(base, 'libcitadel.dylib')
    else:
        path = os.path.join(base, 'libcitadel.so')
    if not os.path.exists(path):
        print(f"Library not found at {path}")
        print("Build with: cargo build --release -p citadel-ffi")
        sys.exit(1)
    return ctypes.CDLL(path)

def setup_signatures(lib):
    """Declare FFI function signatures."""
    ptr_ptr = ctypes.POINTER(ctypes.c_char_p)
    size_ptr = ctypes.POINTER(ctypes.c_size_t)

    lib.citadel_keygen.argtypes = [ptr_ptr, size_ptr, ptr_ptr, size_ptr]
    lib.citadel_keygen.restype  = ctypes.c_int

    lib.citadel_seal.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ptr_ptr, size_ptr,
    ]
    lib.citadel_seal.restype = ctypes.c_int

    lib.citadel_open.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ptr_ptr, size_ptr,
    ]
    lib.citadel_open.restype = ctypes.c_int

    lib.citadel_free.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.citadel_free.restype  = None

    # --- 0xA4 (P-384 + ML-KEM-1024) additive symbols; 0xA3 above is unchanged ---
    ten_arg = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ptr_ptr, size_ptr,
    ]
    lib.citadel_p384_keygen.argtypes = [ptr_ptr, size_ptr, ptr_ptr, size_ptr]
    lib.citadel_p384_keygen.restype  = ctypes.c_int
    lib.citadel_p384_seal.argtypes = ten_arg
    lib.citadel_p384_seal.restype  = ctypes.c_int
    lib.citadel_p384_open.argtypes = ten_arg
    lib.citadel_p384_open.restype  = ctypes.c_int

    lib.citadel_public_key_bytes_for_suite.argtypes = [ctypes.c_uint8]
    lib.citadel_public_key_bytes_for_suite.restype  = ctypes.c_size_t
    lib.citadel_secret_key_bytes_for_suite.argtypes = [ctypes.c_uint8]
    lib.citadel_secret_key_bytes_for_suite.restype  = ctypes.c_size_t

def test_keygen(lib):
    pk_ptr = ctypes.c_char_p()
    pk_len = ctypes.c_size_t()
    sk_ptr = ctypes.c_char_p()
    sk_len = ctypes.c_size_t()
    rc = lib.citadel_keygen(ctypes.byref(pk_ptr), ctypes.byref(pk_len),
                            ctypes.byref(sk_ptr), ctypes.byref(sk_len))
    assert rc == 0, f"keygen failed: {rc}"
    assert pk_len.value == 1216, f"pk wrong length: {pk_len.value}"
    assert sk_len.value == 2432, f"sk wrong length: {sk_len.value}"
    print(f"  keygen OK — pk={pk_len.value}B sk={sk_len.value}B")
    return pk_ptr, pk_len, sk_ptr, sk_len

def test_roundtrip(lib, pk_ptr, pk_len, sk_ptr, sk_len):
    plaintext = b"python-roundtrip-test"
    aad       = b"test-aad"

    ct_ptr = ctypes.c_char_p()
    ct_len = ctypes.c_size_t()
    rc = lib.citadel_seal(pk_ptr, pk_len, plaintext, len(plaintext),
                          aad, len(aad), None, 0,
                          ctypes.byref(ct_ptr), ctypes.byref(ct_len))
    assert rc == 0, f"seal failed: {rc}"
    print(f"  seal OK — ct={ct_len.value}B")

    pt_ptr = ctypes.c_char_p()
    pt_len = ctypes.c_size_t()
    rc = lib.citadel_open(sk_ptr, sk_len, ct_ptr, ct_len,
                          aad, len(aad), None, 0,
                          ctypes.byref(pt_ptr), ctypes.byref(pt_len))
    assert rc == 0, f"open failed: {rc}"
    recovered = ctypes.string_at(pt_ptr, pt_len.value)
    assert recovered == plaintext, f"plaintext mismatch: {recovered!r}"
    print(f"  open OK — plaintext='{recovered.decode()}'")

    lib.citadel_free(ct_ptr, ct_len)
    lib.citadel_free(pt_ptr, pt_len)

def test_wrong_aad(lib, pk_ptr, pk_len, sk_ptr, sk_len):
    plaintext = b"secret"
    aad_seal  = b"correct-aad"
    aad_open  = b"wrong-aad"

    ct_ptr = ctypes.c_char_p()
    ct_len = ctypes.c_size_t()
    lib.citadel_seal(pk_ptr, pk_len, plaintext, len(plaintext),
                     aad_seal, len(aad_seal), None, 0,
                     ctypes.byref(ct_ptr), ctypes.byref(ct_len))

    pt_ptr = ctypes.c_char_p()
    pt_len = ctypes.c_size_t()
    rc = lib.citadel_open(sk_ptr, sk_len, ct_ptr, ct_len,
                          aad_open, len(aad_open), None, 0,
                          ctypes.byref(pt_ptr), ctypes.byref(pt_len))
    assert rc != 0, f"wrong-AAD open must fail, got rc={rc}"
    print(f"  wrong-AAD rejection OK — rc={rc}")
    lib.citadel_free(ct_ptr, ct_len)

def test_null_free(lib):
    lib.citadel_free(None, 0)
    lib.citadel_free(None, 64)
    print("  null-free safety OK")

def test_suite_size_accessors(lib):
    """§3.5 suite-parameterized size accessors; fixed 0xA3 accessors stay unchanged."""
    assert lib.citadel_public_key_bytes() == 1216
    assert lib.citadel_secret_key_bytes() == 2432
    assert lib.citadel_public_key_bytes_for_suite(0xA3) == 1216
    assert lib.citadel_secret_key_bytes_for_suite(0xA3) == 2432
    assert lib.citadel_public_key_bytes_for_suite(0xA4) == 1665
    assert lib.citadel_secret_key_bytes_for_suite(0xA4) == 112
    assert lib.citadel_public_key_bytes_for_suite(0x00) == 0
    assert lib.citadel_secret_key_bytes_for_suite(0xFF) == 0
    print("  suite size accessors OK — 0xA3=1216/2432, 0xA4=1665/112, unknown=0")

def test_p384_keygen(lib):
    pk_ptr = ctypes.c_char_p(); pk_len = ctypes.c_size_t()
    sk_ptr = ctypes.c_char_p(); sk_len = ctypes.c_size_t()
    rc = lib.citadel_p384_keygen(ctypes.byref(pk_ptr), ctypes.byref(pk_len),
                                 ctypes.byref(sk_ptr), ctypes.byref(sk_len))
    assert rc == 0, f"p384 keygen failed: {rc}"
    assert pk_len.value == 1665, f"p384 pk wrong length: {pk_len.value}"
    assert sk_len.value == 112, f"p384 sk wrong length: {sk_len.value}"
    print(f"  p384 keygen OK — pk={pk_len.value}B sk={sk_len.value}B")
    return pk_ptr, pk_len, sk_ptr, sk_len

def test_p384_roundtrip(lib, pk_ptr, pk_len, sk_ptr, sk_len):
    plaintext = b"python-p384-roundtrip (CNSA category-5)"
    aad       = b"p384-aad"

    ct_ptr = ctypes.c_char_p(); ct_len = ctypes.c_size_t()
    rc = lib.citadel_p384_seal(pk_ptr, pk_len, plaintext, len(plaintext),
                               aad, len(aad), None, 0,
                               ctypes.byref(ct_ptr), ctypes.byref(ct_len))
    assert rc == 0, f"p384 seal failed: {rc}"
    print(f"  p384 seal OK — ct={ct_len.value}B")

    pt_ptr = ctypes.c_char_p(); pt_len = ctypes.c_size_t()
    rc = lib.citadel_p384_open(sk_ptr, sk_len, ct_ptr, ct_len,
                               aad, len(aad), None, 0,
                               ctypes.byref(pt_ptr), ctypes.byref(pt_len))
    assert rc == 0, f"p384 open failed: {rc}"
    recovered = ctypes.string_at(pt_ptr, pt_len.value)
    assert recovered == plaintext, f"p384 plaintext mismatch: {recovered!r}"
    print(f"  p384 open OK — plaintext='{recovered.decode()}'")

    lib.citadel_free(ct_ptr, ct_len)
    lib.citadel_free(pt_ptr, pt_len)

def main():
    lib = load_library()
    setup_signatures(lib)
    print("Citadel FFI Python roundtrip test")
    print("=" * 40)

    print("--- 0xA3 (X25519 + ML-KEM-768) ---")
    pk_ptr, pk_len, sk_ptr, sk_len = test_keygen(lib)
    test_roundtrip(lib, pk_ptr, pk_len, sk_ptr, sk_len)
    test_wrong_aad(lib, pk_ptr, pk_len, sk_ptr, sk_len)
    test_null_free(lib)
    lib.citadel_free(pk_ptr, pk_len)
    lib.citadel_free(sk_ptr, sk_len)

    print("--- 0xA4 (P-384 + ML-KEM-1024) ---")
    test_suite_size_accessors(lib)
    p4_pk, p4_pk_len, p4_sk, p4_sk_len = test_p384_keygen(lib)
    test_p384_roundtrip(lib, p4_pk, p4_pk_len, p4_sk, p4_sk_len)
    lib.citadel_free(p4_pk, p4_pk_len)
    lib.citadel_free(p4_sk, p4_sk_len)

    print("=" * 40)
    print("ALL TESTS PASSED")

if __name__ == '__main__':
    main()
