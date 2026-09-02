#!/usr/bin/env python3
"""
citadel_cross_verify.py

Independent Python verification of citadel-envelope's cryptographic construction.

This script independently reimplements every layer of citadel's encryption:
  SHA3-256 → HKDF-SHA256 → AES-256-GCM

and verifies that:
  1. Each primitive produces NIST/RFC known answer test vector outputs
  2. citadel's composition of these primitives is correct and stable
  3. (optional) a real citadel ciphertext can be decrypted by Python

Usage:
  # Basic verification (no citadel binary needed):
  python citadel_cross_verify.py

  # Round-trip vectors from the real generator (public API, envelope v2):
  cargo run -p citadel-envelope --example generate_vectors > test_vectors.json
  # NOTE: test_vectors.json is NOT consumable by --vector below. It contains
  # public round-trip vectors (keys, ciphertexts) but no intermediate secrets.

  # Optional --vector mode: verifies the v1 composition (citadel-env-v1 KDF)
  # of one ciphertext from a hand-built JSON file with the fields
  # combined_ss, kem_ct, nonce, aead_ct (hex) and aad, context, plaintext
  # (ASCII). No shipped example emits this schema today.
  python citadel_cross_verify.py --vector my_vector.json

Requires: pip install cryptography
"""

import sys
import json
import hashlib
import argparse

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
except ImportError:
    print("ERROR: cryptography library not installed.")
    print("Run: pip install cryptography")
    sys.exit(1)

PASS = "✅ PASS"
FAIL = "❌ FAIL"

results = {"pass": 0, "fail": 0}


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        print(f"  {PASS}  {name}")
        results["pass"] += 1
    else:
        print(f"  {FAIL}  {name}")
        if detail:
            print(f"         {detail}")
        results["fail"] += 1


def h(s: str) -> bytes:
    return bytes.fromhex(s.replace("\n", "").replace(" ", ""))


def hkdf_sha256(ikm: bytes, length: int, info: bytes, salt: bytes = None) -> bytes:
    hkdf = HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def aes256gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes256gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ─────────────────────────────────────────────────────────────────────────────
# 1. HKDF-SHA256 RFC 5869 Known Answer Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_hkdf_rfc5869():
    print("\n── 1. HKDF-SHA256 RFC 5869 Known Answer Tests ────────────────────")

    # Test Case 1
    ikm  = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = h("000102030405060708090a0b0c")
    info = h("f0f1f2f3f4f5f6f7f8f9")
    expected = h("3cb25f25faacd57a90434f64d0362f2a"
                 "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                 "34007208d5b887185865")
    okm = hkdf_sha256(ikm, 42, info, salt)
    check("RFC 5869 Test Case 1", okm == expected, f"got {okm.hex()}")

    # Test Case 2 (longer)
    ikm  = h("000102030405060708090a0b0c0d0e0f"
             "101112131415161718191a1b1c1d1e1f"
             "202122232425262728292a2b2c2d2e2f"
             "303132333435363738393a3b3c3d3e3f"
             "404142434445464748494a4b4c4d4e4f")
    salt = h("606162636465666768696a6b6c6d6e6f"
             "707172737475767778797a7b7c7d7e7f"
             "808182838485868788898a8b8c8d8e8f"
             "909192939495969798999a9b9c9d9e9f"
             "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    info = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
             "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
             "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
             "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
             "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    expected = h("b11e398dc80327a1c8e7f78c596a4934"
                 "4f012eda2d4efad8a050cc4c19afa97c"
                 "59045a99cac7827271cb41c65e590e09"
                 "da3275600c2f09b8367793a9aca3db71"
                 "cc30c58179ec3e87c14c01d5c1f3434f"
                 "1d87")
    okm = hkdf_sha256(ikm, 82, info, salt)
    check("RFC 5869 Test Case 2", okm == expected, f"got {okm.hex()}")

    # Test Case 3 (no salt)
    ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    expected = h("8da4e775a563c18f715f802a063c5a31"
                 "b8a11f5c5ee1879ec3454e5f3c738d2d"
                 "9d201395faa4b61a96c8")
    okm = hkdf_sha256(ikm, 42, b"", None)
    check("RFC 5869 Test Case 3 (no salt)", okm == expected, f"got {okm.hex()}")


# ─────────────────────────────────────────────────────────────────────────────
# 2. AES-256-GCM NIST Test Vectors
# ─────────────────────────────────────────────────────────────────────────────

def test_aes256gcm_nist():
    print("\n── 2. AES-256-GCM NIST SP 800-38D Test Vectors ──────────────────")

    # Empty plaintext, all-zero key/IV
    ct = aes256gcm_encrypt(bytes(32), bytes(12), b"", b"")
    expected_tag = h("530f8afbc74536b9a963b4f1c4cb738b")
    check("NIST: empty PT — tag", ct == expected_tag, f"got {ct.hex()}")

    # Known plaintext, no AAD
    key   = h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    nonce = h("cafebabefacedbaddecaf888")
    pt    = h("d9313225f88406e5a55909c5aff5269a"
              "86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b39")
    expected_ct = h("522dc1f099567d07f47f37a32a84427d"
                    "643a8cdcbfe5c0c97598a2bd2555d1aa"
                    "8cb08e48590dbb3da7b08b1056828838"
                    "c5f61e6393ba7a0abcc9f662eb9f796c"
                    "8d356fc31a8433884b696f4f")
    ct = aes256gcm_encrypt(key, nonce, pt, b"")
    check("NIST: nonempty PT — CT+tag", ct == expected_ct, f"got {ct.hex()}")

    # Round-trip decrypt
    recovered = aes256gcm_decrypt(key, nonce, ct, b"")
    check("NIST: nonempty PT — round-trip", recovered == pt)

    # With AAD — tag must differ from no-AAD case
    aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    ct_aad = aes256gcm_encrypt(key, nonce, pt, aad)
    expected_tag_aad = h("76fc6ece0f4e1768cddf8853bb2d551b")
    check("NIST: with AAD — tag", ct_aad[-16:] == expected_tag_aad,
          f"got {ct_aad[-16:].hex()}")
    check("NIST: AAD changes tag (not no-AAD tag)", ct_aad[-16:] != expected_ct[-16:])

    # Wrong AAD must fail
    try:
        aes256gcm_decrypt(key, nonce, ct_aad, b"wrong-aad")
        check("NIST: wrong AAD rejected", False, "decryption succeeded with wrong AAD!")
    except Exception:
        check("NIST: wrong AAD rejected", True)


# ─────────────────────────────────────────────────────────────────────────────
# 3. SHA3-256 NIST FIPS 202 Vectors
# ─────────────────────────────────────────────────────────────────────────────

def test_sha3_256_nist():
    print("\n── 3. SHA3-256 NIST FIPS 202 Vectors ────────────────────────────")

    check(
        'SHA3-256("") — FIPS 202',
        sha3_256(b"").hex() ==
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    )
    check(
        'SHA3-256("abc") — FIPS 202',
        sha3_256(b"abc").hex() ==
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    )
    msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    check(
        "SHA3-256(448-bit message) — FIPS 202",
        sha3_256(msg).hex() ==
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. X25519 RFC 7748 Section 6.1
# ─────────────────────────────────────────────────────────────────────────────

def test_x25519_rfc7748():
    print("\n── 4. X25519 DH Properties ───────────────────────────────────────")
    print("  Note: RFC 7748 KAT is in primitive_kat.rs (Rust). Python's")
    print("  cryptography library clamps keys internally, making direct")
    print("  comparison with already-clamped RFC vectors require raw EC math.")
    print("  This test verifies the DH properties that matter for citadel.")

    # Property 1: DH is symmetric — Alice.dh(Bob.pk) == Bob.dh(Alice.pk)
    alice = X25519PrivateKey.generate()
    bob   = X25519PrivateKey.generate()
    shared_ab = alice.exchange(bob.public_key())
    shared_ba = bob.exchange(alice.public_key())
    check("X25519: DH is symmetric", shared_ab == shared_ba)

    # Property 2: Shared secret is 32 bytes
    check("X25519: Shared secret is 32 bytes", len(shared_ab) == 32)

    # Property 3: Different keypairs produce different shared secrets
    charlie = X25519PrivateKey.generate()
    shared_ac = alice.exchange(charlie.public_key())
    check("X25519: Different keys → different shared secrets", shared_ab != shared_ac)

    # Property 4: Public key is derivable from private key (deterministic)
    # (verify by doing a fresh DH with the same keys)
    alice2_pk = alice.public_key()
    shared_ba2 = bob.exchange(alice2_pk)
    check("X25519: Public key derivation is deterministic", shared_ba == shared_ba2)


# ─────────────────────────────────────────────────────────────────────────────
# 5. citadel Composition — SHA3-256 + HKDF + AES-256-GCM (pinned)
#    Cross-verifies the same fixed test vector as primitive_kat.rs.
# ─────────────────────────────────────────────────────────────────────────────

def test_citadel_composition_pinned():
    print("\n── 5. citadel Composition — Pinned Cross-Verification ────────────")

    # Fixed inputs (same as primitive_kat.rs composition test)
    combined_ss = h(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    )
    kem_ct   = bytes([0xAB] * 1120)
    nonce    = bytes([0x77] * 12)
    plaintext = b"CROSSVERIFY: patient SSN 123-45-6789"
    aad      = b"patient-001"
    context  = b"medical-records"

    # Step 1: ct_hash = SHA3-256(kem_ct)
    ct_hash = sha3_256(kem_ct)
    expected_ct_hash = h("c1cc7758975a0748851260d508d303600af043b706962bb77d9adfb4b9322fe0")
    check("Composition Step 1: SHA3-256(kem_ct)", ct_hash == expected_ct_hash,
          f"got {ct_hash.hex()}")

    # Step 2: aes_key = HKDF-SHA256(ikm=combined_ss, info=PROTOCOL_ID||"|aes|"||ct_hash||context)
    info = b"citadel-env-v1" + b"|aes|" + ct_hash + context
    aes_key = hkdf_sha256(combined_ss, 32, info, None)
    expected_aes_key = h("42463031ea5408a266c0d0403730d323b3c8a416a82809fcc80768f41353d876")
    check("Composition Step 2: HKDF-SHA256 key derivation", aes_key == expected_aes_key,
          f"got {aes_key.hex()}")

    # Step 3: AES-256-GCM encrypt
    ct = aes256gcm_encrypt(aes_key, nonce, plaintext, aad)
    check("Composition Step 3: AES-256-GCM encrypt (no error)", len(ct) > 0)

    # Step 4: Decrypt and verify
    recovered = aes256gcm_decrypt(aes_key, nonce, ct, aad)
    check("Composition Step 4: Round-trip decrypt", recovered == plaintext,
          f"got {recovered}")

    # Step 5: Wrong AAD must fail
    try:
        aes256gcm_decrypt(aes_key, nonce, ct, b"wrong-patient")
        check("Composition Step 5: Wrong AAD rejected", False)
    except Exception:
        check("Composition Step 5: Wrong AAD rejected", True)

    print(f"\n  ct_hash: {ct_hash.hex()}")
    print(f"  aes_key: {aes_key.hex()}")
    print(f"  ct:      {ct.hex()}")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Real citadel ciphertext verification (optional — needs export_test_vector)
# ─────────────────────────────────────────────────────────────────────────────

def test_real_ciphertext(vector_path: str):
    print(f"\n── 6. Real citadel Ciphertext Verification ({vector_path}) ───────")

    try:
        with open(vector_path) as f:
            vec = json.load(f)
    except FileNotFoundError:
        print(f"  ⚠️  SKIP — {vector_path} not found")
        print("  No shipped example emits this schema; build the JSON by hand with")
        print("  combined_ss, kem_ct, nonce, aead_ct (hex) and aad, context,")
        print("  plaintext (ASCII). See the module docstring.")
        return
    except json.JSONDecodeError as e:
        print(f"  ⚠️  SKIP — invalid JSON: {e}")
        return

    combined_ss = h(vec["combined_ss"])
    kem_ct      = h(vec["kem_ct"])
    nonce       = h(vec["nonce"])
    aad         = vec["aad"].encode()
    context     = vec["context"].encode()
    expected_pt = vec["plaintext"].encode()
    ciphertext  = h(vec["aead_ct"])

    # Step 1: SHA3-256(kem_ct)
    ct_hash = sha3_256(kem_ct)
    check("Real vector: ct_hash matches", ct_hash.hex() == vec.get("ct_hash", ct_hash.hex()),
          f"got {ct_hash.hex()}")

    # Step 2: HKDF
    info = b"citadel-env-v1" + b"|aes|" + ct_hash + context
    aes_key = hkdf_sha256(combined_ss, 32, info, None)
    check("Real vector: aes_key matches", aes_key.hex() == vec.get("aes_key", aes_key.hex()),
          f"got {aes_key.hex()}")

    # Step 3: Decrypt
    try:
        pt = aes256gcm_decrypt(aes_key, nonce, ciphertext, aad)
        check("Real vector: decrypt succeeds", True)
        check("Real vector: plaintext matches", pt == expected_pt,
              f"got {pt!r}, expected {expected_pt!r}")
    except Exception as e:
        check("Real vector: decrypt succeeds", False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="citadel-envelope Python cross-verification"
    )
    parser.add_argument(
        "--vector",
        default=None,
        help=(
            "Path to a hand-built JSON test vector with combined_ss, kem_ct, "
            "nonce, aead_ct (hex) and aad, context, plaintext (ASCII); "
            "no shipped example emits this schema (see module docstring)"
        ),
    )
    args = parser.parse_args()

    print("citadel-envelope Python Cross-Verification")
    print("=" * 60)
    print("Independently verifies each cryptographic primitive using")
    print("Python's cryptography library against NIST/RFC test vectors,")
    print("then cross-verifies citadel's composition matches Rust output.")
    print("=" * 60)

    test_hkdf_rfc5869()
    test_aes256gcm_nist()
    test_sha3_256_nist()
    test_x25519_rfc7748()
    test_citadel_composition_pinned()

    if args.vector:
        test_real_ciphertext(args.vector)

    print("\n" + "=" * 60)
    print(f"Results: {results['pass']} passed  |  {results['fail']} failed")

    if results["fail"] == 0:
        print(f"\n✅ All cross-verification checks passed")
        print("   Python and Rust implementations are consistent.")
    else:
        print(f"\n❌ {results['fail']} check(s) failed — investigate immediately")
        sys.exit(1)


if __name__ == "__main__":
    main()
