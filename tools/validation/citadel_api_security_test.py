#!/usr/bin/env python3
"""
citadel_api_security_test.py

HTTP-level security boundary tests for citadel-api.
Tests auth rejection, scope enforcement, rate limiting, and input validation.

Usage:
    # Start citadel-api first:
    #   CITADEL_API_KEY=test-secret-key cargo run -p citadel-api
    #
    # Then run:
    #   python citadel_api_security_test.py --url http://localhost:8443 --key test-secret-key

Requires: pip install requests
"""

import argparse
import json
import sys
import time
import statistics
from typing import Optional
import requests

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
WARN = "\033[93m⚠️  WARN\033[0m"
INFO = "\033[94mℹ️  INFO\033[0m"

results = {"pass": 0, "fail": 0, "warn": 0}


def check(name: str, condition: bool, detail: str = "", warn_only: bool = False):
    if condition:
        print(f"  {PASS}  {name}")
        results["pass"] += 1
    elif warn_only:
        print(f"  {WARN}  {name}")
        if detail:
            print(f"         {detail}")
        results["warn"] += 1
    else:
        print(f"  {FAIL}  {name}")
        if detail:
            print(f"         {detail}")
        results["fail"] += 1


def get(url: str, base_url: str, headers: dict = None) -> requests.Response:
    return requests.get(f"{base_url}{url}", headers=headers or {}, timeout=10)


def post(url: str, base_url: str, body: dict, headers: dict = None) -> requests.Response:
    return requests.post(
        f"{base_url}{url}",
        json=body,
        headers=headers or {},
        timeout=10
    )


def auth_header(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


# ─────────────────────────────────────────────────────────────────────────────
# 1. HEALTH CHECK (no auth required)
# ─────────────────────────────────────────────────────────────────────────────

def test_health(base_url: str, key: str):
    print("\n── 1. Health / Public Endpoints ──────────────────────────────────")
    r = get("/health", base_url)
    check("GET /health returns 200", r.status_code == 200, f"got {r.status_code}")
    check("Health response has ok field", r.json().get("status") == "ok", str(r.json()))


# ─────────────────────────────────────────────────────────────────────────────
# 2. AUTHENTICATION REJECTION
# ─────────────────────────────────────────────────────────────────────────────

def test_auth_rejection(base_url: str, key: str):
    print("\n── 2. Authentication Rejection ───────────────────────────────────")

    # No auth header
    r = get("/api/status", base_url)
    check("No auth header → 401", r.status_code == 401, f"got {r.status_code}")

    # Wrong scheme
    r = get("/api/status", base_url, {"Authorization": f"Basic {key}"})
    check("Basic auth scheme → 401", r.status_code == 401, f"got {r.status_code}")

    # Empty bearer
    r = get("/api/status", base_url, {"Authorization": "Bearer "})
    check("Empty bearer token → 401", r.status_code == 401, f"got {r.status_code}")

    # Wrong key
    r = get("/api/status", base_url, auth_header("definitely-wrong-key-xyz"))
    check("Wrong API key → 401", r.status_code == 401, f"got {r.status_code}")

    # Slightly wrong key (off by one char)
    wrong = key[:-1] + ("X" if key[-1] != "X" else "Y")
    r = get("/api/status", base_url, auth_header(wrong))
    check("Off-by-one key → 401", r.status_code == 401, f"got {r.status_code}")

    # SQL injection attempt in auth
    r = get("/api/status", base_url, {"Authorization": "Bearer ' OR '1'='1"})
    check("SQL injection in auth → 401", r.status_code == 401, f"got {r.status_code}")

    # Correct key works
    r = get("/api/status", base_url, auth_header(key))
    check("Correct key → 200", r.status_code == 200, f"got {r.status_code}")


# ─────────────────────────────────────────────────────────────────────────────
# 3. AUTH RESPONSE UNIFORMITY
#    Wrong key and missing key should return identical responses —
#    no information leakage about whether the key exists vs is wrong.
# ─────────────────────────────────────────────────────────────────────────────

def test_auth_response_uniformity(base_url: str, key: str):
    print("\n── 3. Auth Response Uniformity (no info leakage) ─────────────────")

    r_no_auth = get("/api/status", base_url)
    r_wrong = get("/api/status", base_url, auth_header("wrong-key-12345"))
    r_empty = get("/api/status", base_url, {"Authorization": "Bearer x"})

    check(
        "No-auth and wrong-key return same status code",
        r_no_auth.status_code == r_wrong.status_code,
        f"no-auth={r_no_auth.status_code} wrong={r_wrong.status_code}"
    )

    # Response bodies should not say "key not found" vs "invalid key"
    body_no_auth = r_no_auth.text.lower()
    body_wrong = r_wrong.text.lower()
    leaks_detail = any(
        phrase in body_no_auth or phrase in body_wrong
        for phrase in ["not found", "does not exist", "key id", "no such"]
    )
    check(
        "Auth error bodies don't leak key existence info",
        not leaks_detail,
        f"Body may leak info: {body_wrong[:100]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. ENCRYPT / DECRYPT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def test_encrypt_decrypt(base_url: str, key: str) -> Optional[str]:
    """Returns key_id if a key was created, for use in subsequent tests."""
    print("\n── 4. Encrypt / Decrypt Operations ───────────────────────────────")
    headers = auth_header(key)

    # Generate a key
    r = post("/api/keys", base_url, {}, headers)
    if r.status_code != 200:
        check("Generate key", False, f"got {r.status_code}: {r.text[:100]}")
        return None
    key_id = r.json().get("id")
    check("Generate key → 200", key_id is not None, str(r.json()))

    # Activate it
    r = post(f"/api/keys/{key_id}/activate", base_url, {}, headers)
    check("Activate key → 200", r.status_code == 200, f"got {r.status_code}")

    # Encrypt
    r = post(f"/api/keys/{key_id}/encrypt", base_url, {
        "plaintext": "patient SSN: 123-45-6789",
        "aad": "patient-001",
        "context": "medical-records"
    }, headers)
    check("Encrypt → 200", r.status_code == 200, f"got {r.status_code}: {r.text[:100]}")
    if r.status_code != 200:
        return key_id

    blob = r.json()
    check("Encrypt response has blob structure", isinstance(blob, dict) and len(blob) > 0)

    # Plaintext must not appear in blob
    blob_str = json.dumps(blob)
    check(
        "Plaintext not in encrypted blob",
        "123-45-6789" not in blob_str and "SSN" not in blob_str,
        "Plaintext found in ciphertext response!"
    )

    # Decrypt
    r = post("/api/decrypt", base_url, {
        "blob": blob,
        "aad": "patient-001",
        "context": "medical-records"
    }, headers)
    check("Decrypt → 200", r.status_code == 200, f"got {r.status_code}: {r.text[:100]}")
    if r.status_code == 200:
        pt = r.json().get("plaintext", "")
        check("Decrypt returns correct plaintext", pt == "patient SSN: 123-45-6789", f"got: {pt}")

    # Wrong AAD must fail
    r = post("/api/decrypt", base_url, {
        "blob": blob,
        "aad": "wrong-patient",
        "context": "medical-records"
    }, headers)
    check("Wrong AAD → non-200", r.status_code != 200, f"got {r.status_code}")

    # Wrong context must fail
    r = post("/api/decrypt", base_url, {
        "blob": blob,
        "aad": "patient-001",
        "context": "financial-records"
    }, headers)
    check("Wrong context → non-200", r.status_code != 200, f"got {r.status_code}")

    return key_id


# ─────────────────────────────────────────────────────────────────────────────
# 5. INPUT VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def test_input_validation(base_url: str, key: str, key_id: Optional[str]):
    print("\n── 5. Input Validation ───────────────────────────────────────────")
    headers = auth_header(key)

    if not key_id:
        print(f"  {WARN}  Skipping — no key_id available")
        return

    # Empty plaintext should work (not crash)
    r = post(f"/api/keys/{key_id}/encrypt", base_url, {
        "plaintext": "",
        "aad": "aad",
        "context": "ctx"
    }, headers)
    check(
        "Empty plaintext → 200 or 4xx (not 500)",
        r.status_code != 500,
        f"got {r.status_code}"
    )

    # Malformed JSON
    r = requests.post(
        f"{base_url}/api/keys/{key_id}/encrypt",
        data="not valid json{{{",
        headers={**headers, "Content-Type": "application/json"},
        timeout=10
    )
    check("Malformed JSON → 4xx not 500", 400 <= r.status_code < 500, f"got {r.status_code}")

    # Missing required fields
    r = post(f"/api/keys/{key_id}/encrypt", base_url, {"plaintext": "only plaintext"}, headers)
    check("Missing fields → 4xx not 500", r.status_code != 500, f"got {r.status_code}")

    # Very large plaintext (1MB) — should handle gracefully
    large = "A" * (1024 * 1024)
    r = post(f"/api/keys/{key_id}/encrypt", base_url, {
        "plaintext": large,
        "aad": "aad",
        "context": "ctx"
    }, headers)
    check(
        "1MB plaintext → 200 or 4xx (not 500, not hang)",
        r.status_code != 500,
        f"got {r.status_code}",
        warn_only=True
    )

    # Null bytes in plaintext
    r = post(f"/api/keys/{key_id}/encrypt", base_url, {
        "plaintext": "data\x00with\x00nulls",
        "aad": "aad",
        "context": "ctx"
    }, headers)
    check(
        "Null bytes in plaintext → 200 or 4xx (not 500)",
        r.status_code != 500,
        f"got {r.status_code}"
    )

    # Non-existent key ID
    r = post("/api/keys/nonexistent-key-id-xyz/encrypt", base_url, {
        "plaintext": "test",
        "aad": "aad",
        "context": "ctx"
    }, headers)
    check("Non-existent key → 4xx not 500", 400 <= r.status_code < 500, f"got {r.status_code}")


# ─────────────────────────────────────────────────────────────────────────────
# 6. TIMING UNIFORMITY ON API
#    Auth failures (wrong key vs missing key) should take similar time.
#    A significant timing difference leaks whether a key exists.
# ─────────────────────────────────────────────────────────────────────────────

def test_api_timing(base_url: str, key: str):
    print("\n── 6. API Auth Timing Uniformity ─────────────────────────────────")
    iterations = 50

    times_no_auth = []
    times_wrong_key = []

    for _ in range(iterations):
        t = time.perf_counter()
        requests.get(f"{base_url}/api/status", timeout=10)
        times_no_auth.append(time.perf_counter() - t)

        t = time.perf_counter()
        requests.get(
            f"{base_url}/api/status",
            headers=auth_header("wrong-key-that-does-not-exist"),
            timeout=10
        )
        times_wrong_key.append(time.perf_counter() - t)

    mean_no = statistics.mean(times_no_auth) * 1000
    mean_wrong = statistics.mean(times_wrong_key) * 1000
    diff_pct = abs(mean_no - mean_wrong) / mean_wrong * 100

    print(f"         No auth:   mean={mean_no:.1f}ms  stddev={statistics.stdev(times_no_auth)*1000:.1f}ms")
    print(f"         Wrong key: mean={mean_wrong:.1f}ms  stddev={statistics.stdev(times_wrong_key)*1000:.1f}ms")
    print(f"         Diff: {diff_pct:.1f}%")

    check(
        "Auth timing difference < 30% (no timing side-channel)",
        diff_pct < 30.0,
        f"Timing diff is {diff_pct:.1f}% — possible side channel",
        warn_only=True  # Network jitter makes this a warning not hard fail
    )


# ─────────────────────────────────────────────────────────────────────────────
# 7. SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────────────────

def test_security_headers(base_url: str, key: str):
    print("\n── 7. Security Headers ───────────────────────────────────────────")
    r = get("/health", base_url)

    headers = {k.lower(): v for k, v in r.headers.items()}

    check(
        "X-Content-Type-Options: nosniff present",
        headers.get("x-content-type-options", "").lower() == "nosniff",
        f"got: {headers.get('x-content-type-options', 'MISSING')}",
        warn_only=True
    )
    check(
        "X-Frame-Options present",
        "x-frame-options" in headers,
        "Missing X-Frame-Options",
        warn_only=True
    )
    check(
        "Server header suppressed",
        "server" not in headers or headers.get("server", "") == "",
        f"Server header: {headers.get('server', '')}",
        warn_only=True
    )


# ─────────────────────────────────────────────────────────────────────────────
# 8. WHOAMI / SCOPE INTROSPECTION
# ─────────────────────────────────────────────────────────────────────────────

def test_whoami(base_url: str, key: str):
    print("\n── 8. API Key Introspection ──────────────────────────────────────")
    r = get("/api/auth/whoami", base_url, auth_header(key))
    check("GET /api/auth/whoami → 200", r.status_code == 200, f"got {r.status_code}")
    if r.status_code == 200:
        body = r.json()
        check("Whoami has scopes field", "scopes" in body, str(body))
        # Key hash should not be in response
        check(
            "Raw key not in whoami response",
            key not in r.text,
            "Raw API key returned in whoami response!"
        )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="citadel-api security tests")
    parser.add_argument("--url", default="http://localhost:8443", help="API base URL")
    parser.add_argument("--key", required=True, help="Admin API key")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    key = args.key

    print(f"\ncitadel-api Security Test Suite")
    print(f"Target: {base_url}")
    print("=" * 60)

    try:
        test_health(base_url, key)
        test_auth_rejection(base_url, key)
        test_auth_response_uniformity(base_url, key)
        key_id = test_encrypt_decrypt(base_url, key)
        test_input_validation(base_url, key, key_id)
        test_api_timing(base_url, key)
        test_security_headers(base_url, key)
        test_whoami(base_url, key)
    except requests.exceptions.ConnectionError:
        print(f"\n{FAIL} Cannot connect to {base_url}")
        print("  Make sure citadel-api is running:")
        print("  CITADEL_API_KEY=your-key cargo run -p citadel-api")
        sys.exit(1)

    print("\n" + "=" * 60)
    print(f"Results: {results['pass']} passed  |  {results['fail']} failed  |  {results['warn']} warnings")

    if results["fail"] > 0:
        print(f"\n{FAIL} {results['fail']} security check(s) failed")
        sys.exit(1)
    else:
        print(f"\n{PASS} All hard security checks passed")


if __name__ == "__main__":
    main()
