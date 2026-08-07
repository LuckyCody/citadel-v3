#!/bin/bash
# Concurrency stress test for Citadel.
#
# Fires concurrent HTTP requests to expose TOCTOU races, double-operations,
# and authorization bypass under load. Uses curl + background jobs (no extra deps).
#
# Safety:
#   - Binds only to localhost:8443
#   - Never touches Ollama or ports 11434/11435/8090/8091
#   - Cleans up only its own background jobs
#
# Prerequisites:
#   - Citadel server running on localhost:8443
#   - curl, python3
#
# Usage:
#   bash concurrency_stress.sh [ROUNDS] [CONCURRENCY]
#   Default: 100 rounds, 50 concurrent requests per round
#
# Artifact: citadel/concurrency_stress_report.md

set -euo pipefail

BASE_URL="${CITADEL_URL:-http://localhost:8443}"
API_KEY="${CITADEL_API_KEY:-redteam-test-key}"
ROUNDS="${1:-100}"
CONCURRENCY="${2:-50}"
REPORT_DIR="${CITADEL_REPORT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
REPORT_FILE="$REPORT_DIR/concurrency_stress_report.md"
TMPDIR=$(mktemp -d /tmp/citadel-concurrency-XXXXXX)

AUTH="Authorization: Bearer $API_KEY"
CT="Content-Type: application/json"

PASS=0
FAIL=0
PANIC=0

echo "============================================"
echo "  CITADEL CONCURRENCY STRESS TEST"
echo "  Rounds: $ROUNDS"
echo "  Concurrency: $CONCURRENCY"
echo "  Temp: $TMPDIR"
echo "============================================"
echo ""

# ── Setup: create key hierarchy ──

echo "── Setting up test keys ──"

ROOT_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d '{"name":"conc-root","key_type":"Root"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$ROOT_ID/activate" -d '{}' > /dev/null

DOMAIN_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"conc-domain\",\"key_type\":\"Domain\",\"parent_id\":\"$ROOT_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DOMAIN_ID/activate" -d '{}' > /dev/null

KEK_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"conc-kek\",\"key_type\":\"KeyEncrypting\",\"parent_id\":\"$DOMAIN_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$KEK_ID/activate" -d '{}' > /dev/null

echo "  Hierarchy ready."
echo ""

# ── Scenario 1: Concurrent decrypts of same blob ──
# Invariant: decrypt must either succeed or fail, never panic.
# With replay protection, at most one decrypt should succeed per nonce.

echo "── Scenario 1: Concurrent decrypt ($CONCURRENCY parallel, $ROUNDS rounds) ──"

SCENARIO1_SUCCESS=0
SCENARIO1_FAILURE=0
SCENARIO1_PANIC=0

for round in $(seq 1 $ROUNDS); do
    # Create a fresh DEK and blob each round
    DEK_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
        -d "{\"name\":\"conc-dek-$round\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
    curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/activate" -d '{}' > /dev/null

    BLOB=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/encrypt" \
        -d '{"plaintext":"636f6e63757272656e6379","aad":"conc-aad","context":"conc-ctx"}')

    BODY="{\"blob\":$BLOB,\"aad\":\"conc-aad\",\"context\":\"conc-ctx\"}"

    # Fire concurrent decrypts
    round_success=0
    round_fail=0
    for j in $(seq 1 $CONCURRENCY); do
        curl -o "$TMPDIR/r${round}_${j}.out" -w '%{http_code}' \
            -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/decrypt" \
            -d "$BODY" > "$TMPDIR/r${round}_${j}.code" 2>/dev/null &
    done
    wait

    for j in $(seq 1 $CONCURRENCY); do
        code=$(cat "$TMPDIR/r${round}_${j}.code" 2>/dev/null || echo "000")
        if [ "$code" = "200" ]; then
            round_success=$((round_success + 1))
        elif [ "$code" = "000" ] || [ "$code" = "500" ]; then
            SCENARIO1_PANIC=$((SCENARIO1_PANIC + 1))
        else
            round_fail=$((round_fail + 1))
        fi
    done

    SCENARIO1_SUCCESS=$((SCENARIO1_SUCCESS + round_success))
    SCENARIO1_FAILURE=$((SCENARIO1_FAILURE + round_fail))

    # Progress every 10 rounds
    if [ $((round % 10)) -eq 0 ]; then
        echo "  Round $round/$ROUNDS done (this round: ${round_success} success, ${round_fail} fail)"
    fi
done

echo "  Total: $SCENARIO1_SUCCESS success, $SCENARIO1_FAILURE fail, $SCENARIO1_PANIC panic/5xx"
if [ $SCENARIO1_PANIC -gt 0 ]; then
    echo "  [FAIL] $SCENARIO1_PANIC panics or 5xx responses detected"
    FAIL=$((FAIL + 1))
else
    echo "  [PASS] Zero panics under concurrent decrypt"
    PASS=$((PASS + 1))
fi
echo ""

# ── Scenario 2: Concurrent revoke while encrypting ──
# Invariant: after revoke succeeds, no subsequent encrypt should succeed.

echo "── Scenario 2: Revoke-while-encrypting ($ROUNDS rounds) ──"

SCENARIO2_ENCRYPT_AFTER_REVOKE=0
SCENARIO2_OK=0

for round in $(seq 1 $ROUNDS); do
    DEK_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
        -d "{\"name\":\"conc-revoke-$round\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
    curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/activate" -d '{}' > /dev/null

    # Fire revoke and encrypts simultaneously
    curl -o "$TMPDIR/revoke_${round}.out" -w '%{http_code}' \
        -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/revoke" \
        -d '{"reason":"concurrency test"}' > "$TMPDIR/revoke_${round}.code" 2>/dev/null &

    for j in $(seq 1 5); do
        curl -o "$TMPDIR/enc_${round}_${j}.out" -w '%{http_code}' \
            -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/encrypt" \
            -d '{"plaintext":"636f6e63","aad":"conc-aad","context":"conc-ctx"}' \
            > "$TMPDIR/enc_${round}_${j}.code" 2>/dev/null &
    done
    wait

    # Check: after revoke completed, did any encrypt succeed?
    revoke_code=$(cat "$TMPDIR/revoke_${round}.code" 2>/dev/null || echo "000")
    if [ "$revoke_code" = "200" ]; then
        # Revoke succeeded — now verify the key is really revoked
        post_check=$(curl -o /dev/null -w '%{http_code}' \
            -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/encrypt" \
            -d '{"plaintext":"636f6e63","aad":"conc-aad","context":"conc-ctx"}' 2>/dev/null || echo "000")
        if [ "$post_check" = "200" ]; then
            SCENARIO2_ENCRYPT_AFTER_REVOKE=$((SCENARIO2_ENCRYPT_AFTER_REVOKE + 1))
        else
            SCENARIO2_OK=$((SCENARIO2_OK + 1))
        fi
    fi
done

echo "  Rounds: $ROUNDS, post-revoke encrypt failures: $SCENARIO2_OK, post-revoke encrypt successes: $SCENARIO2_ENCRYPT_AFTER_REVOKE"
if [ $SCENARIO2_ENCRYPT_AFTER_REVOKE -gt 0 ]; then
    echo "  [FAIL] $SCENARIO2_ENCRYPT_AFTER_REVOKE encrypts succeeded AFTER revoke completed"
    FAIL=$((FAIL + 1))
else
    echo "  [PASS] Revoked keys cannot encrypt after revoke completes"
    PASS=$((PASS + 1))
fi
echo ""

# ── Scenario 3: Concurrent destroy while decrypting ──
# Invariant: no panics. Decrypt may succeed or fail, never crash.

echo "── Scenario 3: Destroy-while-decrypting ($ROUNDS rounds) ──"

SCENARIO3_PANIC=0

for round in $(seq 1 $ROUNDS); do
    DEK_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
        -d "{\"name\":\"conc-destroy-$round\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
    curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/activate" -d '{}' > /dev/null

    BLOB=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/encrypt" \
        -d '{"plaintext":"636f6e63","aad":"conc-aad","context":"conc-ctx"}')
    BODY="{\"blob\":$BLOB,\"aad\":\"conc-aad\",\"context\":\"conc-ctx\"}"

    # Revoke first (required before destroy)
    curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/revoke" \
        -d '{"reason":"concurrency test"}' > /dev/null 2>&1

    # Fire destroy and decrypt simultaneously
    curl -o /dev/null -w '%{http_code}' \
        -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/destroy" \
        -d '{}' > "$TMPDIR/destroy_${round}.code" 2>/dev/null &

    for j in $(seq 1 5); do
        curl -o "$TMPDIR/dec_${round}_${j}.out" -w '%{http_code}' \
            -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/decrypt" \
            -d "$BODY" > "$TMPDIR/dec_${round}_${j}.code" 2>/dev/null &
    done
    wait

    # Check for 5xx/panics
    for j in $(seq 1 5); do
        code=$(cat "$TMPDIR/dec_${round}_${j}.code" 2>/dev/null || echo "000")
        if [ "$code" = "500" ] || [ "$code" = "000" ]; then
            SCENARIO3_PANIC=$((SCENARIO3_PANIC + 1))
        fi
    done
done

if [ $SCENARIO3_PANIC -gt 0 ]; then
    echo "  [FAIL] $SCENARIO3_PANIC panics/5xx during destroy-while-decrypt"
    FAIL=$((FAIL + 1))
else
    echo "  [PASS] Zero panics under concurrent destroy+decrypt"
    PASS=$((PASS + 1))
fi
echo ""

# ── Cleanup ──
rm -rf "$TMPDIR"

# ── Report ──

echo "============================================"
echo "  CONCURRENCY STRESS: $PASS PASSED, $FAIL FAILED"
echo "============================================"

cat > "$REPORT_FILE" << MEOF
# Citadel Concurrency Stress Report

- **Date:** $(date '+%Y-%m-%d %H:%M:%S')
- **Rounds:** $ROUNDS
- **Concurrency:** $CONCURRENCY per round
- **Build mode:** release

## Results

| Scenario | Result |
|---|---|
| Concurrent decrypt (no panic) | $( [ $SCENARIO1_PANIC -eq 0 ] && echo "PASS" || echo "FAIL ($SCENARIO1_PANIC panics)" ) |
| Revoke-while-encrypting | $( [ $SCENARIO2_ENCRYPT_AFTER_REVOKE -eq 0 ] && echo "PASS" || echo "FAIL ($SCENARIO2_ENCRYPT_AFTER_REVOKE post-revoke encrypts)" ) |
| Destroy-while-decrypting (no panic) | $( [ $SCENARIO3_PANIC -eq 0 ] && echo "PASS" || echo "FAIL ($SCENARIO3_PANIC panics)" ) |

## Counts

- Scenario 1: $SCENARIO1_SUCCESS successful decrypts, $SCENARIO1_FAILURE failed, $SCENARIO1_PANIC panics across $ROUNDS rounds x $CONCURRENCY concurrent
- Scenario 2: $SCENARIO2_OK correct post-revoke rejections, $SCENARIO2_ENCRYPT_AFTER_REVOKE unauthorized post-revoke encrypts
- Scenario 3: $SCENARIO3_PANIC panics/5xx during $ROUNDS rounds of destroy+decrypt races

## Overall: $PASS PASSED, $FAIL FAILED
MEOF

echo "Report: $REPORT_FILE"

if [ $FAIL -gt 0 ]; then
    exit 1
else
    exit 0
fi
