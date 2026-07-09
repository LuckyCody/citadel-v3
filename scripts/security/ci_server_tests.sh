#!/bin/bash
# CI-ready live server test runner.
# Manages its own server lifecycle, uses relative paths, no hardcoded machine paths.
#
# Usage from the citadel_v3 workspace root:
#   bash ../../ci_server_tests.sh
#
# Or with CITADEL_SCRIPTS_DIR set:
#   CITADEL_SCRIPTS_DIR=/path/to/citadel bash ci_server_tests.sh
#
# Expects citadel-api binary at ./target/release/citadel-api

set -euo pipefail

SCRIPT_DIR="${CITADEL_SCRIPTS_DIR:-$(cd "$(dirname "$0")" && pwd)}"
WORKSPACE_DIR="${CITADEL_WORKSPACE_DIR:-$(pwd)}"
BINARY="${WORKSPACE_DIR}/target/release/citadel-api"
DATA_DIR=$(mktemp -d /tmp/citadel-ci-XXXXXX)
LOG_FILE="$DATA_DIR/server.log"

if [ ! -f "$BINARY" ]; then
    echo "[FATAL] Binary not found: $BINARY"
    echo "Build first: cargo build -p citadel-api --release"
    exit 1
fi

export CITADEL_MASTER_KEY=$(openssl rand -hex 32)
export CITADEL_API_KEY="ci-test-key-$(openssl rand -hex 4)"
HASH_OUTPUT=$(echo -n "$CITADEL_API_KEY" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$CITADEL_MASTER_KEY)
export CITADEL_API_KEY_HASH=$(echo "$HASH_OUTPUT" | awk '{print $NF}')
export CITADEL_ENV=development
export CITADEL_ALLOW_PLAINTEXT_KEYS=1
export CITADEL_DATA_DIR="$DATA_DIR"
export CITADEL_RATE_LIMIT_RPS=10000
export CITADEL_RATE_LIMIT_BURST=20000
export CITADEL_URL="http://localhost:3000"

SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

TOTAL_PASS=0
TOTAL_FAIL=0

echo "============================================"
echo "  CI SERVER TEST SUITE"
echo "  Scripts: $SCRIPT_DIR"
echo "  Binary:  $BINARY"
echo "============================================"
echo ""

# ── Test 1: Persistence / restart (manages own server) ──

echo "══ TEST 1: Persistence / Restart ══"
echo ""
if CITADEL_DIR="$WORKSPACE_DIR" bash "$SCRIPT_DIR/persistence_server_test.sh" 2>&1; then
    echo "  RESULT: PASS"
    TOTAL_PASS=$((TOTAL_PASS + 1))
else
    echo "  RESULT: FAIL"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi
echo ""

# ── Start server for remaining tests ──

echo "══ Starting server for live tests ══"
$BINARY > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "  PID: $SERVER_PID"

for i in $(seq 1 30); do
    if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
        echo "  Healthy after ${i}s"
        break
    fi
    sleep 1
done
echo ""

# ── Test 2: Concurrency stress ──

echo "══ TEST 2: Concurrency Stress ══"
echo ""
if bash "$SCRIPT_DIR/concurrency_stress.sh" 20 10 2>&1; then
    echo "  RESULT: PASS"
    TOTAL_PASS=$((TOTAL_PASS + 1))
else
    echo "  RESULT: FAIL"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi
echo ""

# ── Test 3: Canary log leakage ──

echo "══ TEST 3: Canary Log Leakage ══"
echo ""
if bash "$SCRIPT_DIR/log_canary_test.sh" "$LOG_FILE" 2>&1; then
    echo "  RESULT: PASS"
    TOTAL_PASS=$((TOTAL_PASS + 1))
else
    echo "  RESULT: FAIL"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi
echo ""

# ── Test 4: Schemathesis (if installed) ──

echo "══ TEST 4: Schemathesis API Fuzzing ══"
echo ""
ST_CMD=""
for candidate in schemathesis "$HOME/.local/bin/schemathesis"; do
    if command -v "$candidate" &>/dev/null || [ -x "$candidate" ]; then
        ST_CMD="$candidate"
        break
    fi
done

if [ -n "$ST_CMD" ] && [ -f "$SCRIPT_DIR/openapi.yaml" ]; then
    if $ST_CMD run "$SCRIPT_DIR/openapi.yaml" \
        --url http://localhost:3000 \
        -H "Authorization:Bearer $CITADEL_API_KEY" \
        -n 500 \
        -c not_a_server_error,status_code_conformance,response_schema_conformance \
        --no-color 2>&1; then
        echo "  RESULT: PASS"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        echo "  RESULT: FAIL"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
else
    echo "  SKIPPED (schemathesis not installed or openapi.yaml not found)"
fi
echo ""

# ── Summary ──

echo "============================================"
echo "  CI SERVER TESTS: $TOTAL_PASS PASS, $TOTAL_FAIL FAIL"
echo "============================================"

if [ $TOTAL_FAIL -gt 0 ]; then
    exit 1
fi
