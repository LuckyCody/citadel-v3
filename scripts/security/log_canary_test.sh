#!/bin/bash
# Canary-based log leakage test for Citadel.
#
# Injects unique canary strings as plaintext, AAD, context, and API key values,
# runs encrypt/decrypt/error cycles, then greps ALL server output for leaked
# canary values. Much stronger than keyword-based grep.
#
# Prerequisites:
#   - Citadel server running with output captured to a log file
#   - Server log path passed as $1 (or CITADEL_LOG_FILE env var)
#
# Usage:
#   # Start server with log capture:
#   CITADEL_MASTER_KEY=... citadel-api > /tmp/citadel-canary.log 2>&1 &
#   # Then:
#   bash log_canary_test.sh /tmp/citadel-canary.log

set -euo pipefail

BASE_URL="${CITADEL_URL:-http://localhost:3000}"
API_KEY="${CITADEL_API_KEY:-redteam-test-key}"
LOG_FILE="${1:-${CITADEL_LOG_FILE:-/tmp/citadel-canary.log}}"

AUTH="Authorization: Bearer $API_KEY"
CT="Content-Type: application/json"

# Generate unique canary values
CANARY_SUFFIX=$(openssl rand -hex 8)
CANARY_PLAINTEXT="LEAK_CANARY_PLAINTEXT_${CANARY_SUFFIX}"
CANARY_AAD="LEAK_CANARY_AAD_${CANARY_SUFFIX}"
CANARY_CTX="LEAK_CANARY_CTX_${CANARY_SUFFIX}"
CANARY_APIKEY="LEAK_CANARY_APIKEY_${CANARY_SUFFIX}"

# Convert plaintext canary to hex for the API
CANARY_PLAINTEXT_HEX=$(echo -n "$CANARY_PLAINTEXT" | xxd -p | tr -d '\n')

PASS=0
FAIL=0

echo "============================================"
echo "  CANARY LOG LEAKAGE TEST"
echo "  Log file: $LOG_FILE"
echo "============================================"
echo ""
echo "Canary values (these must NOT appear in logs):"
echo "  Plaintext: $CANARY_PLAINTEXT"
echo "  AAD:       $CANARY_AAD"
echo "  Context:   $CANARY_CTX"
echo "  API key:   $CANARY_APIKEY"
echo ""

# Record the log file size before our operations
LOG_START=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)

# ── Setup: create test keys ──

echo "── Setting up test keys ──"

ROOT_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d '{"name":"canary-root","key_type":"Root"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$ROOT_ID/activate" -d '{}' > /dev/null

DOMAIN_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"canary-domain\",\"key_type\":\"Domain\",\"parent_id\":\"$ROOT_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DOMAIN_ID/activate" -d '{}' > /dev/null

KEK_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"canary-kek\",\"key_type\":\"KeyEncrypting\",\"parent_id\":\"$DOMAIN_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$KEK_ID/activate" -d '{}' > /dev/null

DEK_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"canary-dek\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/activate" -d '{}' > /dev/null

echo "  Keys created and activated."
echo ""

# ── Exercise paths with canary values ──

echo "── Exercising API paths with canary values ──"

# 1. Encrypt with canary plaintext, AAD, context
echo -n "  Encrypting with canary values... "
BLOB=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DEK_ID/encrypt" \
    -d "{\"plaintext\":\"$CANARY_PLAINTEXT_HEX\",\"aad\":\"$CANARY_AAD\",\"context\":\"$CANARY_CTX\"}")
echo "done"

# 2. Decrypt successfully (canary plaintext in response)
echo -n "  Decrypting with canary values... "
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/decrypt" \
    -d "{\"blob\":$BLOB,\"aad\":\"$CANARY_AAD\",\"context\":\"$CANARY_CTX\"}" > /dev/null
echo "done"

# 3. Decrypt with wrong canary AAD (error path)
echo -n "  Triggering wrong-AAD error with canary... "
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/decrypt" \
    -d "{\"blob\":$BLOB,\"aad\":\"WRONG_${CANARY_AAD}\",\"context\":\"$CANARY_CTX\"}" > /dev/null 2>&1 || true
echo "done"

# 4. Decrypt with wrong canary context (error path)
echo -n "  Triggering wrong-context error with canary... "
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/decrypt" \
    -d "{\"blob\":$BLOB,\"aad\":\"$CANARY_AAD\",\"context\":\"WRONG_${CANARY_CTX}\"}" > /dev/null 2>&1 || true
echo "done"

# 5. Auth with canary API key (should fail)
echo -n "  Triggering auth failure with canary API key... "
curl -sf -H "Authorization: Bearer $CANARY_APIKEY" -H "$CT" "$BASE_URL/api/status" > /dev/null 2>&1 || true
echo "done"

# 6. Encrypt with canary plaintext to a non-encrypt key (error path)
echo -n "  Triggering key-type error with canary plaintext... "
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$KEK_ID/encrypt" \
    -d "{\"plaintext\":\"$CANARY_PLAINTEXT_HEX\",\"aad\":\"$CANARY_AAD\",\"context\":\"$CANARY_CTX\"}" > /dev/null 2>&1 || true
echo "done"

echo ""

# Give the server a moment to flush logs
sleep 1

# ── Check for canary leakage ──

echo "── Scanning logs for canary leakage ──"
echo ""

# Extract only the new log entries since our test started
LOG_NEW=$(tail -c +"$((LOG_START + 1))" "$LOG_FILE" 2>/dev/null || cat "$LOG_FILE")

check_canary() {
    local label="$1"
    local canary="$2"

    if echo "$LOG_NEW" | grep -qF "$canary"; then
        echo "  [FAIL] $label leaked in logs"
        # Show the offending lines
        echo "$LOG_NEW" | grep -nF "$canary" | head -5 | while read -r line; do
            echo "         >>> $line"
        done
        FAIL=$((FAIL+1))
    else
        echo "  [PASS] $label not found in logs"
        PASS=$((PASS+1))
    fi
}

check_canary "Plaintext canary"     "$CANARY_PLAINTEXT"
check_canary "Plaintext hex canary" "$CANARY_PLAINTEXT_HEX"
check_canary "AAD canary"           "$CANARY_AAD"
check_canary "Context canary"       "$CANARY_CTX"
check_canary "API key canary"       "$CANARY_APIKEY"
check_canary "Canary suffix"        "$CANARY_SUFFIX"

echo ""
echo "============================================"
echo "  CANARY LEAKAGE: $PASS PASSED, $FAIL FAILED"
echo "============================================"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "FINDING: Server logs contain actual secret values."
    echo "Each leaked canary indicates a log statement that must be fixed."
    exit 1
else
    echo ""
    echo "No canary values leaked to server logs."
    exit 0
fi
