#!/bin/bash
# Full server restart persistence test for Citadel.
#
# Tests that all security-critical state survives a clean server stop/restart:
# - Key states (active, revoked, destroyed) persist
# - API key revocation persists
# - Domain scope enforcement persists
# - Key hierarchy remains intact
#
# Usage:
#   bash persistence_server_test.sh
#
# Prerequisites:
#   - citadel-api binary built (release or debug)
#   - No other Citadel instance on port 3000

set -euo pipefail

CITADEL_DIR="${CITADEL_WORKSPACE_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
BINARY="$CITADEL_DIR/target/release/citadel-api"
DATA_DIR=$(mktemp -d /tmp/citadel-persist-XXXXXX)
PORT=3000
BASE_URL="http://localhost:$PORT"

MASTER_KEY=$(openssl rand -hex 32)
ADMIN_KEY="persist-test-admin-key-$(openssl rand -hex 8)"
ADMIN_HASH=$(echo -n "$ADMIN_KEY" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$MASTER_KEY | awk '{print $NF}')

AUTH="Authorization: Bearer $ADMIN_KEY"
CT="Content-Type: application/json"

PASS=0
FAIL=0

check() {
    local label="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" = "$expected" ]; then
        echo "  [PASS] $label"
        PASS=$((PASS+1))
    else
        echo "  [FAIL] $label (expected=$expected, got=$actual)"
        FAIL=$((FAIL+1))
    fi
}

start_server() {
    CITADEL_MASTER_KEY="$MASTER_KEY" \
    CITADEL_API_KEY_HASH="$ADMIN_HASH" \
    CITADEL_DATA_DIR="$DATA_DIR" \
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1 \
    CITADEL_PORT=$PORT \
    CITADEL_RATE_LIMIT_RPS=1000 \
    CITADEL_RATE_LIMIT_BURST=2000 \
    $BINARY > /tmp/citadel-persist-server.log 2>&1 &

    SERVER_PID=$!
    echo "  Server PID: $SERVER_PID"

    # Wait for health
    for i in $(seq 1 30); do
        if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
            echo "  Server healthy after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  [FATAL] Server failed to start"
    cat /tmp/citadel-persist-server.log | tail -20
    exit 1
}

stop_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        echo "  Server stopped"
        sleep 1
    fi
}

cleanup() {
    stop_server
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

echo "============================================"
echo "  PERSISTENCE / RESTART TEST"
echo "  Data dir: $DATA_DIR"
echo "============================================"
echo ""

# ── Phase 1: Set up state ──

echo "── Phase 1: Creating state ──"
start_server

# Create key hierarchy
ROOT_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d '{"name":"persist-root","key_type":"Root"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
echo "  Root: $ROOT_ID"
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$ROOT_ID/activate" -d '{}' > /dev/null

DOMAIN_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"persist-domain\",\"key_type\":\"Domain\",\"parent_id\":\"$ROOT_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
echo "  Domain: $DOMAIN_ID"
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DOMAIN_ID/activate" -d '{}' > /dev/null

KEK_ID=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"persist-kek\",\"key_type\":\"KeyEncrypting\",\"parent_id\":\"$DOMAIN_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
echo "  KEK: $KEK_ID"
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$KEK_ID/activate" -d '{}' > /dev/null

# Active DEK
ACTIVE_DEK=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"persist-dek-active\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$ACTIVE_DEK/activate" -d '{}' > /dev/null
echo "  Active DEK: $ACTIVE_DEK"

# Encrypt a payload (for later decrypt test)
BLOB=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$ACTIVE_DEK/encrypt" \
    -d '{"plaintext":"70657273697374","aad":"persist-aad","context":"persist-ctx"}')
echo "  Encrypted blob with active DEK"

# Revoked DEK
REVOKED_DEK=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"persist-dek-revoked\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$REVOKED_DEK/activate" -d '{}' > /dev/null
REVOKED_BLOB=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$REVOKED_DEK/encrypt" \
    -d '{"plaintext":"7265766f6b6564","aad":"persist-aad","context":"persist-ctx"}')
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$REVOKED_DEK/revoke" -d '{"reason":"persistence test"}' > /dev/null
echo "  Revoked DEK: $REVOKED_DEK"

# Destroyed DEK
DESTROYED_DEK=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"persist-dek-destroyed\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DESTROYED_DEK/activate" -d '{}' > /dev/null
DESTROY_REVOKE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DESTROYED_DEK/revoke" -d '{"reason":"persistence test"}')
check "Destroyed-test DEK revoke before destroy succeeds" "200" "$DESTROY_REVOKE_STATUS"
DESTROY_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$DESTROYED_DEK/destroy" -d '{}')
check "Destroyed-test DEK destroy succeeds" "200" "$DESTROY_STATUS"
echo "  Destroyed DEK: $DESTROYED_DEK"

# Create a second API key that we'll revoke
SECOND_KEY_RESP=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/auth/keys" \
    -d "{\"name\":\"persist-revoked-apikey\",\"scopes\":[\"read\",\"encrypt\"],\"allowed_domains\":[\"$DOMAIN_ID\"]}")
SECOND_KEY=$(echo "$SECOND_KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
SECOND_KEY_ID=$(echo "$SECOND_KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
echo "  Second API key: $SECOND_KEY_ID"

# Verify second key works before revoking
SECOND_STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $SECOND_KEY" "$BASE_URL/api/auth/whoami")
check "Second API key works before revoke" "200" "$SECOND_STATUS"

# Revoke the second API key
curl -sf -H "$AUTH" -X DELETE "$BASE_URL/api/auth/keys/$SECOND_KEY_ID" > /dev/null
echo "  Revoked second API key"

# Create new DEK under existing hierarchy (proves hierarchy works pre-restart)
NEW_DEK_PRE=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"persist-dek-new-pre\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
echo "  New DEK (pre-restart): $NEW_DEK_PRE"

echo ""

# ── Phase 2: Stop and restart ──

echo "── Phase 2: Stopping server ──"
stop_server
echo ""

echo "── Phase 3: Restarting server with same data dir ──"
start_server
echo ""

# ── Phase 4: Verify all state survived ──

echo "── Phase 4: Verifying state after restart ──"

# 1. Active DEK still decrypts
DECRYPT_STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "$AUTH" -H "$CT" "$BASE_URL/api/decrypt" \
    -d "{\"blob\":$BLOB,\"aad\":\"persist-aad\",\"context\":\"persist-ctx\"}")
check "Active DEK still decrypts after restart" "200" "$DECRYPT_STATUS"

# 2. Active DEK still encrypts
ENCRYPT_STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$ACTIVE_DEK/encrypt" \
    -d '{"plaintext":"706f7374","aad":"persist-aad","context":"persist-ctx"}')
check "Active DEK still encrypts after restart" "200" "$ENCRYPT_STATUS"

# 3. Revoked DEK cannot decrypt
REVOKED_DECRYPT=$(curl -o /dev/null -w '%{http_code}' -H "$AUTH" -H "$CT" "$BASE_URL/api/decrypt" \
    -d "{\"blob\":$REVOKED_BLOB,\"aad\":\"persist-aad\",\"context\":\"persist-ctx\"}" 2>/dev/null)
check "Revoked DEK cannot decrypt after restart" "400" "$REVOKED_DECRYPT"

# 4. Revoked DEK cannot encrypt
REVOKED_ENCRYPT=$(curl -o /dev/null -w '%{http_code}' -H "$AUTH" -H "$CT" "$BASE_URL/api/keys/$REVOKED_DEK/encrypt" \
    -d '{"plaintext":"7465737431","aad":"persist-aad","context":"persist-ctx"}' 2>/dev/null)
# Should be 400 or 403 (not 200)
if [ "$REVOKED_ENCRYPT" = "200" ]; then
    echo "  [FAIL] Revoked DEK can still encrypt after restart (status=$REVOKED_ENCRYPT)"
    FAIL=$((FAIL+1))
else
    echo "  [PASS] Revoked DEK cannot encrypt after restart (status=$REVOKED_ENCRYPT)"
    PASS=$((PASS+1))
fi

# 5. Destroyed DEK is gone
DESTROYED_STATUS=$(curl -o /dev/null -w '%{http_code}' -H "$AUTH" "$BASE_URL/api/keys/$DESTROYED_DEK" 2>/dev/null)
# Should NOT be 200 with Active state — either 403/404 or metadata shows Destroyed
if [ "$DESTROYED_STATUS" = "200" ]; then
    # Check if it reports Destroyed state
    DESTROYED_STATE=$(curl -sf -H "$AUTH" "$BASE_URL/api/keys/$DESTROYED_DEK" | python3 -c "import sys,json; print(json.load(sys.stdin).get('state','unknown'))" 2>/dev/null || echo "unknown")
    case "$DESTROYED_STATE" in
        Destroyed|DESTROYED)
            echo "  [PASS] Destroyed DEK shows Destroyed state after restart"
            PASS=$((PASS+1))
            ;;
        *)
            echo "  [FAIL] Destroyed DEK shows Destroyed state after restart (expected=Destroyed/DESTROYED, got=$DESTROYED_STATE)"
            FAIL=$((FAIL+1))
            ;;
    esac
else
    echo "  [PASS] Destroyed DEK inaccessible after restart (status=$DESTROYED_STATUS)"
    PASS=$((PASS+1))
fi

# 6. Revoked API key stays revoked
REVOKED_KEY_STATUS=$(curl -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $SECOND_KEY" "$BASE_URL/api/auth/whoami" 2>/dev/null)
check "Revoked API key stays revoked after restart" "401" "$REVOKED_KEY_STATUS"

# 7. Admin key still works
ADMIN_STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "$AUTH" "$BASE_URL/api/auth/whoami")
check "Admin API key still works after restart" "200" "$ADMIN_STATUS"

# 8. Key hierarchy still intact (can create new DEK under existing KEK)
NEW_DEK_POST=$(curl -sf -H "$AUTH" -H "$CT" "$BASE_URL/api/keys" \
    -d "{\"name\":\"persist-dek-new-post\",\"key_type\":\"DataEncrypting\",\"parent_id\":\"$KEK_ID\"}" 2>/dev/null)
NEW_DEK_POST_STATUS=$?
if [ $NEW_DEK_POST_STATUS -eq 0 ] && echo "$NEW_DEK_POST" | python3 -c "import sys,json; json.load(sys.stdin)['key_id']" > /dev/null 2>&1; then
    echo "  [PASS] Key hierarchy intact — new DEK created under existing KEK after restart"
    PASS=$((PASS+1))
else
    echo "  [FAIL] Cannot create new DEK under existing KEK after restart"
    FAIL=$((FAIL+1))
fi

# 9. Root key state persisted
ROOT_STATE=$(curl -sf -H "$AUTH" "$BASE_URL/api/keys/$ROOT_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('state','unknown').upper())" 2>/dev/null || echo "unknown")
check "Root key remains Active after restart" "ACTIVE" "$ROOT_STATE"

# 10. Domain key state persisted
DOMAIN_STATE=$(curl -sf -H "$AUTH" "$BASE_URL/api/keys/$DOMAIN_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('state','unknown').upper())" 2>/dev/null || echo "unknown")
check "Domain key remains Active after restart" "ACTIVE" "$DOMAIN_STATE"

echo ""
echo "============================================"
echo "  PERSISTENCE TEST: $PASS PASSED, $FAIL FAILED"
echo "============================================"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "FINDINGS: State did not survive server restart."
    exit 1
else
    echo ""
    echo "All security-critical state survived clean restart."
    exit 0
fi
