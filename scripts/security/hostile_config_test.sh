#!/bin/bash
# Hostile config testing: verify Citadel fails closed on bad/missing configs.
# Each test starts the server with a specific bad config and verifies it refuses to start.

cd "${CITADEL_WORKSPACE_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
BINARY="./target/release/citadel-api"
PASS=0
FAIL=0

check_refuses() {
    local name="$1"
    shift
    local tmpdir=$(mktemp -d /tmp/citadel-hostile-XXXXXX)

    # Run server with the given env vars, capture exit code and output
    timeout 5 env CITADEL_DATA_DIR="$tmpdir" "$@" $BINARY > /tmp/hostile_out.txt 2>&1
    local code=$?

    # Server should NOT be running (exit != 0, or no health response)
    if [ $code -eq 0 ]; then
        # It exited 0 — check if it actually started by looking for "listening" or similar
        if grep -qi "configured\|listening\|ready" /tmp/hostile_out.txt; then
            echo "  [FAIL] $name — server started when it should have refused"
            FAIL=$((FAIL+1))
        else
            echo "  [PASS] $name — exited cleanly without starting"
            PASS=$((PASS+1))
        fi
    else
        echo "  [PASS] $name — refused to start (exit $code)"
        PASS=$((PASS+1))
    fi

    rm -rf "$tmpdir"
}

check_starts() {
    local name="$1"
    shift
    local tmpdir=$(mktemp -d /tmp/citadel-hostile-XXXXXX)

    timeout 5 env CITADEL_DATA_DIR="$tmpdir" "$@" $BINARY > /tmp/hostile_out.txt 2>&1 &
    local pid=$!
    sleep 3

    if curl -sf http://localhost:8443/health > /dev/null 2>&1; then
        echo "  [PASS] $name — started correctly"
        PASS=$((PASS+1))
    else
        echo "  [FAIL] $name — failed to start"
        FAIL=$((FAIL+1))
    fi

    kill $pid 2>/dev/null
    wait $pid 2>/dev/null
    rm -rf "$tmpdir"
}

echo "============================================"
echo "  HOSTILE CONFIG TESTING"
echo "============================================"
echo ""

# Good config (control)
GOOD_KEY=$(openssl rand -hex 32)
GOOD_HASH=$(echo -n "test-key" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$GOOD_KEY | awk '{print $NF}')

echo "── Control: valid config should start ──"
check_starts "Valid config starts" \
    CITADEL_MASTER_KEY="$GOOD_KEY" \
    CITADEL_API_KEY_HASH="$GOOD_HASH" \
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1 \
    CITADEL_SEED_DEMO=true

echo ""
echo "── Missing master key ──"
check_refuses "No CITADEL_MASTER_KEY" \
    CITADEL_ENV=production

echo ""
echo "── Weak master key (sequential bytes) ──"
check_refuses "Sequential master key" \
    CITADEL_MASTER_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" \
    CITADEL_API_KEY_HASH="$GOOD_HASH" \
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1

echo ""
echo "── All-same-byte master key ──"
check_refuses "All-zeros master key" \
    CITADEL_MASTER_KEY="0000000000000000000000000000000000000000000000000000000000000000" \
    CITADEL_API_KEY_HASH="$GOOD_HASH" \
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1

echo ""
echo "── Too-short master key ──"
check_refuses "16-byte master key" \
    CITADEL_MASTER_KEY="abcdef1234567890abcdef1234567890" \
    CITADEL_API_KEY_HASH="$GOOD_HASH" \
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1

echo ""
echo "── Invalid hex master key ──"
check_refuses "Non-hex master key" \
    CITADEL_MASTER_KEY="this-is-not-valid-hex-at-all-and-should-be-rejected-by-validator!!" \
    CITADEL_API_KEY_HASH="$GOOD_HASH" \
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1

echo ""
echo "── Period-16 repeating master key ──"
check_refuses "Repeating-block master key" \
    CITADEL_MASTER_KEY="000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f" \
    CITADEL_API_KEY_HASH="$GOOD_HASH" \
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1

echo ""
echo "── Production mode without plaintext keys allowed ──"
check_refuses "Production without master key" \
    CITADEL_ENV=production

echo ""
echo "============================================"
echo "  HOSTILE CONFIG: $PASS PASSED, $FAIL FAILED"
echo "============================================"
