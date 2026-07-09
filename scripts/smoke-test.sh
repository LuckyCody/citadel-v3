#!/usr/bin/env bash
# =============================================================================
# Citadel V3 — End-to-End Smoke Test & Proof Generator
#
# Proves: env check → start → health → auth rejection → encrypt → decrypt → replay blocked
# Writes: artifacts/citadel_smoke_proof_<timestamp>.json
#
# Usage:
#   ./scripts/smoke-test.sh --dev              # dev mode (auto-start, auto-key)
#   ./scripts/smoke-test.sh --prod --key KEY   # production (needs running API)
#   ./scripts/smoke-test.sh --api URL --key K  # remote API
#   ./scripts/smoke-test.sh --help
#
# Exit: 0=all pass, 1=any failure
# =============================================================================
set -uo pipefail

PASS=0; FAIL=0; SKIP=0
BASE_URL="${CITADEL_SMOKE_URL:-http://localhost:8443}"
API_KEY="${CITADEL_API_KEY:-}"
MODE="dev"
MANAGED=false
SERVER_PID=""
SMOKE_DEV_KEY="citadel-smoke-$(date +%s)"
TS=$(date -u +%Y%m%dT%H%M%SZ)
PROOF_DIR="artifacts"
PROOF_FILE="${PROOF_DIR}/citadel_smoke_proof_${TS}.json"

# Per-test result accumulation (name:status:detail)
declare -a RESULTS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

usage() {
  cat <<'EOF'
Usage: smoke-test.sh [--dev|--prod|--api URL] [--key API_KEY]

  --dev          Start API in development mode (auto-key, all 7 tests run)
  --prod         Test against a running production API
  --api URL      Remote API URL (default: http://localhost:8443)
  --key KEY      API key (auto-set in --dev mode)

Dev:  no CITADEL_MASTER_KEY needed; proof written to artifacts/
Prod: CITADEL_MASTER_KEY + CITADEL_API_KEY_HASH + CITADEL_REPLAY_STORE required
EOF
  exit 0
}

ok()   { local msg="$1" id="$2"; echo -e "${GREEN}✓ PASS${NC} — ${msg}"; ((PASS++)) || true;
         RESULTS+=("${id}:PASS:${msg}"); }
fail() { local msg="$1" id="$2"; echo -e "${RED}✗ FAIL${NC} — ${msg}"; ((FAIL++)) || true;
         RESULTS+=("${id}:FAIL:${msg}"); }
skip() { local msg="$1" id="$2"; echo -e "${YELLOW}  SKIP${NC} — ${msg}"; ((SKIP++)) || true;
         RESULTS+=("${id}:SKIP:${msg}"); }
info() { echo -e "${YELLOW}  ▶${NC} $1"; }

write_proof() {
  local final_status="$1"
  mkdir -p "$PROOF_DIR"
  # Build JSON using python3
  python3 - <<PYEOF
import json, sys

results_raw = """${RESULTS[*]:-}"""
tests = {}
for entry in results_raw.split():
    parts = entry.split(":", 2)
    if len(parts) == 3:
        tid, status, detail = parts
        tests[tid] = {"status": status, "detail": detail}

proof = {
    "schema_version": "1.0",
    "timestamp": "${TS}",
    "mode": "${MODE}",
    "api_url": "${BASE_URL}",
    "final_status": "${final_status}",
    "summary": {
        "pass": ${PASS},
        "fail": ${FAIL},
        "skip": ${SKIP},
        "total": $((PASS + FAIL + SKIP))
    },
    "tests": tests,
    "logs": "/tmp/citadel-smoke.log",
    "proof_file": "${PROOF_FILE}"
}
with open("${PROOF_FILE}", "w") as f:
    json.dump(proof, f, indent=2)
print(f"Proof: ${PROOF_FILE}")
PYEOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage ;;
    --dev)  MODE="dev";  shift ;;
    --prod) MODE="prod"; shift ;;
    --api)  BASE_URL="$2"; shift 2 ;;
    --key)  API_KEY="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

mkdir -p "$PROOF_DIR"

echo "═══════════════════════════════════════════════════"
echo "  Citadel V3 Smoke Test & Proof — mode: ${MODE}"
echo "  url: ${BASE_URL}  proof: ${PROOF_FILE}"
echo "═══════════════════════════════════════════════════"
echo ""

# ── TEST 1: Prerequisites ────────────────────────────────────────────────────
info "TEST 1: Prerequisites"
if command -v curl &>/dev/null; then ok "curl available" "t1_prereqs";
else fail "curl not found" "t1_prereqs"; write_proof "FAIL"; exit 1; fi
if command -v python3 &>/dev/null; then ok "python3 available" "t1_prereqs_py";
else fail "python3 not found" "t1_prereqs_py"; write_proof "FAIL"; exit 1; fi

if [[ "$MODE" == "prod" ]]; then
  for var in CITADEL_MASTER_KEY CITADEL_API_KEY_HASH CITADEL_REPLAY_STORE; do
    if [[ -z "${!var:-}" ]]; then fail "${var} not set (required)" "t1_${var,,}";
    else ok "${var} set" "t1_${var,,}"; fi
  done
fi

# ── TEST 2: API reachability (auto-start in dev) ──────────────────────────────
info "TEST 2: API reachability"
if ! curl -sf "${BASE_URL}/health" &>/dev/null; then
  if [[ "$MODE" == "dev" ]]; then
    MANAGED=true
    info "Starting API in dev mode (key=${SMOKE_DEV_KEY:0:16}...)"
    CITADEL_ENV=development \
    CITADEL_ALLOW_PLAINTEXT_KEYS=1 \
    CITADEL_SEED_DEMO=true \
    CITADEL_API_KEY="$SMOKE_DEV_KEY" \
      cargo run -q -p citadel-api &>/tmp/citadel-smoke.log &
    SERVER_PID=$!
    info "Waiting up to 90s for API (PID ${SERVER_PID})..."
    STARTED=false
    for i in $(seq 1 90); do
      sleep 1
      if curl -sf "${BASE_URL}/health" &>/dev/null; then STARTED=true; break; fi
    done
    if [[ "$STARTED" == "true" ]]; then
      ok "API started in dev mode" "t2_start"
      [[ -z "$API_KEY" ]] && API_KEY="$SMOKE_DEV_KEY"
    else
      fail "API did not start in 90s — see /tmp/citadel-smoke.log" "t2_start"
      write_proof "FAIL"
      [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
      exit 1
    fi
  else
    fail "API not reachable at ${BASE_URL}" "t2_start"
    write_proof "FAIL"; exit 1
  fi
else
  ok "API reachable" "t2_start"
fi

HEALTH=$(curl -sf "${BASE_URL}/health" 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null \
  || echo "unknown")
[[ "$HEALTH" == "ok" ]] \
  && ok "Health → {\"status\":\"ok\"}" "t2_health" \
  || fail "Health → '${HEALTH}'" "t2_health"

# ── TEST 3: Unauthenticated rejected ─────────────────────────────────────────
info "TEST 3: Unauthenticated access rejected"
UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/status" 2>/dev/null || echo "000")
[[ "$UNAUTH" == "401" || "$UNAUTH" == "403" ]] \
  && ok "Unauthenticated → HTTP ${UNAUTH}" "t3_unauth" \
  || fail "Unauthenticated → HTTP ${UNAUTH} (expected 401/403)" "t3_unauth"

# ── TESTS 4–7: Authenticated encrypt → decrypt → replay ──────────────────────
if [[ -n "$API_KEY" ]]; then
  AUTH="Authorization: Bearer ${API_KEY}"

  info "TEST 4: Fetch active DEK"
  KEYS=$(curl -sf -H "$AUTH" "${BASE_URL}/api/keys" 2>/dev/null || echo '[]')
  DEK_ID=$(echo "$KEYS" | python3 -c "
import sys, json
try:
    k = json.load(sys.stdin)
    if isinstance(k, dict): k = k.get('keys', [])
    active = [x for x in k if x.get('state') == 'Active']
    print(active[0]['id'] if active else '')
except: print('')
" 2>/dev/null || echo "")

  if [[ -z "$DEK_ID" ]]; then
    fail "No active DEK (response: ${KEYS:0:80})" "t4_dek"
  else
    ok "Active DEK: ${DEK_ID:0:8}..." "t4_dek"

    info "TEST 5: Encrypt known plaintext ('smoke-test')"
    ENC=$(curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
      -d '{"plaintext":"c21va2UtdGVzdA==","aad":"smoke-test","context":"v3"}' \
      "${BASE_URL}/api/keys/${DEK_ID}/encrypt" 2>/dev/null || echo "")
    BLOB=$(echo "$ENC" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    if 'blob' in r: print(json.dumps(r['blob']))
    elif 'key_id' in r or 'ciphertext_hex' in r: print(json.dumps(r))
    else: print('')
except: print('')
" 2>/dev/null || echo "")

    if [[ -z "$BLOB" || "$BLOB" == "null" ]]; then
      fail "Encrypt failed (${ENC:0:80})" "t5_encrypt"
    else
      ok "Encrypt succeeded" "t5_encrypt"

      info "TEST 6: Decrypt — verify plaintext matches"
      DEC=$(curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
        -d "{\"blob\":${BLOB},\"aad\":\"smoke-test\",\"context\":\"v3\"}" \
        "${BASE_URL}/api/decrypt" 2>/dev/null || echo "")
      PT=$(echo "$DEC" | python3 -c "
import sys, json, base64
try:
    d = json.load(sys.stdin)
    pt = d.get('plaintext') or d.get('plaintext_base64') or d.get('data') or ''
    try: print(base64.b64decode(pt).decode())
    except: print(pt)
except: print('')
" 2>/dev/null || echo "")
      [[ "$PT" == "smoke-test" ]] \
        && ok "Decrypt → 'smoke-test' ✓" "t6_decrypt" \
        || fail "Decrypt → '${PT}' (expected 'smoke-test')" "t6_decrypt"

      info "TEST 7: Replay — same blob must be rejected"
      RP=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "$AUTH" -H "Content-Type: application/json" \
        -d "{\"blob\":${BLOB},\"aad\":\"smoke-test\",\"context\":\"v3\"}" \
        "${BASE_URL}/api/decrypt" 2>/dev/null || echo "000")
      [[ "$RP" == "4"* ]] \
        && ok "Replay blocked → HTTP ${RP}" "t7_replay" \
        || fail "Replay returned HTTP ${RP} (expected 4xx)" "t7_replay"
    fi
  fi
else
  for t in t4_dek t5_encrypt t6_decrypt t7_replay; do
    skip "No API key — skipping authenticated tests (use --key or --dev)" "$t"
  done
fi

# ── Cleanup ──────────────────────────────────────────────────────────────────
if [[ "$MANAGED" == "true" && -n "$SERVER_PID" ]]; then
  kill "$SERVER_PID" 2>/dev/null || true
  info "Stopped managed API server (PID ${SERVER_PID})"
fi

# ── Write proof + summary ─────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]] && FINAL="PASS" || FINAL="FAIL"
write_proof "$FINAL"

if [[ $FAIL -eq 0 ]]; then
  echo -e "${GREEN}ALL TESTS PASSED${NC} — ${PASS}/$((PASS+FAIL+SKIP)) (${SKIP} skipped)"
  echo "═══════════════════════════════════════════════════"
  exit 0
else
  echo -e "${RED}TESTS FAILED${NC} — ${FAIL} failed, ${PASS} passed (${SKIP} skipped)"
  echo "═══════════════════════════════════════════════════"
  exit 1
fi
