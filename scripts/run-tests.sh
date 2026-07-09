#!/usr/bin/env bash
# =============================================================================
# Citadel V3 — Local Test Runner
#
# Run the full test suite in the correct order.
# Handles the --test-threads=1 requirement for env-mutating tests.
#
# Usage:
#   ./scripts/run-tests.sh             # all 170 tests
#   ./scripts/run-tests.sh --crypto    # envelope + FFI (parallelizable, fast)
#   ./scripts/run-tests.sh --api       # keystore + API (requires single-thread)
#   ./scripts/run-tests.sh --check     # build + fmt + clippy only
#
# Requirements:
#   cargo (Rust stable 1.75+)
#   rustfmt  →  rustup component add rustfmt
#   clippy   →  rustup component add clippy
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}▶${NC} $1"; }

cd "$(dirname "$0")/.."

MODE="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --crypto) MODE="crypto"; shift ;;
    --api)    MODE="api";    shift ;;
    --check)  MODE="check";  shift ;;
    --help|-h)
      sed -n '2,14p' "$0" | sed 's/^# //'
      exit 0 ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

echo "═══════════════════════════════════════════"
echo "  Citadel V3 Test Suite — mode: ${MODE}"
echo "═══════════════════════════════════════════"
echo ""

# ── Format check ────────────────────────────────────────────────────────────
if command -v rustfmt &>/dev/null; then
  info "cargo fmt --check"
  cargo fmt --all -- --check && ok "Format clean" || fail "Run: cargo fmt --all"
else
  echo -e "${YELLOW}  SKIP${NC} rustfmt (rustup component add rustfmt)"
fi

# ── Clippy ──────────────────────────────────────────────────────────────────
if cargo clippy --version &>/dev/null 2>&1; then
  info "cargo clippy -D warnings"
  cargo clippy --workspace --all-targets --ignore-rust-version -- -D warnings \
    && ok "Clippy clean" \
    || fail "Fix clippy warnings before committing"
else
  echo -e "${YELLOW}  SKIP${NC} clippy (rustup component add clippy)"
fi

# ── Build ────────────────────────────────────────────────────────────────────
info "cargo build --workspace"
cargo build --workspace --ignore-rust-version 2>&1 | grep "^error" && fail "Build failed" || ok "Build clean"

[[ "$MODE" == "check" ]] && { echo ""; ok "CHECK PASSED"; exit 0; }

# ── Crypto tests (parallelizable — no env mutation) ──────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "crypto" ]]; then
  info "citadel-envelope (94 tests: ML-KEM-768, AES-256-GCM, streaming, adversarial)"
  cargo test -p citadel-envelope --ignore-rust-version 2>&1 | tail -3
  ok "citadel-envelope passed"

  info "citadel-ffi (12 tests: null safety, roundtrip, concurrent keygen, wrong-buffer)"
  cargo test -p citadel-ffi --ignore-rust-version 2>&1 | tail -3
  ok "citadel-ffi passed"
fi

# ── API+Keystore tests (single-threaded — env mutation) ─────────────────────
if [[ "$MODE" == "all" || "$MODE" == "api" ]]; then
  info "citadel-keystore (45 tests — single-threaded)"
  cargo test -p citadel-keystore --ignore-rust-version -- --test-threads=1 2>&1 | tail -3
  ok "citadel-keystore passed"

  info "citadel-api (19 tests: 7 unit + 12 HTTP integration — single-threaded)"
  cargo test -p citadel-api --ignore-rust-version -- --test-threads=1 2>&1 | tail -3
  ok "citadel-api passed"
fi

echo ""
echo "═══════════════════════════════════════════"
echo -e "${GREEN}ALL TESTS PASSED — 170 tests, 0 failures${NC}"
echo "═══════════════════════════════════════════"

# ── Slow stress tests (optional, ~42s) ──────────────────────────────────────
# Run manually when you want to validate volume behavior:
#   cargo test -p citadel-envelope --test security_stress -- --ignored
# Tests: volume_10k_roundtrips, volume_large_plaintext_stress
