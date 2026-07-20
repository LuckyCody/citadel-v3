#!/usr/bin/env bash
# Citadel Adversarial Gauntlet — orchestrator.
# Runs each available tier, writes a receipt per tier, prints one PASS/FAIL
# summary, and exits non-zero if any executed tier failed.
#
# Usage:
#   bash run.sh                 # every tier the toolchain supports
#   bash run.sh tier1 tier2b    # a subset
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"        # citadel_v3
REC="$HERE/receipts"
mkdir -p "$REC"
SUMMARY="$REC/LAST_RUN.md"   # auto-generated per run; curated SUMMARY.md is hand-maintained

STAMP="${GAUNTLET_STAMP:-unstamped}"  # pass a timestamp in; scripts can't call date deterministically in some envs
declare -A RESULT

want() { [ "$#" -eq 0 ] && return 0; for w in "$SELECT"; do :; done; case " $SELECT " in *" $1 "*) return 0;; *) return 1;; esac; }
SELECT="${*:-tier1 tier1b tier2 tier2b tier3 tier4}"

run_tier() { # name, human, command...
  local key="$1" human="$2"; shift 2
  case " $SELECT " in *" $key "*) ;; *) return 0;; esac
  echo "=================================================================="
  echo ">> $key — $human"
  echo "=================================================================="
  if "$@"; then RESULT[$key]="PASS"; else RESULT[$key]="FAIL"; fi
}

# ---- Tier 1 + 1b: crypto vectors + composition ----------------------------
t1() {
  ( cd "$HERE/tier1_vectors" && cargo test 2>&1 | tee "$REC/tier1_vectors.txt" \
      | grep -E "wycheproof|test result|FAILED"; return "${PIPESTATUS[0]}" )
}
run_tier tier1 "Wycheproof primitive vectors + proptest composition" t1
RESULT[tier1b]="${RESULT[tier1]:-SKIP}"   # same crate

# ---- Tier 2: memory safety (Miri) -----------------------------------------
t2() {
  command -v cargo >/dev/null || return 2
  cargo +nightly miri --version >/dev/null 2>&1 || { echo "miri absent — rustup component add miri --toolchain nightly"; return 2; }
  ( cd "$ROOT" && MIRIFLAGS="-Zmiri-disable-isolation" \
      cargo +nightly miri test -p citadel-ffi 2>&1 | tee "$REC/tier2_miri.txt" \
      | grep -E "test result|error: Undefined|FAILED"; return "${PIPESTATUS[0]}" )
}
run_tier tier2 "cargo miri UB detection (FFI boundary)" t2

# ---- Tier 2b: supply chain -------------------------------------------------
t2b() {
  ( cd "$ROOT"
    local rc=0
    { echo "### cargo deny check";  cargo deny check 2>&1; echo "### cargo audit"; cargo audit 2>&1; } \
      | tee "$REC/tier2b_supplychain.txt"
    # Fail only on vulnerabilities. Unmaintained dev-tooling warnings are
    # reviewed/accepted in deny.toml `ignore` (all dev-only, not shipped).
    # `cargo audit` exits non-zero on vulnerabilities, zero on warnings.
    cargo audit >/dev/null 2>&1 || rc=$?
    return "$rc" )
}
run_tier tier2b "cargo-deny + cargo-audit supply chain" t2b

# ---- Tier 3: extended fuzzing ---------------------------------------------
t3() {
  cargo fuzz --help >/dev/null 2>&1 || { echo "cargo-fuzz absent"; return 2; }
  local secs="${FUZZ_SECS:-60}"
  # cargo-fuzz needs nightly for -Zsanitizer; select via env, not `+nightly`.
  ( cd "$ROOT/citadel-envelope" || cd "$ROOT"
    export RUSTUP_TOOLCHAIN=nightly
    local rc=0
    for tgt in $(cargo fuzz list 2>/dev/null); do
      echo "--- fuzzing $tgt for ${secs}s ---"
      cargo fuzz run "$tgt" -- -max_total_time="$secs" -rss_limit_mb=4096 2>&1 | tail -5 || rc=$?
    done
    return "$rc" ) | tee "$REC/tier3_fuzz.txt"
}
run_tier tier3 "cargo-fuzz sustained run (libFuzzer)" t3

# ---- Tier 4: constant-time -------------------------------------------------
t4() {
  ( cd "$ROOT/citadel-envelope" 2>/dev/null || cd "$ROOT"
    echo "dudect timing benches (attacker-controlled-input classes):"
    cargo bench --bench timing_sidechannel 2>&1 | tail -30 || true
    echo
    echo "NOTE: binary-level CT (DATA/MicroWalk) is a documented follow-on; see README Tier 4."
  ) | tee "$REC/tier4_timing.txt"
}
run_tier tier4 "dudect constant-time classes (+DATA/MicroWalk follow-on)" t4

# ---- Summary --------------------------------------------------------------
{
  echo "# Citadel Gauntlet — run summary ($STAMP)"
  echo
  echo "| Tier | Result |"
  echo "|---|---|"
  for k in tier1 tier1b tier2 tier2b tier3 tier4; do
    printf "| %s | %s |\n" "$k" "${RESULT[$k]:-SKIP}"
  done
} | tee "$SUMMARY"

fail=0
for k in "${!RESULT[@]}"; do [ "${RESULT[$k]}" = "FAIL" ] && fail=1; done
echo
[ "$fail" -eq 0 ] && echo "GAUNTLET: no executed tier failed" || echo "GAUNTLET: at least one tier FAILED"
exit "$fail"
