#!/usr/bin/env bash
# One-off Tier-3 libFuzzer smoke, kept as a file to avoid nested-quote mangling.
set -uo pipefail
# cargo-fuzz needs nightly for -Zsanitizer; select it via env (not `+nightly`,
# which makes cargo look for cargo-fuzz in the nightly toolchain bin).
export RUSTUP_TOOLCHAIN=nightly
cd "$(dirname "$0")/../citadel-envelope"
R="$(dirname "$0")/receipts/tier3_fuzz_smoke.txt"
{
  echo "=== Tier 3 libFuzzer smoke (40s/target, ASan) ==="
  for tgt in decode_envelope_v2 decrypt_full; do
    echo "--- ${tgt} (40s) ---"
    cargo fuzz run "${tgt}" -- -max_total_time=40 -rss_limit_mb=4096 2>&1 \
      | grep -E "Done|crash|ERROR|leaked|SUMMARY|Executed|^#[0-9]" | tail -6
    echo "exit=${PIPESTATUS[0]}"
  done
} | tee "$R"
echo SMOKE_DONE
