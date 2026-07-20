#!/usr/bin/env bash
# Canonical Citadel Ubuntu/WSL2 build and test driver.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNS=2
OFFLINE=1
RECEIPT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    --receipt-dir) RECEIPT_DIR="$2"; shift 2 ;;
    --online) OFFLINE=0; shift ;;
    --help|-h)
      echo "Usage: bash scripts/test-citadel-ubuntu.sh [--runs N] [--receipt-dir PATH] [--online]"
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || { echo "--runs must be a positive integer" >&2; exit 2; }

# Non-login WSL invocations do not necessarily source the rustup PATH setup.
if ! command -v cargo >/dev/null 2>&1 && [[ -d "$HOME/.cargo/bin" ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

for tool in cargo rustc python3 git sha256sum find sort xargs tee; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 3; }
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$RECEIPT_DIR" ]]; then
  RECEIPT_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/citadel-receipts/$STAMP"
fi
mkdir -p "$RECEIPT_DIR"

CARGO_ARGS=(--workspace --locked)
if [[ "$OFFLINE" -eq 1 ]]; then CARGO_ARGS+=(--offline); fi

source_hash() {
  find . -type f \
    \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' -o -name '*.sh' \) \
    -not -path '*/target/*' -not -path './.git/*' -print0 |
    sort -z |
    xargs -0 sha256sum |
    sha256sum |
    awk '{print $1}'
}

SOURCE_HASH_INITIAL="$(source_hash)"
LOCK_HASH="$(sha256sum Cargo.lock | awk '{print $1}')"
REVISION="$(git rev-parse HEAD 2>/dev/null || echo unavailable)"
DIRTY_HASH="$(git diff --binary HEAD 2>/dev/null | sha256sum | awk '{print $1}')"
RUSTC_VERSION="$(rustc --version)"
CARGO_VERSION="$(cargo --version)"
PLATFORM="$(uname -a)"

cargo metadata --locked $( [[ "$OFFLINE" -eq 1 ]] && echo --offline ) --no-deps --format-version 1   > "$RECEIPT_DIR/cargo-metadata.json"

for run in $(seq 1 "$RUNS"); do
  RUN_DIR="$RECEIPT_DIR/run_$run"
  mkdir -p "$RUN_DIR"
  BEFORE="$(source_hash)"
  [[ "$BEFORE" == "$SOURCE_HASH_INITIAL" ]] || {
    echo "source changed before run $run" >&2
    exit 4
  }

  set +e
  cargo test "${CARGO_ARGS[@]}" --no-run --message-format=json-render-diagnostics 2>&1 | tee "$RUN_DIR/compile.log"
  COMPILE_RC=${PIPESTATUS[0]}
  set -e
  [[ "$COMPILE_RC" -eq 0 ]] || { echo "compile failed in run $run" >&2; exit "$COMPILE_RC"; }

  python3 - "$RUN_DIR/compile.log" "$RUN_DIR/artifacts.sha256" <<'PY'
import hashlib, json, pathlib, sys

log_path, output_path = map(pathlib.Path, sys.argv[1:])
executables = set()
for raw_line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        message = json.loads(raw_line)
    except json.JSONDecodeError:
        continue
    executable = message.get("executable")
    if message.get("reason") == "compiler-artifact" and executable:
        executables.add(pathlib.Path(executable))

if not executables:
    raise SystemExit("Cargo reported no test executables")

with output_path.open("w", encoding="utf-8") as output:
    for executable in sorted(executables, key=lambda path: str(path)):
        digest = hashlib.sha256()
        with executable.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
        output.write(f"{digest.hexdigest()}  {executable}\n")
PY
  ARTIFACT_INVENTORY_HASH="$(sha256sum "$RUN_DIR/artifacts.sha256" | awk '{print $1}')"

  set +e
  cargo test "${CARGO_ARGS[@]}" -- --test-threads=1 2>&1 | tee "$RUN_DIR/test.log"
  TEST_RC=${PIPESTATUS[0]}
  set -e

  AFTER="$(source_hash)"
  python3 - "$RUN_DIR/test.log" "$RUN_DIR/receipt.json" "$run" "$COMPILE_RC" "$TEST_RC"     "$BEFORE" "$AFTER" "$LOCK_HASH" "$ARTIFACT_INVENTORY_HASH" "$REVISION"     "$DIRTY_HASH" "$RUSTC_VERSION" "$CARGO_VERSION" "$PLATFORM" <<'PY'
import json, re, sys
from datetime import datetime, timezone
(log_path, out_path, run_index, compile_rc, test_rc, before, after, lock_hash,
 artifact_hash, revision, dirty_hash, rustc, cargo, platform) = sys.argv[1:]
totals = {"passed": 0, "failed": 0, "ignored": 0, "filtered_out": 0}
pattern = re.compile(
    r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; \d+ measured; (\d+) filtered out"
)
with open(log_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        match = pattern.search(line)
        if match:
            for key, value in zip(totals, map(int, match.groups())):
                totals[key] += value
record = {
    "schema_version": 1,
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "run_index": int(run_index),
    "status": "pass" if int(compile_rc) == 0 and int(test_rc) == 0 and before == after else "fail",
    "compile_exit_code": int(compile_rc),
    "test_exit_code": int(test_rc),
    "source_hash_before": before,
    "source_hash_after": after,
    "cargo_lock_sha256": lock_hash,
    "artifact_inventory_sha256": artifact_hash,
    "git_revision": revision,
    "dirty_diff_sha256": dirty_hash,
    "rustc": rustc,
    "cargo": cargo,
    "platform": platform,
    "test_totals": totals,
}
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

  [[ "$TEST_RC" -eq 0 ]] || { echo "tests failed in run $run" >&2; exit "$TEST_RC"; }
  [[ "$BEFORE" == "$AFTER" ]] || { echo "source changed during run $run" >&2; exit 5; }
done

python3 - "$RECEIPT_DIR" "$RUNS" <<'PY'
import json, pathlib, sys
directory, count = pathlib.Path(sys.argv[1]), int(sys.argv[2])
runs = [json.loads((directory / f"run_{i}" / "receipt.json").read_text()) for i in range(1, count + 1)]
same_source = len({r["source_hash_before"] for r in runs} | {r["source_hash_after"] for r in runs}) == 1
same_lock = len({r["cargo_lock_sha256"] for r in runs}) == 1
same_inventory = len({r["artifact_inventory_sha256"] for r in runs}) == 1
same_totals = len({json.dumps(r["test_totals"], sort_keys=True) for r in runs}) == 1
passed = all(r["status"] == "pass" for r in runs)
summary = {
    "schema_version": 1,
    "status": "pass" if all((same_source, same_lock, same_inventory, same_totals, passed)) else "fail",
    "run_count": count,
    "same_source": same_source,
    "same_lock": same_lock,
    "same_artifact_inventory": same_inventory,
    "same_test_totals": same_totals,
    "runs_passed": passed,
    "test_totals": runs[0]["test_totals"] if runs else {},
    "run_receipts": [str(pathlib.Path(f"run_{i}") / "receipt.json") for i in range(1, count + 1)],
}
(directory / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, indent=2, sort_keys=True))
raise SystemExit(0 if summary["status"] == "pass" else 6)
PY

echo "Receipts: $RECEIPT_DIR"
