#!/usr/bin/env bash
set -euo pipefail

CARGO_BIN="${CARGO_BIN:-cargo}"
workdir="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$workdir"
}
trap cleanup EXIT

chmod 0700 "$workdir"
umask 077
$CARGO_BIN run -q -p citadel-keystore --bin citadel-root-key -- init "$workdir/root.key" >/dev/null
$CARGO_BIN run -q -p citadel-keystore --bin citadel-root-key -- check "$workdir/root.key" >/dev/null

export CITADEL_PROFILE=local-pilot
export CITADEL_ROOT_KEY_FILE="$workdir/root.key"
export CITADEL_ENV=pilot
export CITADEL_REPLAY_STORE=file
export CITADEL_REPLAY_STORE_PATH="$workdir/replay.json"
unset CITADEL_MASTER_KEY CITADEL_API_KEY CITADEL_ALLOW_PLAINTEXT_KEYS CITADEL_ALLOW_FLAT_DEKS

hash_one="$($CARGO_BIN run -q -p citadel-api --bin hash-apikey -- packet-008-test-api-key | sed -n 's/^HASH://p')"
[[ "$hash_one" =~ ^[0-9a-f]{64}$ ]]

chmod 0644 "$workdir/root.key"
if $CARGO_BIN run -q -p citadel-api --bin hash-apikey -- packet-008-test-api-key >/dev/null 2>&1; then
  echo "insecure root-key mode was accepted" >&2
  exit 1
fi
chmod 0600 "$workdir/root.key"

ln -s "$workdir/root.key" "$workdir/root.link"
export CITADEL_ROOT_KEY_FILE="$workdir/root.link"
if $CARGO_BIN run -q -p citadel-api --bin hash-apikey -- packet-008-test-api-key >/dev/null 2>&1; then
  echo "root-key symlink was accepted" >&2
  exit 1
fi
export CITADEL_ROOT_KEY_FILE="$workdir/root.key"

export CITADEL_MASTER_KEY=0000000000000000000000000000000000000000000000000000000000000000
if $CARGO_BIN run -q -p citadel-api --bin hash-apikey -- packet-008-test-api-key >/dev/null 2>&1; then
  echo "environment root key was accepted in local-pilot mode" >&2
  exit 1
fi
unset CITADEL_MASTER_KEY

dd if=/dev/urandom of="$workdir/other.key" bs=32 count=1 status=none
export CITADEL_ROOT_KEY_FILE="$workdir/other.key"
hash_two="$($CARGO_BIN run -q -p citadel-api --bin hash-apikey -- packet-008-test-api-key | sed -n 's/^HASH://p')"
[[ "$hash_one" != "$hash_two" ]]
export CITADEL_ROOT_KEY_FILE="$workdir/root.key"

export CITADEL_API_KEY_HASH="$hash_one"
export CITADEL_DATA_DIR="$workdir/data"
export CITADEL_SEED_DEMO=false
export CITADEL_PORT=39008

$CARGO_BIN build -q -p citadel-api --bin citadel-api
target/debug/citadel-api >"$workdir/server.log" 2>&1 &
server_pid=$!

healthy=0
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$CITADEL_PORT/health" >/dev/null; then
    healthy=1
    break
  fi
  sleep 0.1
done
[[ "$healthy" = 1 ]]

kill "$server_pid"
wait "$server_pid" || true
server_pid=""

echo "local-pilot-hash-bootstrap=pass"
echo "permission-and-symlink-rejection=pass"
echo "environment-root-rejection=pass"
echo "different-provider-separation=pass"
echo "api-health-startup=pass"
