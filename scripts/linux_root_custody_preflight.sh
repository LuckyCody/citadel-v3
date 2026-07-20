#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d)"
cleanup() { rm -rf -- "$workdir"; }
trap cleanup EXIT

chmod 0700 "$workdir"
umask 077
dd if=/dev/urandom of="$workdir/root.key" bs=32 count=1 status=none
ln -s "$workdir/root.key" "$workdir/root.link"

echo "uid=$(id -u)"
echo "filesystem=$(findmnt -T "$workdir" -no FSTYPE)"
echo "key=$(stat -c '%a %u %F %s' "$workdir/root.key")"
echo "link=$(stat -c '%a %u %F' "$workdir/root.link")"

test "$(stat -c '%a' "$workdir/root.key")" = "600"
test "$(stat -c '%u' "$workdir/root.key")" = "$(id -u)"
test "$(stat -c '%s' "$workdir/root.key")" = "32"
test -L "$workdir/root.link"

chmod 0644 "$workdir/root.key"
test "$(stat -c '%a' "$workdir/root.key")" = "644"
echo "insecure-mode-detectable=yes"
