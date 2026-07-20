#!/usr/bin/env bash
# Citadel Adversarial Gauntlet — preflight
# Reports what free/OSS validation tooling is available and what is missing.
# Read-only: it never installs. Prints an install hint per missing tool.
set -uo pipefail

ok()   { printf '  \033[32m[ok]\033[0m    %-16s %s\n' "$1" "$2"; }
miss() { printf '  \033[31m[MISSING]\033[0m %-13s install: %s\n' "$1" "$2"; }

hr() { printf '%s\n' "------------------------------------------------------------"; }

echo "=== Citadel gauntlet preflight ==="
hr
echo "Rust toolchains"
rustup toolchain list 2>/dev/null | sed 's/^/  /'
nver=$(rustc +nightly --version 2>/dev/null || true)
[ -n "$nver" ] && ok nightly "$nver" || miss nightly "rustup toolchain install nightly"

hr
echo "Cargo subcommands (crypto/security)"
for pair in \
  "miri:rustup component add miri --toolchain nightly" \
  "fuzz:cargo install cargo-fuzz" \
  "afl:cargo install cargo-afl" \
  "deny:cargo install cargo-deny" \
  "audit:cargo install cargo-audit" \
  "vet:cargo install cargo-vet" \
  "geiger:cargo install cargo-geiger" \
  "nextest:cargo install cargo-nextest"; do
  sub="${pair%%:*}"; hint="${pair#*:}"
  if cargo "$sub" --help >/dev/null 2>&1; then
    ok "cargo-$sub" "present"
  else
    miss "cargo-$sub" "$hint"
  fi
done

hr
echo "System tools"
for pair in \
  "valgrind:apt-get install valgrind" \
  "clang:apt-get install clang" \
  "gcc:apt-get install gcc" \
  "python3:apt-get install python3" \
  "jq:apt-get install jq" \
  "osv-scanner:go install github.com/google/osv-scanner/cmd/osv-scanner@latest"; do
  b="${pair%%:*}"; hint="${pair#*:}"
  if command -v "$b" >/dev/null 2>&1; then
    ok "$b" "$($b --version 2>&1 | head -1)"
  else
    miss "$b" "$hint"
  fi
done

hr
echo "Python oracle libs (independent differential source)"
python3 - <<'PY' 2>/dev/null || echo "  python3 unavailable"
import importlib.util as u
for m in ("cryptography",):
    s = u.find_spec(m)
    print(f"  [ok]    {m:<16}", "present" if s else "MISSING (pip install cryptography)")
PY

hr
echo "Network reachability (crates.io index)"
if timeout 8 cargo search --limit 1 zeroize >/dev/null 2>&1; then
  echo "  [ok]    crates.io reachable (online deps OK)"
else
  echo "  [warn]  crates.io not reachable — Tier 1 online deps will fail; run on a networked shell"
fi
hr
echo "preflight done"
