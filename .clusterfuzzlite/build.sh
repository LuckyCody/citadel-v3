#!/bin/bash -eu
# Build Citadel's cargo-fuzz targets for ClusterFuzzLite (base-builder-rust
# provides the sanitizer RUSTFLAGS and cargo-fuzz).

build_workspace () {
  local dir="$1"; shift
  pushd "$SRC/citadel-v3/$dir" >/dev/null
  cargo fuzz build -O --debug-assertions
  local out="fuzz/target/x86_64-unknown-linux-gnu/release"
  for target in "$@"; do
    cp "$out/$target" "$OUT/"
  done
  popd >/dev/null
}

# citadel-envelope fuzz workspace — wire/envelope/decrypt parsers (attack surface).
build_workspace citadel-envelope \
  decode_wire decode_envelope_v2 decrypt_full decrypt_v2_mutation

# top-level fuzz workspace — roundtrip, FFI free(), wire parse.
build_workspace . \
  fuzz_decrypt fuzz_ffi_free fuzz_roundtrip fuzz_wire_parse
