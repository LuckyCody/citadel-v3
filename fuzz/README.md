# Citadel Envelope Fuzz Targets

This directory contains fuzz targets for security testing using `cargo-fuzz`.

## Prerequisites

```bash
# Install cargo-fuzz (requires nightly Rust)
cargo install cargo-fuzz
```

## Fuzz Targets

### 1. Wire Format Parser (`fuzz_wire_parse`)

Tests the wire format parser with arbitrary input bytes.

```bash
cargo +nightly fuzz run fuzz_wire_parse
```

**Goal:** Find panics or unexpected behavior in `parse_hybrid_wire()`.

### 2. Decrypt Path (`fuzz_decrypt`)

Tests the full decryption path with arbitrary ciphertexts.

```bash
cargo +nightly fuzz run fuzz_decrypt
```

**Goal:** Find panics, hangs, or timing anomalies in `decrypt()`.

### 3. Roundtrip (`fuzz_roundtrip`)

Verifies that `decrypt(encrypt(x)) == x` for arbitrary inputs.

```bash
cargo +nightly fuzz run fuzz_roundtrip
```

**Goal:** Find cases where valid encryptions fail to decrypt correctly.

## Running Fuzzing

```bash
# Run indefinitely (Ctrl+C to stop)
cargo +nightly fuzz run fuzz_wire_parse

# Run for a specific duration
cargo +nightly fuzz run fuzz_wire_parse -- -max_total_time=3600

# Run with multiple jobs
cargo +nightly fuzz run fuzz_wire_parse -j 4

# Minimize corpus
cargo +nightly fuzz cmin fuzz_wire_parse
```

## Coverage

To generate coverage reports:

```bash
cargo +nightly fuzz coverage fuzz_wire_parse
```

## Crash Analysis

Crashes are saved in `fuzz/artifacts/fuzz_target_name/`. To reproduce:

```bash
cargo +nightly fuzz run fuzz_wire_parse fuzz/artifacts/fuzz_wire_parse/crash-xxx
```

## Expected Results

- `fuzz_wire_parse`: Should never panic. All malformed input should return `Err(DecryptionError)`.
- `fuzz_decrypt`: Should never panic. Invalid ciphertexts should return `Err(DecryptionError)`.
- `fuzz_roundtrip`: Should never fail the assertion. All valid encryptions must decrypt correctly.

## Continuous Fuzzing

For production use, consider:

1. Running fuzzing in CI (e.g., OSS-Fuzz)
2. Maintaining a corpus of interesting inputs
3. Periodic regression runs against the corpus
