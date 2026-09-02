# ML-KEM-768 Provider Decision Log

## 2026-07-15: Replace abandoned PQClean chain with RustCrypto 0.3.2

This decision selected exact-pinned `ml-kem 0.3.2` as the release provider under
the preregistered scorecard in `PROVIDER_BAKEOFF_2026.md`.

The selected implementation passes all 60 checked-in final FIPS 203 ACVP
vectors directly through Citadel's provider boundary, matches libcrux on those
vectors, passes 10,000 randomized hybrid KEM round trips, rejects malformed
public and expanded private keys, and compiles the release-provider timing
bench. The `pqcrypto-mlkem`, `pqcrypto-traits`, and `pqcrypto-internals` crates
are absent from the root and fuzz lockfiles.

Citadel v1 must keep its 2400-byte expanded private-key encoding, so the
provider's deprecated expanded-key compatibility API is isolated to v1 import,
export, diagnostics, and migration benches. A future decision may select the preferred
64-byte seed representation for v2; v1 bytes are not silently changed.

This supersedes the 2026-07-09 keep-PQClean decision because the decisive new
fact is the RustSec abandonment of the PQClean production chain. It does not
claim that RustCrypto has been independently audited: its upstream documentation
explicitly says it has not.

## 2026-07-09 (update): Bare-metal results — all providers fail key-A-vs-key-B

Bare-metal testing on DigitalOcean Premium Intel (Ubuntu 24.04) showed that
**all three providers** (PQClean, libcrux, AWS-LC) fail key-A-vs-key-B dudect.
The earlier WSL results that showed PQClean passing were environmental noise.

| Provider | Control | key-A-vs-key-B |
|---|---|---|
| PQClean | PASS (2.18) | FAIL: 41, 17, 136 |
| libcrux | PASS (1.92) | FAIL: 61 |
| AWS-LC | PASS (2.20) | FAIL: 3.5, 36, 61, 1106, 47 |

Source inspection of PQClean found no code-level CT violations. The signal
is consistent with hardware data-dependent execution (Hertzbleed-class).

**Decision: keep PQClean as production provider.** Switching providers is not
justified — all three fail the same class. Provider choice is made on build
simplicity, maintenance, and audit history, not on a timing signal that all
share equally.

See docs/security/TIMING.md for the full finding, risk assessment, and required wording.

---

## 2026-07-09: Switch from libcrux to PQClean

### Decision

Replace `libcrux-ml-kem 0.0.9` with `pqcrypto-mlkem 0.1.1` as the production
ML-KEM-768 provider in citadel-envelope.

### Reason

dudect timing validation (key-A-vs-key-B shared-buffer bench) showed
key-material-dependent timing in libcrux decapsulation. PQClean passed the
same test on the same machine, same harness.

### Results (standalone mlkem_standalone bench, WSL Ubuntu, 2026-07-09)

| Provider | Crate | same-key control | key-A-vs-key-B |
|---|---|---|---|
| libcrux | libcrux-ml-kem 0.0.9 | PASS, \|t\| = 1.92 | FAIL, \|t\| = 19.5 |
| PQClean | pqcrypto-mlkem 0.1.1 | PASS, \|t\| = 3.43 | PASS: 2.88, 3.80, 3.58 |
| AWS-LC | aws-lc-rs 1.17.1 | PASS, \|t\| = 2.20 | FAIL, \|t\| = 7.22 |

PQClean passed 3/3 independent runs below |t| < 4.5 threshold.

### Previous provider (rollback target)

If PQClean causes other issues (KAT failures, integration bugs, performance
regression), revert to libcrux by changing citadel-envelope/Cargo.toml:

```toml
# Production provider — revert to this if PQClean causes issues:
libcrux-ml-kem = { version = "=0.0.9", default-features = false, features = ["mlkem768"] }
```

And in `citadel-envelope/src/kem.rs`, restore the libcrux import and type
aliases:

```rust
use libcrux_ml_kem::mlkem768;
type LcMlKemPublicKey = mlkem768::MlKem768PublicKey;
type LcMlKemSecretKey = mlkem768::MlKem768PrivateKey;
```

libcrux keygen takes a `[u8; 64]` seed, encapsulate takes `(pk, [u8; 32])`.
The KemProvider trait impl routes through these. All type mappings and API
shapes are documented in the git history of kem.rs at the commit prior to
the PQClean switch.

### What libcrux got right

- Formally verified in F*/HACL* — the algorithm logic is proven correct
- All KAT and round-trip tests passed
- Same-key controls passed (no harness artifact)
- Clean pure-Rust build, no C compiler needed

The timing signal is likely from the F*-to-Rust extraction or LLVM codegen
not preserving constant-time properties of the verified source. This is worth
reporting upstream to Cryspen with the standalone repro bench.

### What to watch after the switch

- Re-run `cargo test -p citadel-envelope --test primitive_kat` (must pass 20/20)
- Re-run `cargo test -p citadel-envelope --test nist_acvp_kat` (must pass 14/14)
- Re-run full workspace tests
- Re-run the full timing_sidechannel bench suite (not just standalone)
- Verify key sizes: pk=1184, sk=2400, ct=1088, ss=32 (FIPS 203)
- Monitor for any performance regression in encrypt/decrypt latency

### Crate details for rollback

| Field | libcrux (previous) | PQClean (current) |
|---|---|---|
| Crate | libcrux-ml-kem | pqcrypto-mlkem |
| Version | 0.0.9 | 0.1.1 |
| Language | Rust (F* extraction) | C (compiled via cc) |
| License | Apache-2.0 | Apache-2.0 / MIT (code: CC0) |
| Build deps | None (pure Rust) | C compiler (cc crate) |
| CT claim | Formally verified | Reference implementation, dudect validated |
| FIPS 203 | Yes | Yes |
