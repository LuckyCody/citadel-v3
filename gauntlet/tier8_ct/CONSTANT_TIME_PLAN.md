# Tier 8 — Constant-Time as a Proof (not a measurement)

**Status: BLOCKED on a one-line system install (needs root).** Everything is
specified and ready to run; the tools require `sudo apt` / LLVM packages, and
sudo in this WSL needs a password. Unblock with **`sudo apt-get install -y valgrind`**
(and optionally the LLVM/boolector stack below), then run the commands here.

## Why this tier exists

`TIMING.md` documents a *measured* key-material-dependent timing effect in ML-KEM
decapsulation (via dudect — a black-box statistical test). dudect can only say
"we saw/didn't see a difference." It cannot **locate** a leak or **prove** its
absence. Tier 8 upgrades that to instruction-level evidence.

Target: the ML-KEM-768 decapsulation path (`kem::decapsulate` /
`diagnostic_mlkem_decapsulate_only`) and the AEAD tag comparison.

## Tools (all free/OSS), in order of leverage

1. **ctgrind (valgrind memcheck client requests)** — mark secret bytes as
   "uninitialized," run under valgrind; any branch or memory index that depends on
   a secret byte is reported with a stack trace. Cheapest, most direct.
   - Install: `sudo apt-get install -y valgrind`
   - Instrument: wrap the secret key bytes with `VALGRIND_MAKE_MEM_UNDEFINED` before
     decapsulation in a `#[cfg(feature="ctgrind")]` harness.
   - Run: `valgrind --error-exitcode=1 ./target/debug/ct_harness`
2. **DATA** (Graz, github.com/IAIK/DATA) — differential address-trace analysis;
   runs the binary under Pin/valgrind with two secret classes and does statistical
   leakage detection at address granularity. Heavier setup; the definitive dynamic tool.
3. **haybale-pitchfork** (github.com/PLSysSec/haybale-pitchfork) — *symbolic*
   execution over LLVM bitcode that **proves** constant-time (or yields a
   counterexample path). No sampling. Needs LLVM + boolector:
   - `sudo apt-get install -y llvm-dev libclang-dev boolector`
   - Emit bitcode for the decap function, point pitchfork at it, mark secret args.
4. **MicroWalk** / **Binsec/Rel** — alternatives for microarchitectural / relational
   CT verification if 1–3 are inconclusive.

## Expected outcome

Either (a) prove the decap path is constant-time at the instruction level —
promoting `TIMING.md`'s measured wobble to "not a code-level leak; the effect is
platform/microarchitectural," or (b) locate the exact secret-dependent branch/access,
which becomes a concrete fix. Both are strictly better than the current dudect-only
evidence.

## To run this tier

```bash
sudo apt-get install -y valgrind          # unblock ctgrind (2 min)
# then the ctgrind harness + optional DATA/haybale per above
```
Grant that (or passwordless sudo) and this tier executes end-to-end.
