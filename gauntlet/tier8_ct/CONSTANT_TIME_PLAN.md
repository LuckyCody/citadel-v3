# Tier 8 — Constant-Time as a Proof (not a measurement)

**Status: harness COMPLETE and built; execution blocked on one root install.**
Done rootless (no sudo): valgrind 3.24.0 built into `~/.local`; the ctgrind harness
(`ctgrind_harness/`, a C shim over memcheck client requests — no crabgrind/bindgen/
libclang) compiles; glibc debug symbols fetched via `apt-get download libc6-dbg`
and extracted to `~/.local/dbgsym`. The ONE remaining blocker: valgrind's mandatory
`ld-linux` `strcmp` redirection needs those debug symbols in its default
`/usr/lib/debug` search path, and `--extra-debuginfo-path` did not resolve it —
placing them there needs root.

**Unblock (either):**
- `sudo apt-get install -y libc6-dbg` (puts glibc debuginfo where valgrind looks), OR
- `sudo cp -r ~/.local/dbgsym/usr/lib/debug/* /usr/lib/debug/`

**Then run (harness is ready):**
```bash
cd gauntlet/tier8_ct/ctgrind_harness
VALGRIND_INCLUDE=$HOME/.local/include cargo build
~/.local/bin/valgrind --error-exitcode=1 --track-origins=yes ./target/debug/ctgrind_harness
```
A clean run (ERROR SUMMARY: 0 errors) = no secret-dependent branch/addressing on the
ML-KEM decap path for that input. Any "Conditional jump ... depends on uninitialised
value" pinpoints the leaking instruction.

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
