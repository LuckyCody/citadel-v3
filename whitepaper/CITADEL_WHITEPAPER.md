# Citadel: A Hybrid Post-Quantum Envelope and Key-Management Implementation

**Author:** Andre Cordero  
**Status:** Draft, 2026-08-05. Beta-stage. Validated through the known-answer tests, adversarial suite, and machine-checked combiner proofs described in Section 6; not third-party audited or CMVP-validated as a deployment.

## Abstract

Citadel is a key-management and envelope-encryption system that combines a classical
key-encapsulation mechanism with a post-quantum one, so that a stored ciphertext is designed to stay
confidential as long as either mechanism remains unbroken. It ships two suites. The first pairs X25519 with
ML-KEM-768. The second pairs P-384 with ML-KEM-1024 and targets the higher security category named in
NSA's CNSA 2.0 guidance. Data is sealed with AES-256-GCM under a key derived through HKDF-SHA256 from
a transcript that binds the suite and the recipient identity. The system runs in two modes. The
default mode uses pure-Rust cryptography. An optional mode routes the category-5 suite's
key-encapsulation operations and the shared symmetric primitives, which are AES-256-GCM, HKDF-SHA256,
and the hash functions, through the AWS-LC cryptographic library, executing inside the exact build
that CMVP validated as AWS-LC-FIPS 3.1.0, while all category-5 recipient key-pair generation, for both
the P-384 and the ML-KEM arm, and ML-KEM seed expansion stay in pure Rust. This paper documents the design, the implementation choices, and the measured results,
including known-answer tests, an adversarial test suite, and machine-checked secrecy proofs for the
category-5 combiner. It also states plainly what has not been established: there is no independent
security audit, no FIPS 140-3 validation of any deployment, and no production track record.

## 1. Scope and honest framing

This document describes an implementation, not a new cryptographic primitive and not a security
proof of a deployed product. Every primitive Citadel uses is a published standard, and the value of
the work is in composing those primitives correctly, testing that composition hard, and stating the
boundaries of each claim.

Three boundaries hold throughout the paper. First, a working and test-passing composition is not an
independently reviewed security proof. Second, executing an algorithm that appears in a FIPS standard
is not FIPS validation of the module or the deployment. Third, results measured in one environment do
not transfer to another without direct evidence. These are not disclaimers added at the end. They are
the reason the claim language in this paper is narrow.

## 2. Background and threat model

### 2.1 Why migrate now

Most of the encryption that protects data today depends on public-key algorithms such as RSA and
elliptic-curve Diffie-Hellman. A large enough quantum computer would break those algorithms. No such
machine is known to exist yet, but the risk does not wait for one to arrive. An attacker can copy
encrypted data today, store it, and decrypt it years later once the hardware exists. Anything that has
to stay secret for a long time, such as health records, financial records, or archived
communications, is exposed to that record-now-decrypt-later approach from the moment it is stored.

NIST's initial-public-draft transition plan describes its expected approach for moving off the
quantum-vulnerable algorithms, and for the migration period it discusses hybrid key-establishment
techniques that run a classical algorithm and a post-quantum algorithm together, with the intended
property that the result stays secure unless both are broken, subject to construction-specific
analysis [A11]. NSA's CNSA 2.0 suite
names the specific algorithms and deadlines for national-security systems, and it is the reason
Citadel's second suite targets the stronger parameter set [A12]. Citadel is built for this migration
period. It does not ask an operator to drop the classical algorithms that are well understood, and it
does not ask them to trust a post-quantum algorithm on its own.

### 2.2 What Citadel protects, and what it does not

Citadel works as a store-and-forward service. An application sends plaintext to Citadel and receives a
single self-contained encrypted blob that it can store in any database. The blob carries the wrapped
key material, the algorithm identifiers, and the ciphertext. To read the data back, the application
sends the blob to Citadel with the same associated data and context it used to encrypt.

The attacker in this model can see stored blobs and can submit chosen inputs to the encryption and
decryption interface. The design objective is confidentiality of the plaintext and rejection of any
unauthorized modification of an existing envelope and its bound metadata. Citadel is built to keep the
plaintext confidential when one of the two key-encapsulation mechanisms in the active suite fails,
provided AES-256-GCM still holds. The evidence for that objective is conditional and suite-specific.
Sections 3.2 and 6.4 give the assumptions and the gap between the model and the running code, and the
objective is not stated here as an unconditional guarantee about the shipped implementation. The
format does not authenticate a sender. Any party that holds the recipient's public key, or that is
allowed to call the encryption interface, can create a new valid envelope. Sender authentication is
out of scope and would require a separate signature layer.

The model has limits, and they are stated up front. It does not cover an attacker who has already
taken over the host and can read process memory while an operation runs. It does not cover key custody
in dedicated hardware. Root-key custody in Citadel is software-based today, and no hardware security
module is claimed.

## 3. Design

### 3.1 Two hybrid suites

A key-encapsulation mechanism, or KEM, is the modern way two parties agree on a shared secret. The
sender uses the recipient's public key to produce a short ciphertext and a secret value, and the
recipient uses their private key to recover the same secret from that ciphertext. Citadel uses two
KEMs together in each suite, one classical and one post-quantum, and selects the suite with a single
byte in the wire format. The envelope performs no in-envelope suite negotiation. The authenticated
suite identifier and the suite-specific key types remove that protocol-level negotiation downgrade
path. Application-level suite selection is outside this claim.

Suite `0xA3` pairs X25519 with ML-KEM-768. X25519 is a widely deployed elliptic-curve Diffie-Hellman
function from RFC 7748 [A13, B2]. Citadel rejects non-contributory low-order inputs by checking for an
all-zero shared secret. This is a contributory-behavior check rather than a general public-key
rejection rule, since X25519 accepts the non-canonical input encodings that RFC 7748 requires. The
constant-time behavior of the classical arm is discussed with its evidence in Section 6.5. ML-KEM-768
is the module-lattice KEM standardized in FIPS 203 at category 3, the post-quantum algorithm NIST
selected for general use [A1, B1].

Suite `0xA4` pairs P-384 with ML-KEM-1024. P-384 is a NIST elliptic curve from FIPS 186-5 and SP
800-186, and ML-KEM-1024 is the category-5 parameter set of FIPS 203, the higher of the two strength
levels [A4, A10, A1]. ML-KEM-1024 and AES-256 align with the CNSA 2.0 target categories for
national-security use, while P-384 is retained as a classical transition hedge. CNSA 2.0 moves away
from elliptic-curve public-key algorithms rather than naming a P-384 with ML-KEM-1024 hybrid, so this
pairing is Citadel's design choice and not a CNSA-specified suite [A12].

### 3.2 Combining the two secrets

Each suite runs both KEMs and ends up with two shared secrets, one from the classical elliptic-curve
Diffie-Hellman step [A7, A13] and one from the post-quantum one. Citadel does not choose between them. It joins the two secrets and
passes them through HKDF-SHA256, a standard key-derivation function, to produce the single key that
encrypts the data. The construction is intended, under the assumptions stated below, to require
compromising both underlying algorithms to recover the derived key, so the data stays protected if
either algorithm holds. This intent is grounded in the KEM-combiner literature, which analyzes specific combiner
constructions and shows, under stated assumptions about the key-derivation step, that the combined
KEM stays secure as long as one ingredient KEM stays secure [B3, B4]. The X-Wing construction applies
the same idea to X25519 with ML-KEM-768 and is referenced here as a comparator, not as a proof that
Citadel is equivalent to X-Wing [B5, A18]. For the `0xA4` suite, the combiner's secrecy is
machine-checked in an abstract model, described in Section 6.4. For `0xA3` the argument rests on the
literature above, and in both cases the proofs are of models rather than of the Rust code. HKDF is
used in its standard extract-then-expand form, following Krawczyk's analysis, RFC 5869, and SP 800-56C
[B6, A14, A8].

The derivation does not take the raw secrets alone. Citadel derives the key over a length-prefixed
transcript that also binds the suite and the recipient, so a blob produced for one suite or one
recipient will not decrypt under a different one. The next section describes how that binding is laid
out on the wire.

### 3.3 Wire format and transcript binding

An envelope is a fixed 98-byte header, followed by the suite's key-encapsulation ciphertext, followed
by the AES-256-GCM ciphertext and tag, using AES [A3] under an authenticated-encryption interface
[A15]. The 98-byte header holds, in order, the four-byte magic value
`CTD2`, the version, a flags byte, the suite byte, the KDF and AEAD identifiers, a reserved byte, the
header length, the key-encapsulation-ciphertext length, the plaintext length, a 32-byte SHA3-256 hash
of the recipient's public key, a 32-byte SHA3-256 hash of the context, and the 12-byte AES-GCM nonce.
The sender's ephemeral public value and the post-quantum ciphertext are not in the header. They live
in the key-encapsulation ciphertext that follows it.

Two design points matter for authentication. First, the key-derivation transcript and the AEAD
associated data both bind the first 86 bytes of the header, the key-encapsulation ciphertext, and the
raw context. The first 86 header bytes themselves include the suite byte, the SHA3-256 hash of the
recipient's public key, and the SHA3-256 hash of the context. The AEAD associated data additionally
binds the caller-supplied additional authenticated data. This ties every ciphertext to the exact
suite and the exact recipient. A blob relabeled to a different suite, or aimed at a different recipient key, fails
to derive the same key and fails to open. Second, the 12-byte nonce is the last part of the header, at
offsets 86 through 97, outside the bytes fed to the key derivation. The nonce is still
integrity-protected, because AES-GCM authenticates its own nonce. This layout lets the FIPS backend
generate the nonce inside the module without changing the bytes that the key derivation binds.

### 3.4 Key hierarchy

Citadel manages keys in a four-level hierarchy of Root, Domain, KEK, and DEK. This is a
Citadel-specific hierarchy, informed by the key roles and lifecycle guidance in SP 800-57 Part 1
rather than prescribed by it [A9]. The root is a logical offline authority. The online
wrapping chain runs from Domain to KEK to DEK, so that the compromise of one data-encryption key does
not expose others. The keystore also implements lifecycle states, crypto-period policies, and an
integrity-chained audit log. These are operational features, and their guarantees are stated with the
limits in Section 8.

## 4. Implementation

Citadel is a Rust workspace of seven crates covering the envelope core, the keystore, the HTTP API, a
command-line interface, a signer, C and language bindings, and shared types. The envelope core is the
security-critical crate.

### 4.1 Two backends behind one seam

The cryptography sits behind a backend seam. The default backend uses pure-Rust crates from the
RustCrypto project: `ml-kem` for ML-KEM, `p384` and `x25519-dalek` for the classical parts, `aes-gcm`
for the AEAD, and `hkdf` and `sha3` for derivation and hashing. Building with the `fips` feature
selects the AWS-LC backend at the seam, through the `aws-lc-rs` bindings over `aws-lc-fips-sys`.

The FIPS backend does not move every operation into AWS-LC, and the scope is worth stating exactly. On
the `fips` build, suite `0xA4`'s key-encapsulation operations, which are P-384 ECDH and ML-KEM-1024
encapsulation and decapsulation, run in AWS-LC, and so do the symmetric primitives that both suites
share: AES-256-GCM, HKDF-SHA256, SHA-2, SHA-3, and the module-generated random nonce. Suite `0xA3`'s
key-encapsulation arm, which is X25519 and ML-KEM-768, stays in pure Rust on both builds. Recipient
key-pair generation, for both the P-384 arm and the ML-KEM arm, and the expansion of an ML-KEM key
from its stored seed, also stay in pure Rust on both builds, because the AWS-LC bindings at the pinned
version expose no seed import and no scalar export. So on the `fips` build AWS-LC runs the `0xA4`
P-384 ECDH and ML-KEM-1024 encapsulation and decapsulation, but not the generation of the recipient's
`0xA4` key pair. The table below summarizes which component runs where.

| Operation | Default build | `fips` build, `0xA3` | `fips` build, `0xA4` |
|---|---|---|---|
| Recipient key-pair generation (X25519 or P-384, and ML-KEM) | pure Rust | pure Rust | pure Rust |
| ML-KEM stored-seed expansion | pure Rust | pure Rust | pure Rust |
| Classical shared-secret computation (ECDH) | RustCrypto | RustCrypto (X25519) | AWS-LC (P-384) |
| Post-quantum encapsulation and decapsulation | RustCrypto | RustCrypto (ML-KEM-768) | AWS-LC (ML-KEM-1024) |
| AES-256-GCM | RustCrypto | AWS-LC | AWS-LC |
| HKDF-SHA256, SHA-2, SHA-3 | RustCrypto | AWS-LC | AWS-LC |
| Random nonce | RustCrypto, getrandom | AWS-LC module DRBG | AWS-LC module DRBG |

The wire codec, the suite table, and the transcript construction are shared by both backends by
design, and the two backends interoperate: an envelope sealed by one opens with the other. They do not
produce identical seal output, because sealing is randomized. The FIPS AES-GCM path uses the module's
randomized-nonce interface, which generates the nonce internally, so two seals of the same input carry
different nonces and different bytes by design. What is verified is wire compatibility, cross-backend
open interoperability, an equivalent transcript construction, and reproduction of frozen deterministic
test vectors on the default path, where the nonce can be fixed. The FIPS AES-GCM path is verified
instead by round-trip, interoperability, and nonce-liveness tests (Section 6). Because the FIPS claim
covers operations and not key-pair generation or stored-seed expansion, the claim in Section 5 is
scoped accordingly.

### 4.2 Provider selection

The production ML-KEM provider is RustCrypto `ml-kem` 0.3.2, pinned exactly, with zeroization enabled.
An earlier provider chain based on an abandoned library was replaced, and the advisories tied to that
old chain are absent from the production lockfile. The RustCrypto crates carry their own
not-independently-audited disclaimer, which local known-answer tests do not remove. This is recorded
rather than glossed.

## 5. FIPS and CMVP posture

The FIPS backend is where claim discipline matters most, because the words "FIPS" and "validated" are
easy to misuse.

What is true, and measured, is the following. Building with the `fips` feature links AWS-LC-FIPS
3.1.0, the build named on CMVP certificates #5298 (dynamic) and #5314 (static) [A19, A20], through the
pinned `aws-lc-fips-sys` 0.13.11 [C1]. The linked version is checked at runtime: a test reads the module version string through the
library and fails if it does not match the pinned value, and both negative controls for that test fire
as expected. FIPS mode is asserted active at runtime, with `FIPS_mode()` returning 1 before and after
cryptographic use, and the module constructor is fail-closed on an integrity-check mismatch per the
upstream design. The module's approved-algorithm list, read from the certificate's security policy [A21],
includes ML-KEM and SHA3-256 under the algorithm certificates named there, which covers the
AWS-LC-executed ML-KEM encapsulation and decapsulation and the recipient-and-context hash. Citadel's
own ML-KEM key generation and seed expansion, and its `0xA4` P-384 key generation, run in pure Rust
and are outside the module. The AES-GCM nonce is generated inside the
module under approved GCM IV Scenario 2 [A6, A17], using the module's randomized-nonce interface, after
an earlier version was found to use the module's external-IV mode and was corrected. Reusing a GCM
nonce is catastrophic, which is the reason the module generates the nonce internally [B7, B8, B9].

What is not true, and is prohibited as a claim, is that any Citadel deployment is FIPS 140-3
validated or FIPS compliant. The certificate validates one build on two tested operating environments,
both Amazon Linux 2023 on specific instance families, and the security policy records no
vendor-affirmed operating environments [A21]. Citadel's canonical environment is Ubuntu under WSL2, which is
not a tested environment, so no validated-deployment claim is available regardless of the pin. The
system implements the CNSA 2.0 algorithms in the `0xA4` suite, but implementing the algorithms is not
CNSA compliance, exactly as implementing a FIPS 203 algorithm is not FIPS 140-3 validation [A5, A16].
Signing uses pure-Rust ML-DSA, the algorithm in FIPS 204 [A2], on every build, because the pinned
AWS-LC bindings compile their ML-DSA API only
outside FIPS mode, so there is no claim that signing executes inside the module. The module runs its
default seeding path, so there is no CPU-jitter-entropy claim.

The choice to pin the validated 3.1.0 build rather than a later 3.4.0 build is deliberate and has a
recorded cost. The 3.1.0 build carries two advisories that the later unvalidated build fixed, one for
certificate revocation lists and one for AES-CCM. Neither applies to Citadel, which uses no X.509 or
CRL handling and no AES-CCM. Both are recorded, scoped in the dependency policy, and disclosed in the
supply-chain document, to be revisited when a validated build past the fix ships.

## 6. Results

### 6.1 Test suites

Three suites are reported. On the default build the workspace test suite reports 435 passing, 0
failing, and 9 ignored, confirmed on a fresh run for this paper. The known-answer-test suite, built
with the test-vector feature, reports 190 passing, 0 failing, and 5 ignored, also confirmed on a
fresh run. With the FIPS feature added, the known-answer suite reports 223 passing, 0 failing, and 5
ignored on the pinned validated build, as recorded when that suite last ran under the AWS-LC backend.
The ignored tests are not counted as passes and were not executed in these runs. They include stress
and volume tests, documentation examples, and a deterministic fuzz-seed generator, and an ignored
status says nothing about whether a test would pass. These numbers are for one environment and are
reported as measured, not as assurance.

### 6.2 Known-answer tests

The production ML-KEM provider passes the 60 ACVP vectors for FIPS 203 executed directly through the
RustCrypto `ml-kem` 0.3.2 path, together with a ten-thousand-round-trip release test and a
byte-for-byte differential against a second independent implementation. For the category-5 suite, the
implementation passes NIST ACVP vectors for ML-KEM-1024 and Wycheproof vectors for P-384 ECDH, both
provenance-verified, along with a deterministic envelope test vector, property-based round-trip tests,
and a fuzz corpus. Seal and open are exercised end to end from Rust, Python, C, and Java bindings. A
known-answer test exercises the wrapper and provider path on the selected vectors. It does not by
itself establish general wrapper correctness or the wrapped primitive's conformance, so these results
are stated only for the exact provider, path, and vectors tested.

### 6.3 Adversarial testing

Citadel carries an adversarial test suite that runs on both backends and tries to break the
authentication and nonce properties rather than confirm the happy path. The suite was executed at
high volume in a separate automated run, recorded at a fixed commit on the project's Ubuntu-under-WSL2
environment, and the results below are from that run. This is a test execution, not a security audit,
and it is not an execution on an independently controlled host. Section 8 states that no independent
audit exists. At every byte position the suite executed up to four
mutation attempts drawn from three replacement rules, which are XOR with 0x01, add 1, and XOR with
0xFF, and it also exercised seven selected truncation lengths. All 5,099 `0xA3` and 7,279 `0xA4`
mutation and truncation executions per backend returned an error, with zero accepted plaintext and
zero panics. These totals are execution counts, they include duplicate inputs, and they are not an
exhaustive enumeration of every byte substitution or truncation. A high-volume metamorphic test confirmed
round-trip correctness over tens of thousands of random inputs per suite and backend, with fresh
nonces on repeated seals and correct rejection of wrong associated data and wrong context. A
nonce-uniqueness test at scale produced 200,000 distinct, non-zero nonces on both the default and the
FIPS backend, which exercises the randomized-nonce path that the FIPS AES-GCM depends on. Cross-suite
isolation held: a `0xA3` envelope never opened under a `0xA4` key or the reverse. That run also
included two sabotage checks, one altering the module-version pin and one corrupting a frozen test
vector, and both were caught by the suite before the tree was restored.

### 6.4 Formal verification of the combiner

The `0xA4` hybrid combiner's secrecy is machine-checked in CryptoVerif 2.12 [B11]. Two proofs, one
treating the P-384 DHKEM arm as an IND-CCA2 KEM at cofactor one where the prime-order abstraction is
faithful, and one treating the ML-KEM-1024 arm as an IND-CCA2 KEM, each return a proof that the derived
key is secret, with a clean exit and no admitted steps. Each proof establishes that the derived key
stays secret if the surviving component KEM is secure, even if the other component is fully broken,
which is exactly the hybrid property the design aims for. The proofs model the abstract combiner with a
random-oracle key-derivation step. They are not proofs of the Rust code. The
known-answer, property, and fuzz tests provide implementation evidence for selected encodings,
transcripts, interoperability, and negative cases, but they do not close the gap between the abstract
model and the code.

### 6.5 Timing behavior

On the default backend the P-384 ECDH path is constant-time by source-level design. The shipped path
uses the constant-time scalar multiplication in the RustCrypto `p384` crate, version 0.14.0 [C2], with
secret-dependent operations built on the `subtle` crate's constant-time primitives and with off-curve
and identity points rejected before the multiply. This is a source-level review of that crate and the
shipped call path, not an assembly-level or audit-level result. On the `fips` backend the `0xA4`
P-384 operations run in AWS-LC, a separate implementation with its own constant-time posture that this
source review does not cover.

An empirical timing study using the dudect leakage-detection method [B10, C3] did not produce a clean
positive or negative result for the P-384 key-material path. The method is one-sided, so it can fail to
reject a leak but cannot prove constant-time behavior. In a well-powered run the P-384 statistic
straddled the decision threshold without persisting or growing with sample count, which is consistent
with the measurement noise floor, while a positive control on ML-KEM produced a clear signal and the
attacker-controlled controls stayed clean. A separate pre-registered study to test whether the FIPS
backend measurably improves the P-384 timing story did not establish that claim. In the first attempt
the RustCrypto null control fired above the decision threshold while the AWS-LC controls stayed below
it, which already voids a comparison, because a comparative claim needs both arms to have valid
controls. A second, tighter attempt saw the null control fire in both arms. In both attempts a
same-session positive control on ML-KEM fired clearly, so the measurement was sensitive. Neither
attempt supports a backend comparison, and the evidence points at the measurement construction rather
than at either backend. The honest state is that the empirical timing row is inconclusive, not clean,
and the design-level constant-time property is the supported claim.

## 7. Choices and trade-offs

Several decisions in Citadel trade one property for another, and each was made in the open.

Pinning the validated 3.1.0 module rather than the latest 3.4.0 build trades currency for a real
validated-build link. The cost is the two non-applicable advisories in Section 5. The alternative,
which is to chase the version API that would let the code read the module version through a supported
call, forces the module to 3.4.0, which is not the validated build, so it was rejected.

Moving the FIPS AES-GCM to the module's randomized-nonce interface trades the ability to freeze
seal-output bytes for compliance with an approved IV scenario. Because the randomized-nonce interface
owns the nonce, the FIPS backend cannot produce byte-frozen seal vectors, so byte-frozen vectors are a
default-backend artifact and the FIPS path is instead tested through round-trip, cross-backend open interoperability, frozen-decrypt known-answer tests, and nonce-liveness
tests. Tampering with the nonce is still detected, because GCM authenticates its own nonce.

Keeping ML-KEM key generation and seed expansion in pure Rust on the FIPS backend trades a fully-in-
module claim for a working implementation at the pinned version, which exposes no seed import or scalar
export. This is why the FIPS claim is scoped to operations, and specifically excludes key-pair
generation and stored-seed expansion. HKDF-SHA256, which is the envelope's actual key derivation, does
run in AWS-LC on the FIPS build.

Excluding the nonce bytes from the key-derivation transcript trades a slightly simpler mental model for
a layout that lets the module generate its own nonce without disturbing the authenticated binding. The
nonce remains integrity-protected through GCM.

## 8. What is not established

The following are stated as non-claims, and they bound everything above.

There is no independent security audit of Citadel. There is no FIPS 140-3 or CMVP validation of any
Citadel deployment. The system is beta-stage and has no production track record. The pure-Rust ML-KEM
and P-384 providers are not independently audited, and their own disclaimers stand. Native Windows
operation under current code-integrity policy is not tested, and Linux results do not transfer to
Windows. Root-key custody is software-based, with no hardware-module claim. Replay protection is
backend-dependent rather than durable across all failure modes: an in-memory backend loses state on
restart, and a batched file mode has a crash window. Audit logs are integrity-chained locally but are
not anchored to an external immutable store. The formal proofs are of an abstract model, not of the
Rust code. The empirical timing results are inconclusive, not clean. Claims advance only when the exact
artifact, version, configuration, and environment named by the claim pass the matching test.

## 9. License and availability

Citadel is dual-licensed. It is available under the GNU Affero General Public License version 3 or
later for open-source use, and under a separate commercial license for proprietary use. Building with
the FIPS feature links AWS-LC, which carries code under the OpenSSL License and the Original SSLeay
License, terms otherwise incompatible with the AGPL absent an explicit exception. `LICENSE-EXCEPTION`
grants an additional permission under AGPL section 7 covering this combination, granted by the
copyright holder on his own code. The default pure-Rust build does not link any OpenSSL-licensed code.
The exception text and third-party notices ship with the source.

## References

See `REFERENCES.md` in this directory for the full reference list. Citations above use those
identifiers: A-series for standards and government publications, B-series for academic and archival
cryptography literature, and C-series for implementation and tooling.
