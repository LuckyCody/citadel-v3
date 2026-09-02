# Preservation Ledger — citadel-v3

Baseline: upstream `master` @ `31deefe` (2026-09-02). This ledger numbers every capability the system has. Every change branch in this audit's execution phases is verified against it: each numbered item must be **intact**, **changed with a named ruling**, or **removed with a named ruling** — recorded in that branch's `LEDGER_CHECK_<phase>.md`. "Tests still pass" is not a ledger walk.

Scope note: this is a capability inventory for change-safety, not a security assessment.

## A. HTTP API (27 routes — citadel-api/src/main.rs:3339-3363)

| # | Capability | Anchor |
|---|---|---|
| A1 | GET `/` serves the embedded dashboard | main.rs:2631 |
| A2 | GET `/health` unauthenticated health check returning status+version | main.rs:1502 |
| A3 | GET `/api/status` (read) threat level + key counts | main.rs:1537 |
| A4 | GET `/api/metrics` (read) | main.rs:1562 |
| A5 | GET `/api/keys` (read) list keys | main.rs:1578 |
| A6 | POST `/api/keys` (manage) generate key | main.rs:1640 |
| A7 | GET `/api/keys/:id` (read) | main.rs:1621 |
| A8 | POST `/api/keys/:id/activate` (manage) | main.rs:1721 |
| A9 | POST `/api/keys/:id/rotate` (manage) | main.rs:1763 |
| A10 | POST `/api/keys/:id/revoke` (manage) | main.rs:1818 |
| A11 | POST `/api/keys/:id/destroy` (manage) | main.rs:1863 |
| A12 | POST `/api/keys/:id/encrypt` (encrypt) | main.rs:1896 |
| A13 | POST `/api/decrypt` (encrypt) | main.rs:1960 |
| A14 | POST `/api/keys/:id/sign` (encrypt) ML-DSA-65 signing | main.rs:2101 |
| A15 | POST `/api/verify` (read) signature verification | main.rs:2192 |
| A16 | GET `/api/keys/:id/verifying-key` (read) | main.rs:2272 |
| A17 | POST `/api/assertions/issue` (encrypt) CNA assertions | main.rs:2339 |
| A18 | POST `/api/assertions/verify` (read) | main.rs:2459 |
| A19 | GET `/api/threat` (read) | main.rs:2508 |
| A20 | POST `/api/threat/event` (manage) inject threat event | main.rs:2535 |
| A21 | POST `/api/threat/reset` (manage) | main.rs:2563 |
| A22 | GET `/api/policies` (read) | main.rs:2579 |
| A23 | POST `/api/expire` (manage) run due expirations | main.rs:2613 |
| A24 | GET `/api/auth/keys` (admin) | main.rs:2639 |
| A25 | POST `/api/auth/keys` (admin) create scoped/domain-scoped API key | main.rs:2682 |
| A26 | DELETE `/api/auth/keys/:id` (admin) | main.rs:2783 |
| A27 | GET `/api/auth/whoami` (read) | main.rs:2834 |

Plus cross-cutting API behaviors:
| # | Capability |
|---|---|
| A28 | Scope model read/encrypt/manage/admin with admin-implies-all (main.rs:84-117) |
| A29 | Per-IP token-bucket rate limiting with threat escalation on violations |
| A30 | Uniform opaque decryption errors (no oracle) + request_id in error bodies |
| A31 | Replay protection on decrypt (Memory/File/Redis backends per config) |
| A32 | Fail-closed startup gates (missing replay store, corrupt api-keys.json, missing master key in prod) |
| A33 | Constant-time API-key comparison (subtle::ConstantTimeEq) |
| A34 | Integrity-chained (SHA-256) audit log of lifecycle events |
| A35 | Domain-scoped API keys: non-admin keys restricted to allowed_domains (P222/P223) |

## B. CLI (15 subcommands — citadel-cli)

B1 `doctor` · B2 `key graph` · B3 `key inspect` · B4 `key generate` (root/domain/kek/dek incl. parent/policy/activate) · B5 `key rotate` · B6 `key revoke --reason` · B7 `key rewrap` · B8 `key destroy --confirm` · B9 `migrate hierarchy` (dry-run/execute) · B10 `audit export` (jsonl/json/limit) · B11 `audit verify-chain` · B12 `backup create` · B13 `backup verify` · B14 `backup restore` (dry-run/overwrite/conflict-skip) · B15 `replay status` (+ deprecation warning for CITADEL_REPLAY_BACKEND). Globals: `--data-dir`/CITADEL_DATA_DIR, `--output text|json`.

## C. FFI (12 exports — citadel-ffi/src/lib.rs; cdylib+staticlib "citadel")

C1 `citadel_public_key_bytes` · C2 `citadel_secret_key_bytes` · C3 `citadel_public_key_bytes_for_suite` · C4 `citadel_secret_key_bytes_for_suite` · C5 `citadel_keygen` · C6 `citadel_seal` · C7 `citadel_open` · C8 `citadel_p384_keygen` · C9 `citadel_p384_seal` · C10 `citadel_p384_open` · C11 `citadel_free` (zero-before-free) · C12 `citadel_error_string`. C13: catch_unwind guard on every entry point. C14: shipped bindings run: Python (test_citadel.py), Java (Citadel.java), C (test_citadel.c).

## D. Envelope / crypto composition (citadel-envelope)

| # | Capability |
|---|---|
| D1 | Suite 0xA3: X25519 + ML-KEM-768 + AES-256-GCM, HKDF-SHA256 |
| D2 | Suite 0xA4: P-384 + ML-KEM-1024 + AES-256-GCM (category 5, CNSA 2.0-aligned) |
| D3 | Wire v1 header (6-byte) DECODABLE FOREVER (API_FREEZE Tier 1) |
| D4 | Wire v2 header per WIRE_SPEC_V2.md — self-describing suite byte, no negotiation |
| D5 | AAD binding + application context (structural) fed into KDF info |
| D6 | Zeroizing<T> on shared secrets and derived AES keys |
| D7 | Frozen KDF construction: HKDF(x25519_ss||mlkem_ss, info=citadel-env-v1|aes|SHA3-256(kem_ct)|context) |
| D8 | Optional `fips` feature: envelope ops through AWS-LC-FIPS 3.1.0 pinned build |
| D9 | Frozen SDK surface (API_FREEZE Tier 1): Citadel::new/generate_keypair/seal/open, PublicKey/SecretKey to/from_bytes with frozen sizes 1216/2432, PROTOCOL_VERSION 0x01, MIN_CIPHERTEXT_BYTES 1154 |
| D10 | Frozen constants: suites 0xA3/0xB1, HEADER_BYTES 6, KEM_CIPHERTEXT_BYTES 1120, NONCE 12, TAG 16 |
| D11 | Opaque unit-type SealError/OpenError (frozen error semantics — uniform failures) |

## E. Keystore (citadel-keystore)

| # | Capability |
|---|---|
| E1 | 4-level hierarchy Root→Domain→KEK→DEK with parentage enforcement (P211/P213 rules; DEK-under-KEK only, etc.) |
| E2 | CITADEL_ALLOW_FLAT_DEKS override gated on CITADEL_ENV=development (P214) |
| E3 | Key lifecycle states + StateEnforcer (citadel-core) two-layer enforcement |
| E4 | Rotation with old-version retention for decrypt |
| E5 | Revoke (reason-required) and destroy (irreversible) semantics |
| E6 | Replay stores: Memory (evicting), File (single-process, fail-closed on corrupt/truncated/missing), Redis (multi-instance) |
| E7 | Adaptive threat engine: 5 levels (LOW→CRITICAL), event scoring with decay, policy compression (rotation age, grace, usage limits), forced auto-rotate — policy-tightening only, no immediate rotation execution |
| E8 | Encrypted metadata backup (.ctdlbak): roundtrip, wrong-key fail, corrupt fail, empty fail |
| E9 | Audit chain: lifecycle events recorded, hash chain consistent, tamper detectable |

## F. Signer (citadel-signer)

F1 ML-DSA-65 sign/verify · F2 CitadelAssertion (CNA) issue/verify format.

## G. Dashboard (served UI — citadel-api/src/dashboard.html)

G1 API-key sign-in gate + demo "continue without auth" mode · G2 threat strip (DEFCON) · G3 Inject Threat Events panel (calls A20) + Reset (A21) · G4 Adaptive Policy Engine live table · G5 key inventory + create DEK · G6 API Key Management incl. domain-scoped key creation (non-admin requires domains) · G7 event feed · G8 error surfacing of failed ops (opError + api() !res.ok) · G9 single-file, no CDN dependencies.

## H. Ops / deployment

H1 Docker dev compose (dev key, demo seed, 127.0.0.1) · H2 production compose path(s) with TLS/hashed key/Redis (consolidation candidate — see DECISION_QUESTIONS; capability = "a documented production compose exists") · H3 Dockerfile + Dockerfile.fips build targets · H4 systemd/kubernetes/redis deploy templates (deploy/) · H5 canonical judge scripts/test-citadel-ubuntu.sh (2-run reproducibility + JSON receipts) · H6 scripts/run-tests.sh local runner · H7 scripts/security/* CI server tests (persistence, concurrency, log canary) + openapi.yaml (Schemathesis) · H8 gauntlet tiers 1–12 + receipts · H9 fuzz workspace (4 targets) + ClusterFuzzLite CI (PR + daily batch + corpus repo) · H10 supply-chain: cargo-vet (supply-chain/), deny.toml with two scoped documented exceptions, SUPPLY_CHAIN.md · H11 env.example documenting configuration surface · H12 citadel_example.py documented end-to-end example.

## I. Docs-as-promises

I1 API_FREEZE.md Tier 1/2 stability contract incl. breaking-change policy (RFC + 90-day + major bump + 12-month window) · I2 "wire v1 decodable forever" · I3 SECURITY.md private disclosure channel · I4 VALIDATION_MATRIX per-claim evidence (incl. 4 honest PENDING rows — preserving the PENDING-ness is itself part of the honesty) · I5 README "What we do not claim" section (no third-party audit, no FIPS-validated-product claim) · I6 dual license AGPL-3.0-or-later + commercial, with AGPL §7 AWS-LC exception (LICENSE-EXCEPTION) · I7 CHANGELOG discipline (Keep-a-Changelog-ish).

---

**Ledger walk protocol** (per phase branch): for A1–A27 curl or cite the unchanged route registration; A28–A35 cite tests or unchanged code; B/C/D/E/F cite unchanged files or passing suites (workspace tests + KAT gates + judge); G walk the dashboard file diff; H confirm scripts/configs still exist and referenced paths resolve; I confirm no promise-document weakened. Every REMOVED or CHANGED row must carry a DECISION_QUESTIONS ruling id.
