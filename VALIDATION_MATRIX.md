# Citadel V3 — Validation Matrix

**Tag:** citadel-v3-beta-001  
**Current status:** Beta-stage (see [SECURITY_MATURITY.md](SECURITY_MATURITY.md)). Alpha Freeze
and Hardened Alpha gates below are both superseded by validation work completed since —
machine-checked combiner proofs for both suites, an independent adversarial falsification
audit, ACVP vectors now passing, and the CMVP-validated FIPS backend pin. No independent
third-party audit has been performed; see [SECURITY.md](SECURITY.md#what-we-do-not-claim).  
**Baseline validation run (below):** 20260501_200031 — the tables that follow are that run's
record and have not all been individually re-dated since. Where a specific claim has since
changed, it is corrected inline.

---

## Core Cryptographic Guarantees

| Guarantee | Test Name | Crate | Status | Last Run | Limitation |
|-----------|-----------|-------|--------|----------|------------|
| X25519 + ML-KEM-768 hybrid KEM | `primitive_kat_*` | citadel-envelope | ✅ PASS | 20260501 | Self-consistency only, not ACVP vectors |
| AES-256-GCM authenticated encryption | `p006_*`, `p007_*` | citadel-envelope | ✅ PASS | 20260501 | — |
| HKDF-SHA256 key derivation | `hkdf_kat_*` | citadel-envelope | ✅ PASS | 20260501 | — |
| Wrong-key isolation (IND-CCA2 property) | `p012_wrong_key_*` | citadel-envelope | ✅ PASS | 20260501 | — |
| ML-KEM ACVP/NIST official vectors | `nist_acvp_kat`, `acvp_mlkem1024`, `production_mlkem_acvp` | citadel-envelope | ✅ PASS (60/60) | current | Superseded — see [SECURITY.md](SECURITY.md#cryptographic-provider-assurance) |

**Suite `0xA4` (P-384 + ML-KEM-1024):** added after this baseline run; not itemized row-by-row
below. Its evidence lives in `citadel-envelope/tests/wycheproof_p384_ecdh.rs`,
`proptest_a4.rs`, `v2_vector_a4.rs`, `awslc_ecdh_p384_differential.rs`, and the machine-checked
combiner proofs in `gauntlet/tier12_combiner_proof/` (CTD2 P-384 and ML-KEM-1024 arms, both
VERIFIED). See [SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md) for the full primitive table.

---

## Key Hierarchy Enforcement

| Guarantee | Test Name | Crate | Status | Last Run | Limitation |
|-----------|-----------|-------|--------|----------|------------|
| DEK requires KEK parent (not Root, not Domain) | `p211_dek_under_domain_directly_is_rejected`, `p184_dek_under_root_is_rejected` | citadel-keystore | ✅ PASS | 20260502 | — |
| DEK with no parent rejected | `p063_flat_dek_requires_parent_unless_override` | citadel-keystore | ✅ PASS | 20260501 | — |
| KEK requires Domain parent (not Root) | `p211_kek_under_root_is_rejected` | citadel-keystore | ✅ PASS | 20260502 | P211 fix |
| Domain requires Root parent | `p211_domain_under_kek_is_rejected` | citadel-keystore | ✅ PASS | 20260502 | P211 fix |
| Root must have no parent | `p211_root_with_parent_is_rejected` | citadel-keystore | ✅ PASS | 20260502 | P211 fix |
| Full Root→Domain→KEK→DEK chain accepted | `p211_correct_full_hierarchy_is_accepted` | citadel-keystore | ✅ PASS | 20260502 | P211 fix |
| Root→Domain→KEK→DEK hierarchy via API | `it_encrypt_decrypt_roundtrip`, `it_concurrent_encrypt_decrypt_is_safe`, `it_replay_spam_concurrency_is_safe` | citadel-api | ✅ UPDATED | 20260502 | P213 fix — was stale Root→KEK→DEK |
| KEK under Root rejected via API | validation script step (Must-Fail) | citadel-api | ✅ UPDATED | 20260502 | P213 fix — added rejection step |
| CITADEL_ALLOW_FLAT_DEKS requires CITADEL_ENV=development | enforced in keystore.rs generate() | citadel-keystore | ✅ IMPLEMENTED | 20260502 | P214 fix |
| CITADEL_ALLOW_FLAT_DEKS override works in dev mode | `p063_flat_dek_override_flag_allows_parentless` | citadel-keystore | ✅ PASS | 20260502 | Test-only flag + CITADEL_ENV=development |

---

## Replay Protection

| Guarantee | Test Name | Script | Status | Last Run | Limitation |
|-----------|-----------|--------|--------|----------|------------|
| Replay rejected before restart | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 | — |
| Replay rejected after restart | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 | — |
| 100 concurrent replays of same blob | `it_replay_spam_concurrency_is_safe` | citadel-api | ✅ PASS | 20260502 | In-process only |
| FileReplayStore at 10,000 entries | `file_store_large_entry_count_remains_consistent` | citadel-keystore | ✅ PASS | 20260502 | ~98s runtime |
| Multi-process replay safety | `citadel_multiprocess_replay_harness.ps1` | — | ⏳ PENDING | — | FileReplayStore is single-process only |
| MemoryReplayStore eviction | `memory_store_expired_entries_evicted` | citadel-keystore | ✅ PASS | 20260501 | — |

---

## Replay Store Corruption Semantics

| Scenario | Test Name | Status | Expected Behavior |
|----------|-----------|--------|-------------------|
| Truncated replay.json | `file_store_truncated_json_fails_closed` | ✅ PASS | Safe recovery or fail-closed |
| Invalid JSON replay.json | `file_store_invalid_json_fails_safely` | ✅ PASS | Safe recovery or fail-closed |
| Missing replay store at startup | validation script step | ✅ PASS | SAFE_FAILED_STARTUP (exit 1) |
| Permission denied read | — | ⏳ PENDING | Fail-closed expected |

---

## Concurrency

| Guarantee | Test Name | Status | Last Run | Limitation |
|-----------|-----------|--------|----------|------------|
| 50 concurrent encrypts to same DEK | `it_concurrent_encrypt_decrypt_is_safe` step 1 | ✅ PASS | 20260502 | In-process tokio tasks |
| Rotation under encrypt load | `it_concurrent_encrypt_decrypt_is_safe` step 2 | ✅ PASS | 20260502 | 20 tasks only |
| Inactive-key race returns clean 4xx | `it_concurrent_encrypt_decrypt_is_safe` step 3 | ✅ PASS | 20260502 | — |
| Multi-process concurrency | `citadel_multiprocess_replay_harness.ps1` | ⏳ PENDING | — | Not yet confirmed safe |

---

## API Security

| Guarantee | Test Name | Script | Status | Last Run |
|-----------|-----------|--------|--------|----------|
| No auth returns 401 | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 |
| Wrong key returns 401 | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 |
| Malformed JSON rejected | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 |
| Nonexistent key rejected | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 |
| Corrupted ciphertext rejected | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 |
| Wrong AAD rejected | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 |
| Wrong context rejected | validation script step | citadel_full_validation.ps1 | ✅ PASS | 20260501_200031 |
| Opaque error responses | `it_corrupted_blob_returns_error` | citadel-api | ✅ PASS | 20260501 |
| Error includes request_id | — | — | ✅ IMPLEMENTED | 20260502 |
| Rate limiting activates | `it_rate_limit_activates_under_spam` | citadel-api | ✅ PASS | 20260501 |
| Wrong-key spam rate limited | `it_wrong_key_spam_is_rate_limited` | citadel-api | ✅ PASS | 20260501 |
| 100x adversarial abuse storm | `citadel_abuse_harness.ps1` | — | ⏳ PENDING | — |

---

## API Key Lifecycle

| Guarantee | Test Name | Status |
|-----------|-----------|--------|
| Second API key creation | `it_api_key_lifecycle_is_correct` | ✅ PASS |
| Key revocation | `it_api_key_lifecycle_is_correct` | ✅ PASS |
| Revoked key returns 401 | `it_api_key_lifecycle_is_correct` | ✅ PASS |
| Cannot revoke last admin key | `it_api_key_lifecycle_is_correct` | ✅ PASS |
| Scoped key creation | `it_api_key_lifecycle_is_correct` | ✅ PASS |
| Scope enforcement per route | `it_scope_enforcement_blocks_insufficient_permissions` | ✅ IMPLEMENTED | 20260502 |

---

## Fail-Closed Production Gates

| Gate | Test | Status | Last Run |
|------|------|--------|----------|
| Missing replay store blocks startup | validation script step | ✅ PASS | 20260501_200031 |
| Corrupt api-keys.json blocks startup | validation script step | ✅ PASS | 20260501_200031 |
| Missing CITADEL_MASTER_KEY blocks startup | `it_health_no_auth_required` (dev mode only) | ✅ PASS | 20260501 |

---

## Audit Chain

| Guarantee | Test Name | Status |
|-----------|-----------|--------|
| Lifecycle events recorded | `audit_chain_records_lifecycle_events` | ✅ PASS |
| Hash chain is consistent | `audit_chain_records_lifecycle_events` | ✅ PASS |
| Tampering breaks chain (detectable) | `audit_chain_tamper_is_detectable` | ✅ PASS |

---

## Backup / Restore

| Guarantee | Test Name | Status |
|-----------|-----------|--------|
| Backup roundtrip with correct key | `backup_roundtrip_succeeds_with_correct_key` | ✅ PASS |
| Wrong master key fails restore | `restore_with_wrong_master_key_fails` | ✅ PASS |
| Corrupted backup fails cleanly | `restore_corrupted_backup_fails_cleanly` | ✅ PASS |
| Empty backup fails cleanly | `restore_empty_backup_fails_cleanly` | ✅ PASS |

---

## Stress / Load

| Test | Duration | Status | Last Run |
|------|----------|--------|----------|
| Volume 10k roundtrips (stress) | ~30s | ✅ PASS | 20260501_200031 |
| Large plaintext stress | ~10s | ✅ PASS | 20260501_200031 |
| Long-run load (10 min) | 600s | ⏳ PENDING | — |

---

## Promotion Gates

| Gate | Status |
|------|--------|
| **Alpha Freeze** | ✅ PASSED (20260501_200031) |
| **Hardened Alpha** | ✅ SUPERSEDED — combiner proofs, ACVP, and the CMVP-validated FIPS pin all postdate this baseline |
| **Beta** | ✅ REACHED — adversarial suite independently re-run end to end (see [README.md](README.md#how-we-validated-and-audited-it)); no independent third-party audit |

---

## Known Limitations

- FileReplayStore is single-process only. Redis required for multi-instance.
- ML-KEM-768 uses the `ml-kem` crate (currently pinned at v0.3.2), which carries an
  "experimental" designation in its own documentation. ACVP vectors pass (see above).
- API key comparison uses `subtle::ConstantTimeEq` (see `citadel-api/src/main.rs`) — the
  HMAC-hash-equality note above is superseded.
- No independent security audit has been performed.
- Backup/restore does not enforce key state preservation (active/revoked) post-restore.
- **Minimum Rust version varies by crate** — see the `rust-version` field in each crate's
  `Cargo.toml` for its exact requirement; ml-kem's transitive dependencies require a
  toolchain new enough to parse the 2024 edition.

---

*Baseline generated: 2026-05-02 | Superseding notes added: 2026-08-06 | citadel-v3-beta-001*
