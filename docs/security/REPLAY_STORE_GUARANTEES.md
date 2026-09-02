# Citadel V3 — Replay Store Guarantees

> **Operational per-backend guarantees.** For durability boundaries and crash windows, [REPLAY_TRUST_BOUNDARIES.md](REPLAY_TRUST_BOUNDARIES.md) is canonical. Where the two disagree, RTB governs.

> **Update:** ReplayStore now uses an atomic `claim()`/`release()` model, replacing the earlier non-atomic check-then-record two-step. `claim()` is check-and-insert under a single lock — no race window. `release()` frees the slot only on decrypt failure (anti-poisoning). Successful decrypt keeps the claim permanently until TTL.

## What the Replay Store Does

The replay store prevents ciphertext reuse attacks. Every decryption records a
nonce fingerprint. If the same blob is submitted again, the store returns
`claim()` returns `Ok(false)` and decryption is rejected before any key material is accessed.

---

## FileReplayStore — Guarantees and Limitations

### Guarantees

- Nonces claimed in process memory are persisted to `replay.json` on disk
- After a clean restart, previously claimed nonces are recognized and rejected
- Fail-closed: if the store cannot be read at startup, the server exits (exit 1)
- Fail-closed: if a write fails, the error is returned to the caller (not silently dropped)
- 10,000+ entries remain consistent (proven by `file_store_large_entry_count_remains_consistent`)

### Limitations

**SINGLE-PROCESS ONLY**

FileReplayStore does not use cross-process file locking. Two API instances
sharing the same `replay.json` file may both see `claim()=true` for the same
nonce and both successfully decrypt the same ciphertext.

This means:
- FileReplayStore is safe for single-instance deployments
- FileReplayStore is NOT safe for multi-instance or load-balanced deployments
- Redis replay backend (`CITADEL_REPLAY_STORE=redis`) is required for multi-instance

**APPEND-ONLY (NO EVICTION)**

FileReplayStore does not evict expired entries from disk. The `replay.json` file
grows continuously with traffic. For long-running deployments:
- Monitor `replay.json` file size
- Use Redis backend for bounded storage (TTL-based eviction)
- Or schedule periodic maintenance to prune expired entries

---

## Corruption Semantics

| Scenario | Behavior |
|----------|----------|
| Truncated `replay.json` | **Fail-closed** — `FileReplayStore::new()` returns an error; the store never starts fresh (test: `file_store_truncated_json_returns_err`) |
| Invalid JSON `replay.json` | **Fail-closed** — `FileReplayStore::new()` returns an error; the store never starts fresh (test: `file_store_invalid_json_returns_err`) |
| Missing `replay.json` at startup | **Fails startup (exit 1)** — fail-closed |
| Permission denied reading | Fail-closed expected |
| Permission denied writing | Returns error — operation rejected |

The server does NOT silently recreate an empty replay store after corruption
unless the operator explicitly deletes the file and restarts.

---

## MemoryReplayStore

Development-mode default (also used in tests). Not persistent across restarts. Entries are evicted when TTL expires.

---

## RedisReplayStore

Required for production multi-instance deployment.
- Set `CITADEL_REPLAY_STORE=redis`
- Set `CITADEL_REDIS_URL=redis://...`
- Redis TTL provides automatic eviction
- Cross-process atomicity via `SET NX EX` (atomic compare-and-set)

---

## Promotion Gates

### Alpha Freeze Gate: PASSED
- Single-instance replay protection: ✅ proven
- Restart durability: ✅ proven
- Fail-closed on missing store: ✅ proven

### Hardened Alpha Gate: PENDING
- Multi-process replay behavior: documented (not safe without Redis)
- Corruption semantics: ✅ tested
- Replay-spam concurrency: ✅ proven (100 concurrent)

### Beta Gate: PENDING
- Redis multi-instance validation required
- Production load testing required

---

*Last updated: 2026-05-02 | citadel-v3-beta-001*
