# Citadel Production Deployment Guide

## Linux local-pilot custody profile

This hardened single-host profile removes the root wrapping
key from environment variables. It is the supported zero-budget pilot
path; it does **not** claim HSM, TPM, non-exportability, FIPS validation, or
independent review.

The provider accepts exactly one 32-byte raw file. It opens with `O_NOFOLLOW`,
requires a regular file owned by the effective service user with owner-read
permission and no group/world permissions (`0400` or `0600`), requires one hard link,
checks the parent directory, and fails closed on length, ownership, permissions,
or symlink errors. Keep the provider file on the Ubuntu filesystem (for example
`/var/lib/citadel`), not on `/mnt/c`.

```bash
cd /path/to/citadel_v3
bash scripts/linux_root_custody_preflight.sh

install -d -m 0700 "$HOME/.local/share/citadel-custody"
cargo run -p citadel-keystore --bin citadel-root-key -- \
  init "$HOME/.local/share/citadel-custody/root.key"
cargo run -p citadel-keystore --bin citadel-root-key -- \
  check "$HOME/.local/share/citadel-custody/root.key"

export CITADEL_PROFILE=local-pilot
export CITADEL_ROOT_KEY_FILE="$HOME/.local/share/citadel-custody/root.key"
export CITADEL_ENV=pilot
export CITADEL_REPLAY_STORE=file

cargo run -p citadel-api --bin hash-apikey -- --generate
export CITADEL_API_KEY_HASH=<HASH value from the command>
cargo run -p citadel-api
```

Local-pilot startup rejects `CITADEL_MASTER_KEY`, `CITADEL_API_KEY`,
`CITADEL_ALLOW_PLAINTEXT_KEYS`, `CITADEL_ALLOW_FLAT_DEKS`, and
`CITADEL_ENV=development`. The replay store must be `file` or `redis`.

### Recovery and rotation boundary

- Back up the **root provider file separately**, offline, with owner-only access.
  Metadata backups intentionally do not contain it.
- A metadata backup can be verified/restored only with the same provider key;
  tests prove a different provider fails authentication.
- Logical Citadel root keys can rotate normally while remaining wrapped by this
  provider. Replacing the provider file itself is **not an online rotation**:
  existing `enc:` material and backups become unreadable. Provider-key rewrap is
  not implemented in this packet, so retain the old provider and never replace
  it in place.
- The key is exportable and enters zeroizing process memory. A host/root process
compromise can obtain it. Use an external KMS/HSM provider for a higher-assurance
  deployment when budget and integration authority are available.
- Linux `O_NOFOLLOW` protects the final path component; the configured parent
  path must therefore also be administrator-controlled. The provider checks its
  immediate parent, but does not claim kernel-enforced resolution beneath a
  pre-opened directory descriptor.

---

## What Changed (Tier 1 Security Hardening)

Three security gaps closed in this release:

| Gap | Before | After |
|-----|--------|-------|
| **TLS** | Plaintext HTTP, API key and encrypted data in cleartext on the wire | Caddy reverse proxy with automatic Let's Encrypt TLS |
| **Rate limiting** | None — any client could brute-force or DoS the server | Per-IP sliding window token bucket (20 rps default, 50 burst) |
| **API key storage** | Plaintext string comparison in memory | HMAC-SHA256(api_key, CITADEL_MASTER_KEY) with constant-time comparison via `subtle` |

### Why HMAC-SHA256 instead of Argon2?

API keys are high-entropy random strings (not passwords). Password hashing algorithms like Argon2/bcrypt are designed to slow down brute-force attacks on **low-entropy** inputs. For a 256-bit random API key, HMAC-SHA256 with a server-side secret (`CITADEL_MASTER_KEY`) is the correct choice — it is what Stripe, GitHub, and AWS use. The server-side key means the hash cannot be cracked offline even if the hash store is leaked. Constant-time comparison via `subtle::ConstantTimeEq` prevents timing side-channels.

**Important:** The hash is HMAC-SHA256, not bare SHA-256. You must use the `hash-apikey` binary (which reads `CITADEL_MASTER_KEY`) — not `sha256sum` or any other tool.

---

## Quick Start (Local Dev)

**Development mode requires both variables set explicitly.** The API startup rejects
unset `CITADEL_ENV` with a fatal error — this prevents accidental memory-replay deployments.

```bash
# Development: no master key required, memory replay permitted
CITADEL_ENV=development \
CITADEL_ALLOW_PLAINTEXT_KEYS=1 \
CITADEL_SEED_DEMO=true \
cargo run -p citadel-api
```

The plaintext API key (`CITADEL_API_KEY=dev-secret`) is still supported in development
for convenience. In production, always use `CITADEL_API_KEY_HASH` (see Production section).

---

## Production Deployment

### Required variables

Your service will not start without all four of these:

| Variable | Required | How to set |
|----------|----------|------------|
| `CITADEL_MASTER_KEY` | **YES** | `export CITADEL_MASTER_KEY=$(openssl rand -hex 32)` |
| `CITADEL_API_KEY_HASH` | **YES** | Generate with `hash-apikey` binary (step 1 below) |
| `CITADEL_REPLAY_STORE` | **YES** (non-dev) | `file` (single node) or `redis` (multi-node) |
| `CITADEL_ENV` | **YES** | `production` — or `development` with `CITADEL_ALLOW_PLAINTEXT_KEYS=1` |

> **Order matters:** generate `CITADEL_MASTER_KEY` first. All other steps depend on it.

---

### 1. Generate a Master Key and API Key

```bash
# Step 1a — Generate master key (REQUIRED first — hash-apikey needs it)
export CITADEL_MASTER_KEY=$(openssl rand -hex 32)

# Step 1b — Generate a random API key and its HMAC-SHA256 hash in one step:
CITADEL_MASTER_KEY=$CITADEL_MASTER_KEY cargo run --bin hash-apikey -- --generate

# Output:
#   Generated API key (save this — it cannot be recovered):
#     a1b2c3d4e5f6...  (64 hex chars)
#   HMAC-SHA256 hash (set as CITADEL_API_KEY_HASH):
#     9f86d08...        (64 hex chars)

export CITADEL_API_KEY_HASH=<hash from above>
```

Or hash an existing key (must use `hash-apikey` — not sha256sum):

```bash
CITADEL_MASTER_KEY=$CITADEL_MASTER_KEY cargo run --bin hash-apikey -- "your-existing-api-key"
```

Save the plaintext key for clients. Set the **hash** as `CITADEL_API_KEY_HASH`.

### 2. Configure TLS with Caddy

Edit `Caddyfile` for your environment:

**Option A — Real domain with Let's Encrypt (recommended):**
```
citadel.yourdomain.com {
    reverse_proxy citadel:8443
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        -Server
    }
}
```

**Option B — Self-signed cert for internal/staging:**
```
:443 {
    tls internal
    reverse_proxy citadel:8443
    # ... same headers ...
}
```

### 3. Launch

```bash
# Required — generate master key if not already done:
export CITADEL_MASTER_KEY=$(openssl rand -hex 32)

# Set from step 1:
export CITADEL_API_KEY_HASH="9f86d081884c..."

# Optional:
export CITADEL_DOMAIN="citadel.yourdomain.com"
export CITADEL_LOG_FORMAT=json

# The production compose (deploy/docker/docker-compose.yml) includes:
#   CITADEL_ENV: production
#   CITADEL_REPLAY_STORE: redis
#   CITADEL_MASTER_KEY: ${CITADEL_MASTER_KEY:?required}
# Pass CITADEL_MASTER_KEY via environment or Docker Secrets.
docker compose -f deploy/docker/docker-compose.yml up -d
```

> **Redis replay:** The provided image is built with `--features redis-backend`.

### Replay Protection & Restart Behavior

This is a critical operational concern — choose your replay backend knowing what happens on restart:

| Backend | `CITADEL_REPLAY_STORE` | Persists across restart? | Replay window on restart | Use for |
|---------|----------------------|--------------------------|--------------------------|---------|
| Memory | *(unset + dev mode)* | **No** | Up to TTL (24h default) | Development only |
| File | `file` | **Yes** | None | Single-node production |
| Redis | `redis` | **Yes** | None | Multi-node production |

> **Memory backend restart risk:** If the API restarts, all nonces seen before the restart are forgotten. An attacker who captured a ciphertext can replay it within the TTL window. This is acceptable in development. **Never use memory replay in production.**

> **File backend restart safety:** Nonces are claimed atomically and persisted to `CITADEL_DATA_DIR/replay.json`. File backend durability is **batched** — see [REPLAY_TRUST_BOUNDARIES.md](REPLAY_TRUST_BOUNDARIES.md) for the crash window; "survives restart" assumes a flushed claim. A restart reloads the file. TTL-expired entries are purged on load. Single-node only — not safe if multiple API instances share the same data directory.

> **Redis backend:** Nonces are stored in Redis with TTL. Restarts reconnect to the same Redis instance. Safe for multi-node deployments.
> The production compose configures Redis automatically.

Dashboard: `https://citadel.yourdomain.com`
API: `https://citadel.yourdomain.com/api/status`

### 4. Verify

**End-to-end smoke test (recommended):**
```bash
# One command proves: health → auth rejection → encrypt → decrypt → replay rejection
./scripts/smoke-test.sh --dev                              # development mode
./scripts/smoke-test.sh --prod --key <your-api-key>       # production mode
./scripts/smoke-test.sh --api https://citadel.example.com --key <key>  # remote
```

```bash
# Health check (no auth required)
curl -k https://localhost/health

# Run deployment health check (validates environment config)
# NOTE: doctor validates environment configuration only — not live API runtime.
# It reads env vars from the process environment, not the running service.
# Use the health endpoint above to verify the API is actually responding.
citadel doctor   # or: docker compose exec citadel citadel doctor

# Authenticated API call
curl -k https://localhost/api/status \
  -H "Authorization: Bearer your-plaintext-key"

# Rate limit test (should get 429 after burst)
for i in $(seq 1 60); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -k https://localhost/api/status \
    -H "Authorization: Bearer your-plaintext-key"
done
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CITADEL_PORT` | `8443` | Internal listen port |
| `CITADEL_DATA_DIR` | `./citadel-data` | Key material and audit log directory |
| `CITADEL_API_KEY_HASH` | — | HMAC-SHA256 hex hash of API key using CITADEL_MASTER_KEY (production) |
| `CITADEL_API_KEY` | — | Plaintext API key (dev only, hashed at startup) |
| `CITADEL_SEED_DEMO` | `false` | Seed demo keys on first run |
| `CITADEL_LOG_FORMAT` | `pretty` | `json` for structured logging, `pretty` for dev |
| `CITADEL_RATE_LIMIT_RPS` | `20` | Requests per second per IP |
| `CITADEL_RATE_LIMIT_BURST` | `50` | Burst capacity per IP |
| `CITADEL_DOMAIN` | — | Domain for Caddy TLS (production only) |

> **Data path per deployment type** (for `CITADEL_DATA_DIR`):
> - **Docker container:** `/data` (Dockerfile creates and chowns this path)
> - **Native binary / systemd:** `/var/lib/citadel/data` (set in citadel.service)
> - **Local dev (cargo):** `./citadel-data` (default, relative to working directory)
>
> These are different deployment targets — the difference is intentional, not a bug.

---

## Rate Limiting Behavior

The rate limiter uses a per-IP sliding window token bucket:

- Each IP starts with `BURST` tokens
- Tokens replenish at `RPS` per second
- When tokens are exhausted, requests get `429 Too Many Requests` with `Retry-After: 1`
- Rate limit violations are automatically recorded as `RapidAccessPattern` threat events
- Stale buckets are cleaned up every 60 seconds

The rate limiter runs in-memory (no Redis needed). For multi-instance deployments behind a load balancer, each instance maintains its own counters — effective per-IP rate is `RPS × instance_count`.

---

## Structured Logging

With `CITADEL_LOG_FORMAT=json`, output looks like:

```json
{"timestamp":"2026-02-12T10:30:00Z","level":"INFO","target":"citadel_api","message":"starting Citadel API Server v0.2.0","port":8443,"rate_rps":20.0,"rate_burst":50}
{"timestamp":"2026-02-12T10:30:01Z","level":"WARN","target":"citadel_api","message":"rate limit exceeded","ip":"192.168.1.50","path":"/api/keys"}
{"timestamp":"2026-02-12T10:30:01Z","level":"WARN","target":"citadel_api","message":"invalid API key","ip":"10.0.0.5","path":"/api/status"}
```

Feed this into ELK, Datadog, CloudWatch, or any JSON log aggregator.

---

## Architecture (Production)

```
Internet
    │
    ▼
┌──────────────┐
│   Caddy       │  :443 (TLS termination)
│   (reverse    │  :80  (→ redirect to HTTPS)
│    proxy)     │
└──────┬───────┘
       │ plaintext HTTP (internal Docker network only)
       ▼
┌──────────────┐
│  Citadel API  │  :8443 (not exposed to host)
│  ┌──────────┐ │
│  │ Rate     │ │  Per-IP token bucket
│  │ Limiter  │ │
│  ├──────────┤ │
│  │ Auth     │ │  HMAC-SHA256(key, MASTER_KEY) + constant-time compare
│  │ (hashed) │ │
│  ├──────────┤ │
│  │ Keystore │ │  Hybrid PQ encryption engine
│  └──────────┘ │
└──────────────┘
       │
       ▼
  citadel-data/    (volume: keys + audit log)
```

---

## Migration from Pre-Hardening

If you have an existing deployment with `CITADEL_API_KEY`:

1. Your existing setup **still works** — `CITADEL_API_KEY` is supported but deprecated
2. Generate the hash: `CITADEL_MASTER_KEY=<key> cargo run --bin hash-apikey -- "your-current-key"`
3. Set `CITADEL_API_KEY_HASH` to the output
4. Remove `CITADEL_API_KEY` from your environment
5. Switch to `deploy/docker/docker-compose.yml` when ready for production

No key material migration is needed — the data directory is unchanged.

---

## What's Next (Tier 2)

> **Historical.** Scoped multi-key auth shipped in 0.2.0 and is enforced per route (`required_scope`); see README §API Key Scopes. Retained for the untested-rotation caveats only.

After Tier 1 is deployed, the next priorities are:

1. **Multiple API keys with scopes** — per-client keys with permissions (read-only, encrypt-only, admin)
2. **Backup/recovery procedures** — documented key material backup with encryption-at-rest
3. **Key export/import** — portable key bundles for server migration
---

## API Key Management (Operational Limitations)

> **Historical.** Scoped multi-key auth shipped in 0.2.0 and is enforced per route (`required_scope`); see README §API Key Scopes. Retained for the untested-rotation caveats only.

### Current state
Citadel V3 supports a single bootstrap admin key per deployment.
The key is configured via CITADEL_API_KEY_HASH and stored in api-keys.json.

### What is not yet proven
- **Key rotation:** No tested rotation strategy for API keys
- **Multi-tenant isolation:** Scoped permissions exist in the data model but
  are not enforced at the route level (admin scope covers all routes)
- **Second key creation:** api-keys.json supports multiple keys but the
  validation harness only tests with a single key

### Recommended pre-production steps
1. Implement and test API key rotation (generate new key, update hash, verify old key rejected)
2. Define scope enforcement rules per route
3. Test multi-key scenarios before production deployment

### Timing-sensitive host profile

Citadel's fixed-server-key remote timing classes pass the current statistical
screen, but local/co-resident key-value timing independence is not established.
Deployments whose threat model includes a hostile local tenant should use a
dedicated host, prevent untrusted co-resident execution, and disable CPU
frequency boost using the host's supported controls. The WSL validation host
does not prove those production host controls. Do not claim physical
side-channel resistance or universally constant execution.

### FileReplayStore growth
FileReplayStore is append-only. It does not evict expired entries from disk.
For long-running deployments:
- Monitor replay.json file size
- Use CITADEL_REPLAY_STORE=redis for production (bounded by Redis TTL)
- Or schedule periodic maintenance to prune expired entries
