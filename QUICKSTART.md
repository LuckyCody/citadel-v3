# Citadel Quick Start

## ⚡ Golden Path — One-Command Proof (start here)

This is the canonical verification path. It proves the system is correctly deployed
and working end-to-end. No interpretation required.

```bash
# 1. Start API in development mode (no secrets needed for local testing)
./scripts/smoke-test.sh --dev
```

Expected output:
```
ALL TESTS PASSED — 7/7
Proof: artifacts/citadel_smoke_proof_<timestamp>.json
```

The smoke test proves: **health → auth rejection → encrypt → decrypt → replay blocked.**
The JSON proof artifact is written to `artifacts/` for external review.

For production verification (requires a running API):
```bash
export CITADEL_MASTER_KEY=$(openssl rand -hex 32)
# ... generate CITADEL_API_KEY_HASH (see Production Mode below) ...
docker compose -f deploy/docker/docker-compose.yml up -d
./scripts/smoke-test.sh --prod --key <your-api-key>
```

---

Two deployment tracks: **Development** (no key wrapping, for local testing) and **Production**
(full security gates). Follow only the track that matches your use case.

---

## Development Mode (local testing only)

Development mode skips at-rest key wrapping and uses in-memory replay protection.
**Never use this in production or staging.**

### Option A — Cargo (fastest)

```bash
CITADEL_ENV=development \
CITADEL_ALLOW_PLAINTEXT_KEYS=1 \
CITADEL_SEED_DEMO=true \
cargo run -p citadel-api
```

### Option B — Docker (dev compose)

```bash
# Start with the dev compose (no master key required)
docker compose up -d   # uses root docker-compose.yml which sets dev mode

# Or inline:
docker run -p 8443:8443 \
  -e CITADEL_ENV=development \
  -e CITADEL_ALLOW_PLAINTEXT_KEYS=1 \
  -e CITADEL_SEED_DEMO=true \
  citadel:v3
```

### Verify it started

```bash
curl http://localhost:8443/health
# → {"status":"ok"}
```

---

## Production Mode (single-node, file replay)

### 1. Generate required secrets

```bash
# 256-bit master key for at-rest encryption
export CITADEL_MASTER_KEY=$(openssl rand -hex 32)

# API key hash (keep the plaintext for clients, set the hash in config)
CITADEL_MASTER_KEY=$CITADEL_MASTER_KEY cargo run --bin hash-apikey -- --generate
# → API key:  a1b2c3...  (give this to clients)
# → Hash:     9f86d0...  (set as CITADEL_API_KEY_HASH)
export CITADEL_API_KEY_HASH=<hash from above>
```

### 2. Run

```bash
CITADEL_ENV=production \
CITADEL_MASTER_KEY=$CITADEL_MASTER_KEY \
CITADEL_API_KEY_HASH=$CITADEL_API_KEY_HASH \
CITADEL_REPLAY_STORE=file \
CITADEL_REPLAY_STORE_PATH=./citadel-data/replay.json \
CITADEL_SEED_DEMO=false \
./target/release/citadel-api
```

### 3. Docker (production compose)

```bash
# Step 1: Generate master key
export CITADEL_MASTER_KEY=$(openssl rand -hex 32)

# Step 2: Generate API key + hash
CITADEL_MASTER_KEY=$CITADEL_MASTER_KEY cargo run --bin hash-apikey -- --generate
# Copy the hash output, then:
export CITADEL_API_KEY_HASH=<hash from above>

# Step 3: Start production stack (includes Redis)
docker compose -f deploy/docker/docker-compose.yml up -d

# Step 4: Verify and run doctor
curl http://localhost:8443/health
docker compose -f deploy/docker/docker-compose.yml exec citadel citadel doctor
# NOTE: doctor validates the container's environment configuration (env vars, key
# storage structure). It does not query the live API runtime. To verify the API
# is responding, use: curl http://localhost:8443/health
```

> **API key:** Give the plaintext key to clients. The hash is what the server stores.
> Never commit either to version control.

---

## Multi-Node (Redis replay)

```bash
# Requires binary built with: --features redis-backend
# Or the provided Docker image (built with this flag by default)

CITADEL_ENV=production \
CITADEL_MASTER_KEY=$CITADEL_MASTER_KEY \
CITADEL_API_KEY_HASH=$CITADEL_API_KEY_HASH \
CITADEL_REPLAY_STORE=redis \
CITADEL_REDIS_URL=redis://localhost:6379 \
CITADEL_SEED_DEMO=false \
./target/release/citadel-api
```

---

## Using the API

```bash
# Encrypt (with API key)
curl -X POST http://localhost:8443/api/keys/{KEY_ID}/encrypt \
  -H "Authorization: Bearer <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world","aad":"my-app","context":"prod"}'

# Decrypt
curl -X POST http://localhost:8443/api/decrypt \
  -H "Authorization: Bearer <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"blob":{...},"aad":"my-app","context":"prod"}'
```
