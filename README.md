# Citadel

Post-quantum hybrid encryption and key management server.

Citadel combines X25519 + ML-KEM-768 for key encapsulation and AES-256-GCM for data encryption, following NIST's hybrid approach for the post-quantum transition. Applications encrypt and decrypt data through a REST API. Citadel manages the keys — generation, rotation, revocation, access control, and audit logging.

**Status:** Working beta-stage implementation. Unaudited. No production deployments. The controlling claim record is [`../../CLAIM_EVIDENCE_MATRIX.md`](../../CLAIM_EVIDENCE_MATRIX.md); see [Security](#security) below.

---

## What It Does

```
Your Application              Citadel                         Database
       |                         |                               |
       |-- POST /encrypt ------->|                               |
       |                         |-- hybrid KEM (X25519+ML-KEM)  |
       |                         |-- derive AES-256 key (HKDF)   |
       |                         |-- encrypt with AES-256-GCM    |
       |<-- encrypted blob ------|                               |
       |                                                         |
       |-- store blob ------------------------------------------>|
```

Your application never touches raw key material. The encrypted blob is self-contained — it includes the wrapped key, algorithm identifiers, and ciphertext. Store it in any database. Decrypt by sending it back to Citadel with the same AAD and context.

## Architecture

```
citadel-envelope    Hybrid encryption core (X25519 + ML-KEM-768 + AES-256-GCM)
citadel-keystore    Key lifecycle management, 4-level hierarchy, threat-adaptive policies
citadel-api         HTTP server, scoped API key auth, rate limiting, real-time dashboard
```

## Quick Start

### Docker (recommended)

```bash
# Clone
git clone https://github.com/mrcord77/rust_citadel.git
cd rust_citadel

# Set your admin API key
echo -n "your-secret-key" | sha256sum | cut -d' ' -f1
# Copy the hash

# Start
CITADEL_API_KEY_HASH=<paste-hash> docker compose up -d

# Verify
curl http://localhost:3000/health
# {"status":"ok","version":"0.2.0"}
```

Dashboard: http://localhost:3000

### From Source

Requires Rust 1.81+.

> **Note:** The `ml-kem` dependency chain transitively requires `cargo` 1.81+ to parse
> correctly. Ubuntu 24.04 LTS ships cargo 1.75 via `apt` — use `rustup` to install 1.81+.
> `rustup toolchain install stable` on any up-to-date machine will work.

```bash
cargo build --release -p citadel-api
CITADEL_API_KEY="your-secret-key" CITADEL_SEED_DEMO=true ./target/release/citadel-api
```

The default build/test graph excludes the comparison-only AWS-LC provider. Compile the
standalone provider comparison explicitly with:

```bash
cargo check -p citadel-envelope --benches --features aws-lc-comparison --locked
```

Run the canonical Ubuntu judge (two unchanged-source runs plus JSON receipts) with:

```bash
bash scripts/test-citadel-ubuntu.sh
```

## Usage

### Python

```python
import requests

api = "http://localhost:3000"
headers = {"Authorization": "Bearer your-secret-key"}

# Encrypt
r = requests.post(f"{api}/api/keys/{dek_id}/encrypt", headers=headers, json={
    "plaintext": "sensitive data",
    "aad": "record-001",        # binds ciphertext to this record
    "context": "patient-records" # application-defined context (structural only)
})
blob = r.json()

# Decrypt
r = requests.post(f"{api}/api/decrypt", headers=headers, json={
    "blob": blob,
    "aad": "record-001",
    "context": "patient-records"
})
plaintext = r.json()["plaintext"]
```

See [citadel_example.py](citadel_example.py) for a complete working example with AAD binding, key rotation, and threat-aware application behavior.

### curl

```bash
# Status
curl http://localhost:3000/api/status -H "Authorization: Bearer $KEY"

# List keys
curl http://localhost:3000/api/keys -H "Authorization: Bearer $KEY"

# Encrypt
curl -X POST http://localhost:3000/api/keys/$DEK_ID/encrypt \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello","aad":"test","context":"demo"}'
```

## API Endpoints

| Endpoint | Method | Scope | Description |
|----------|--------|-------|-------------|
| `/health` | GET | — | Health check |
| `/api/status` | GET | read | Threat level, key counts |
| `/api/metrics` | GET | read | Security metrics |
| `/api/keys` | GET | read | List all keys |
| `/api/keys` | POST | manage | Generate new key |
| `/api/keys/:id` | GET | read | Get key details |
| `/api/keys/:id/activate` | POST | manage | Activate a pending key |
| `/api/keys/:id/rotate` | POST | manage | Rotate key (new version) |
| `/api/keys/:id/revoke` | POST | manage | Permanently revoke key |
| `/api/keys/:id/destroy` | POST | manage | Destroy key material |
| `/api/keys/:id/encrypt` | POST | encrypt | Encrypt data |
| `/api/decrypt` | POST | encrypt | Decrypt data |
| `/api/threat` | GET | read | Threat intelligence details |
| `/api/policies` | GET | read | Active key policies |
| `/api/auth/whoami` | GET | read | Current API key info |
| `/api/auth/keys` | GET | admin | List API keys |
| `/api/auth/keys` | POST | admin | Create API key |
| `/api/auth/keys/:id` | DELETE | admin | Revoke API key |

## Key Hierarchy

```
Root Key
  └── Domain Key (per environment / business unit)
        └── KEK — Key Encrypting Key (wraps DEKs)
              └── DEK — Data Encrypting Key (encrypts application data)
```

Follows NIST SP 800-57. Each level contains the blast radius of a compromise — a leaked DEK doesn't expose other DEKs because the KEK is separate.

## API Key Scopes

| Scope | Permissions |
|-------|-------------|
| `read` | View keys, status, metrics, threat level |
| `encrypt` | Encrypt and decrypt data |
| `manage` | Create, rotate, revoke, destroy keys |
| `admin` | All of the above + manage API keys |

`admin` implies all other scopes. Principle of least privilege: give monitoring dashboards `read`, application services `read + encrypt`, admin tools `admin`.

## Adaptive Threat System

Citadel monitors security events and automatically adjusts key policies:

| Level | Trigger | Response |
|-------|---------|----------|
| LOW | Normal operations | Standard crypto-periods |
| GUARDED | Minor anomalies | Slightly tighter rotation |
| ELEVATED | Suspicious patterns | Compressed rotation schedules |
| HIGH | Active threat indicators | Forced rotation, reduced usage limits |
| CRITICAL | Under attack | Maximum restrictions |

Events that raise threat level: failed authentication, decryption failures, rapid access patterns, manual escalation. Score decays over time.

## Cryptography

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key encapsulation (classical) | X25519 ECDH | RFC 7748 |
| Key encapsulation (post-quantum) | ML-KEM-768 | FIPS 203 |
| Data encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 | NIST SP 800-56C |

Hybrid construction: both shared secrets are concatenated and fed through HKDF. Security holds if **either** X25519 or ML-KEM-768 remains secure.

### Wire Format

```
version[1] || suite_kem[1] || suite_aead[1] || flags[1] || kem_ct_len[2] ||
x25519_ephemeral_pk[32] || mlkem768_ct[1088] || nonce[12] || aead_ct[variable]
```

Self-describing, versioned, no negotiation (prevents downgrade attacks). See [SPEC.md](SPEC.md) for full specification.

### Security Properties

- **Constant-time comparison** — API key verification via `subtle` crate prevents timing attacks
- **Zeroization** — All shared secrets and AES keys wrapped in `Zeroizing<T>`, zeroed on drop
- **Uniform errors** — Decryption failures return identical error messages (no decryption oracle)
- **Integrity-chained audit log** — SHA-256 hash chain detects log tampering
- **Rate limiting** — Per-IP token bucket with threat escalation on violations

## Security

**Citadel is unaudited software.**

The implementation uses NIST-standardized primitives via established Rust crates (`ml-kem`, `x25519-dalek`, `aes-gcm`, `hkdf`). It does not implement any cryptographic algorithms. The value is in correct composition, not novel math.

**[→ Read the full Security Guarantees document](SECURITY_GUARANTEES.md)**

This document covers exactly:
- What Citadel protects (and what it does not)
- Replay protection guarantees per backend (memory / file / Redis), including restart behavior and clock drift
- Multi-instance assumptions
- Required operator actions for the security model to hold
- Cryptographic primitive table (algorithm, standard, crate version)
- Audit status

What has been done:
- Comprehensive test suite including known-answer tests, timing uniformity, bit-flip detection
- Fuzz testing of wire format parser and full decryption path
- Adversarial keystore tests: corrupted ciphertext, replay injection, truncated blobs, wrong-key
- FFI safety tests: null handling, concurrent keygen, wrong-buffer-length, zero-before-free
- Auth failure events written to tamper-evident audit chain

What has NOT been done:
- Independent security audit
- Formal verification
- FIPS validation
- Production deployment

**Do not use for sensitive data without independent review.** See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Compliance

Mapped against 34 NIST SP 800-57 controls: 26 satisfied, 7 partial, 1 gap. See [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) for the full mapping.

Relevant frameworks: NIST SP 800-57 (key management), CNSA 2.0 (PQC timeline), HIPAA (encryption at rest), SOC 2 (access controls and audit).

## Project Structure

```
rust_citadel/
├── citadel-envelope/        # Core hybrid encryption library
│   ├── src/
│   │   ├── envelope.rs      # Encrypt/decrypt operations
│   │   ├── kem.rs           # X25519 + ML-KEM-768 hybrid KEM
│   │   ├── kdf.rs           # HKDF-SHA256 key derivation
│   │   ├── wire.rs          # Wire format encode/decode
│   │   ├── aead.rs          # AES-256-GCM wrapper
│   │   ├── aad.rs           # Additional authenticated data
│   │   ├── error.rs         # Uniform error types
│   │   └── sdk.rs           # High-level API
│   ├── tests/               # KAT + roundtrip tests
│   └── fuzz/                # Fuzz targets
├── citadel-keystore/        # Key lifecycle management
│   └── src/
│       ├── keystore.rs      # Key CRUD + state machine
│       ├── policy.rs        # Crypto-period policies
│       ├── threat.rs        # Adaptive threat intelligence
│       ├── storage.rs       # File-based key storage
│       ├── audit.rs         # Integrity-chained audit log
│       └── types.rs         # Key types and states
├── citadel-api/             # HTTP server
│   └── src/
│       ├── main.rs          # API routes, auth, rate limiting
│       └── dashboard.html   # Real-time security dashboard
├── citadel_example.py       # Python integration example
├── Backup-Citadel.ps1       # Backup/restore tooling
├── docker-compose.yml       # Development deployment
├── docker-compose-production.yml  # Production with TLS
├── SPEC.md                  # Wire format specification
├── THREAT_MODEL.md          # Security goals and attacker model
├── COMPLIANCE_MATRIX.md     # NIST 800-57 control mapping
└── CITADEL_OVERVIEW.md      # Commercial overview
```

## Documentation

| Document | Audience |
|----------|----------|
| [SPEC.md](SPEC.md) | Wire format specification |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security goals and assumptions |
| [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) | NIST 800-57 compliance mapping |
| [CITADEL_OVERVIEW.md](CITADEL_OVERVIEW.md) | Commercial positioning |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [API_FREEZE.md](API_FREEZE.md) | API stability guarantees |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production deployment guide |
| [QUICKSTART.md](QUICKSTART.md) | Getting started |

## License

This project is dual-licensed:

- **GNU Affero General Public License v3 (AGPL)** — for open source use
- **Commercial License** — for proprietary or commercial use

If you are using this software in a commercial environment or do not wish to comply with AGPL terms, you must obtain a commercial license.

See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for commercial terms.

The full text of the AGPL is provided in [AGPL-3.0.txt](AGPL-3.0.txt) and [COPYING](COPYING).

Contact: commit@reposignal.io

## Author

Andre Cordero — andre.cordero36@gmail.com
