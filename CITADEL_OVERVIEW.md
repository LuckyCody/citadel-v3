# Citadel: Post-Quantum Key Management for Enterprise Applications

> Commercial positioning summary — technical claims herein are simplified; [README.md](README.md) and [SECURITY_MATURITY.md](docs/security/SECURITY_MATURITY.md) govern where they differ.

## The Problem

NIST mandates post-quantum cryptography migration by 2035. Most organizations encrypt sensitive data with algorithms that quantum computers will break. The challenge isn't just swapping algorithms — it's managing the key lifecycle: rotation, revocation, access control, audit trails, and compliance reporting across thousands of keys.

"Harvest now, decrypt later" attacks mean data encrypted today with classical-only algorithms is already at risk if it has long-term sensitivity (healthcare records, financial data, government communications, intellectual property).

## What Citadel Does

Citadel is a self-hosted key management server that handles post-quantum encryption for your applications. Your application calls Citadel's API to encrypt and decrypt data. Citadel manages everything else: key generation, rotation schedules, access control, threat response, and audit logging.

**Your application never touches raw key material.**

## How It Works

```
Your App                    Citadel                      Storage
   |                          |                            |
   |-- encrypt(data, aad) --> |                            |
   |                          |-- derive AES-256 key (HKDF)|
   |                          |   from hybrid KEM secrets  |
   |                          |   (X25519 + ML-KEM-768)    |
   |                          |-- encrypt with AES-256-GCM |
   | <-- encrypted blob ----- |                            |
   |                          |                            |
   |-- store blob ---------------------------------------->|
```

The encrypted blob is self-contained and self-describing. It includes the wrapped key, algorithm identifiers, and ciphertext. Your database schema doesn't change. Your application code is a dozen lines.

## Security Architecture

| Layer | Implementation | Standard |
|-------|---------------|----------|
| Key encapsulation | X25519 + ML-KEM-768 (hybrid) | FIPS 203 + RFC 7748 |
| Data encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 | NIST SP 800-56C |
| Key hierarchy | Root > Domain > KEK > DEK | NIST SP 800-57 |
| Threat response | 5-level adaptive system | Policy-driven |
| Audit | Integrity-chained JSONL | Tamper-evident |

Hybrid construction means security holds if **either** X25519 or ML-KEM remains secure. This is defense-in-depth for the PQC transition period.

### Key hierarchy — structural vs cryptographic wrapping

The four-level hierarchy `Root → Domain → KEK → DEK` is structurally enforced at key generation time: no key can be created outside the valid chain.

**Root** is a **logical authority** (offline key). It is not used at runtime to unwrap Domain. Root and Domain keys are both protected by `CITADEL_MASTER_KEY` (AES-256-GCM at rest).

**The cryptographic wrapping chain** (online, at runtime) is:
- `Domain → KEK`: Domain's Citadel public key (X25519 + ML-KEM-768) seals the KEK's secret key
- `KEK → DEK`: KEK's Citadel public key seals the DEK's secret key
- Decryption requires unwrapping up the online chain (DEK → KEK → Domain)

Root's role is access-control separation and hierarchy validation, not runtime key unwrapping. This is consistent with NIST SP 800-57 guidance on offline root keys and key custodian separation.

**Domain policy enforcement:** Runtime multi-tenant domain enforcement is
implemented at three layers: (1) **API** — API keys are bound to domains
(`allowed_domains`) and a central `authorize_domain_access` gate resolves the
target key's Domain and rejects out-of-domain operations on every crypto/key
endpoint, with cross-domain exploit tests; (2) **replay** — the
replay-claim key is domain-scoped, `SHA256(domain_id ‖ key_id ‖ version ‖ nonce ‖
tag)`, so a claim in one Domain cannot interfere with another; (3)
**keystore/crypto** — `encrypt_authorized`/`decrypt_authorized` independently
resolve the key's Domain from the hierarchy and refuse a mismatched authorization
(defense in depth), verified by `tests/domain_isolation.rs`. The application-level
`context` parameter remains an opaque caller tag and is not itself a domain
boundary — domain isolation does not depend on it and is enforced by the three
mechanisms above.

## Deployment

Citadel ships as a single Docker container. Add it to your existing stack:

```yaml
services:
  citadel:
    image: citadel:latest
    environment:
      CITADEL_ENV: "production"
      CITADEL_MASTER_KEY: "${CITADEL_MASTER_KEY}"
      CITADEL_API_KEY_HASH: "${API_KEY_HASH}"
      CITADEL_REPLAY_STORE: "file"
    volumes:
      - citadel-data:/data
    ports:
      - "8443:8443"
```

Production deployment includes Caddy for TLS termination, per-IP rate limiting, and scoped API keys for separation of duties.

## Integration

```python
# Encrypt a patient record
blob = citadel.encrypt(
    key_id=dek_id,
    plaintext=json.dumps(record),
    aad=record_id,           # Binds ciphertext to this record
    context="patient-records" # Application-defined context (not enforced by Domain)
)
db.store(record_id, blob)    # Store encrypted blob

# Decrypt
blob = db.fetch(record_id)
record = citadel.decrypt(blob, aad=record_id, context="patient-records")
```

AAD binding prevents record substitution attacks — swapping ciphertext between records causes decryption to fail.

## Compliance

Citadel maps to 34 controls in NIST SP 800-57: 27 satisfied, 6 partially satisfied, 1 gap. See docs/security/COMPLIANCE_MATRIX.md for the full mapping.

| Framework | Relevant Controls |
|-----------|------------------|
| NIST SP 800-57 | Key lifecycle, hierarchy, crypto-periods |
| NIST SP 800-131A | Algorithm transition (classical to PQC) |
| CNSA 2.0 | Suite `0xA4` (P-384 + ML-KEM-1024, category 5) is CNSA 2.0-aligned; ML-KEM-768 (`0xA3`, category 3) does not meet CNSA 2.0 |
| HIPAA | Encryption at rest, access controls, audit logs |
| SOC 2 | Logical access, key management, monitoring |

## Current Status

| Aspect | Status |
|--------|--------|
| Core encryption (citadel-envelope) | Working, tested, fuzz-tested |
| Key management (citadel-keystore) | Working, 4-level hierarchy |
| API server (citadel-api) | Working, authenticated, rate-limited |
| Dashboard | Working, real-time threat visualization |
| Independent audit | **Not yet completed** |
| Production deployments | **None yet** |
| FIPS validation | **Not a validated deployment.** The optional `fips` build routes envelope operations through a CMVP-validated AWS-LC module, but that does not make Citadel itself a validated product — see [SECURITY_MATURITY.md](docs/security/SECURITY_MATURITY.md). |

## What Independent Audit Would Cover

A comprehensive independent audit from a brand-name firm (Trail of Bits, NCC
Group) realistically runs **$75K–$150K+** (priced by engineer-weeks). A **scoped**
review of just the core crypto (hybrid-KEM combiner, KDF binding, wire format) by
an independent cryptographer or an academic group can land in the **$20–40K** range
or lower — and the extensive free self-validation below (see `gauntlet/`) is
designed to make that scoped review cheaper by clearing the mechanical findings
first. An audit would review:

1. Hybrid KEM composition correctness
2. KDF domain separation and binding
3. Wire format parsing for memory safety
4. Side-channel resistance on reference hardware
5. Key lifecycle state machine completeness
6. Error handling (no decryption oracle leaks)

## Engagement Models

| Model | Scope | Timeline |
|-------|-------|----------|
| Migration assessment | Inventory current crypto, identify harvest-now risks, prioritize | 2-4 weeks |
| Proof of concept | Deploy Citadel with one application, validate integration | 4-6 weeks |
| Full deployment | Production rollout, monitoring, compliance documentation | 3-6 months |
| Ongoing support | Key rotation oversight, threat monitoring, audit prep | Retainer |

## Contact

Andre Cordero
andre.cordero36@gmail.com
