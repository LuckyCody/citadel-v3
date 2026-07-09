# Citadel - NIST SP 800-57 Compliance Matrix

## Overview

This document maps Citadel's key management capabilities against NIST Special Publication 800-57 Part 1 Rev. 5 ("Recommendation for Key Management: Part 1 - General"). It is intended for compliance officers, security architects, and procurement teams evaluating Citadel for enterprise deployment.

**Assessment date:** February 2026
**Citadel version:** 0.2.0 (citadel-envelope 0.1.0, citadel-keystore 0.1.0)
**Auditor:** Self-assessed (no independent audit)

---

## Compliance Summary

| Category | Controls | Satisfied | Partial | Gap |
|----------|----------|-----------|---------|-----|
| Key Types & Hierarchy | 6 | 5 | 1 | 0 |
| Key Lifecycle | 8 | 7 | 1 | 0 |
| Cryptographic Algorithms | 5 | 4 | 1 | 0 |
| Key Protection | 6 | 4 | 2 | 0 |
| Operational Security | 5 | 3 | 1 | 1 |
| Audit & Accountability | 4 | 3 | 1 | 0 |
| **Total** | **34** | **26** | **7** | **1** |

---

## Detailed Control Mapping

### 1. Key Types & Hierarchy (Section 5.3)

| # | NIST Requirement | Status | Citadel Implementation | Gap |
|---|-----------------|--------|----------------------|-----|
| 1.1 | Distinct key types with defined purposes | SATISFIED | Four-level hierarchy: Root, Domain, Key-Encrypting (KEK), Data-Encrypting (DEK). Each type has enforced usage constraints. | - |
| 1.2 | Key-encrypting keys separated from data-encrypting keys | SATISFIED | KEKs and DEKs are separate types with independent policies. DEKs cannot wrap other keys. | - |
| 1.3 | Key hierarchy with master keys protecting subordinate keys | SATISFIED | Root -> Domain -> KEK -> DEK hierarchy. Parent-child relationships tracked and enforced. | - |
| 1.4 | Symmetric keys for data protection | SATISFIED | AES-256-GCM for all data encryption. Keys generated via OS CSPRNG. | - |
| 1.5 | Asymmetric keys for key transport | SATISFIED | Hybrid X25519 + ML-KEM-768 for key encapsulation. Public/private key pairs generated per operation. | - |
| 1.6 | Key agreement protocols | PARTIAL | Hybrid KEM provides key agreement for encryption. No interactive key agreement (e.g., TLS handshake) - by design, Citadel handles sealed/at-rest encryption only. | Interactive protocols out of scope per threat model. |

### 2. Key Lifecycle (Section 5.3.5)

| # | NIST Requirement | Status | Citadel Implementation | Gap |
|---|-----------------|--------|----------------------|-----|
| 2.1 | Key generation using approved RNG | SATISFIED | `getrandom` crate (OS CSPRNG). ML-KEM key generation per FIPS 203. X25519 key generation per RFC 7748. | - |
| 2.2 | Key activation with explicit transition | SATISFIED | Keys must be explicitly activated before use. State machine: Pending -> Active. Activation logged to audit trail. | - |
| 2.3 | Key rotation before crypto-period expiration | SATISFIED | Policy-driven rotation with configurable crypto-periods. Adaptive threat system compresses rotation schedules under attack. Rotation creates new key version, old version enters grace period. | - |
| 2.4 | Key revocation | SATISFIED | Explicit revocation with mandatory reason. Revoked keys cannot encrypt. State transition is permanent and logged. | - |
| 2.5 | Key destruction with zeroization | SATISFIED | `Zeroizing<T>` wrappers on all sensitive material. Key destruction removes material from storage. Zeroization uses `zeroize` crate (compiler-barrier protected). | - |
| 2.6 | Key state tracking | SATISFIED | Six states: Pending, Active, Rotated, Suspended, Revoked, Destroyed. All transitions logged with timestamps and reasons. | - |
| 2.7 | Crypto-period enforcement | SATISFIED | Per-policy rotation age, max lifetime, usage limits. Adaptive system tightens all three under elevated threat. Keys exceeding max lifetime are automatically expired. | - |
| 2.8 | Key archival for historical decryption | PARTIAL | Rotated keys enter grace period allowing decryption. No long-term archival system beyond file-based storage. | Production deployments should implement HSM-backed archival for keys with long retention requirements. |

### 3. Cryptographic Algorithms (Section 5.2)

| # | NIST Requirement | Status | Citadel Implementation | Gap |
|---|-----------------|--------|----------------------|-----|
| 3.1 | NIST-approved symmetric algorithms | SATISFIED | AES-256-GCM (NIST SP 800-38D). 256-bit keys provide >=128-bit post-quantum security margin. | - |
| 3.2 | NIST-approved key derivation | SATISFIED | HKDF-SHA256 (NIST SP 800-56C Rev. 2). Domain-separated with protocol ID, suite identifiers, and context binding. | - |
| 3.3 | Post-quantum algorithms per FIPS 203 | SATISFIED | ML-KEM-768 (FIPS 203, August 2024). Category 3 security level. | - |
| 3.4 | Hybrid construction for migration period | SATISFIED | X25519 + ML-KEM-768 combined via HKDF. Security holds if either primitive remains secure. Follows NIST hybrid guidance for PQC transition. | - |
| 3.5 | Algorithm agility / negotiation | PARTIAL | Wire format includes suite identifiers (kem=0xA3, aead=0xB1) enabling future algorithm additions. Only one suite currently implemented. | Single suite is intentional to avoid negotiation downgrade attacks. Additional suites can be added via wire format versioning. |

### 4. Key Protection (Section 6.2)

| # | NIST Requirement | Status | Citadel Implementation | Gap |
|---|-----------------|--------|----------------------|-----|
| 4.1 | Keys encrypted at rest | SATISFIED | All key material stored encrypted on disk via file-based backend with OS-level access controls. Docker volume isolation in production deployment. | - |
| 4.2 | Keys protected in memory | SATISFIED | `Zeroizing<T>` wrappers ensure sensitive material is zeroed on drop. Shared secrets never persist beyond their immediate use. | - |
| 4.3 | Access control on key operations | SATISFIED | API key authentication with four scope levels (read, encrypt, manage, admin). Scope enforcement on every endpoint. Constant-time key comparison prevents timing attacks. | - |
| 4.4 | Separation of duties | PARTIAL | Scope system enables separation (read-only monitoring vs. encrypt-capable services vs. admin). No mandatory multi-party approval for critical operations (key destruction, policy changes). | Multi-party authorization recommended for production deployments with high-value keys. |
| 4.5 | Protection against side-channel attacks | PARTIAL | Constant-time comparison via `subtle` crate. Uniform error responses prevent decryption oracles. Timing analysis test suite included. Side-channel properties inherited from dependencies, not independently verified. | Independent verification recommended before handling classified or high-value data. |
| 4.6 | Rate limiting on key access | SATISFIED | Per-IP token bucket rate limiting (configurable RPS and burst). Rate limit violations recorded as threat events. Repeated auth failures escalate threat level. | - |

### 5. Operational Security (Section 6.3)

| # | NIST Requirement | Status | Citadel Implementation | Gap |
|---|-----------------|--------|----------------------|-----|
| 5.1 | Backup and recovery procedures | SATISFIED | Automated backup script with SHA-256 integrity verification. Safety-net backup before restore. Timestamped archives with manifests. | - |
| 5.2 | Incident response / threat handling | SATISFIED | Five-level adaptive threat intelligence (LOW through CRITICAL). Automatic policy tightening under attack. Event-driven threat scoring with time decay. Audit logging of all security events. | - |
| 5.3 | Audit trail of key operations | SATISFIED | Integrity-chained JSONL audit log. Every key operation, auth event, and threat event logged with timestamps. Chain verification detects tampering. | - |
| 5.4 | Key transport security | PARTIAL | API keys transmitted via HTTPS (Caddy TLS termination). Plaintext keys shown once at creation. No dedicated key transport protocol (e.g., KMIP). | KMIP integration would enable interoperability with enterprise key management ecosystems. |
| 5.5 | Compliance reporting | GAP | No built-in compliance reporting or automated control verification. This document serves as manual compliance mapping. | Automated compliance dashboards and periodic control attestation reports recommended for regulated environments. |

### 6. Audit & Accountability (Section 6.7)

| # | NIST Requirement | Status | Citadel Implementation | Gap |
|---|-----------------|--------|----------------------|-----|
| 6.1 | Log all key lifecycle events | SATISFIED | Generate, activate, rotate, revoke, destroy all logged. Encrypt/decrypt operations tracked via usage counters. | - |
| 6.2 | Log authentication events | SATISFIED | Successful auth, failed auth, scope violations, rate limit events all logged. Source IP recorded. | - |
| 6.3 | Tamper-evident audit log | SATISFIED | Integrity chain (SHA-256 hash chain) on audit log entries. Append-only JSONL format. Chain break detection on read. | - |
| 6.4 | Audit log protection and retention | PARTIAL | Log included in backup archives. No built-in log rotation, retention policies, or remote log shipping. | Production deployments should ship audit logs to SIEM (Splunk, ELK) and implement retention policies per organizational requirements. |

---

## Post-Quantum Transition Readiness

| NIST PQC Milestone | Status | Notes |
|-------------------|--------|-------|
| FIPS 203 (ML-KEM) implementation | DONE | ML-KEM-768, Category 3 security |
| Hybrid classical + PQC construction | DONE | X25519 + ML-KEM-768, defense-in-depth |
| Algorithm agility in wire format | DONE | Suite IDs in header, version field for future formats |
| Crypto-period policies for PQC keys | DONE | Configurable per-policy, adaptive under threat |
| Migration path from classical-only | DONE | Wire format self-describing, old data remains decryptable |
| CNSA 2.0 compliance timeline | ON TRACK | ML-KEM-768 meets CNSA 2.0 requirements for software by 2025 |

---

## Recommendations for Production Deployment

### Before handling sensitive data:
1. **Independent security audit** of citadel-envelope (cryptographic core)
2. **Penetration test** of citadel-api (HTTP attack surface)
3. **Side-channel verification** on target deployment hardware

### For regulated environments (HIPAA, SOC 2, FedRAMP):
4. **SIEM integration** - ship audit logs to centralized logging
5. **HSM integration** - protect root keys in hardware security module
6. **Multi-party authorization** - require approval for key destruction
7. **Automated compliance reporting** - periodic control attestation

### For NIST 2035 PQC mandate compliance:
8. **Document current classical-only systems** that need migration
9. **Inventory encrypted data** with expected retention periods
10. **Prioritize harvest-now-decrypt-later risks** (long-lived secrets first)

---

## Document Control

| Field | Value |
|-------|-------|
| Classification | Public |
| Author | Self-assessed |
| Review cycle | Per major release |
| Next review | v0.3.0 or independent audit (whichever first) |
