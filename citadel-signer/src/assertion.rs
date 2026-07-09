// SPDX-License-Identifier: AGPL-3.0-or-later
//! Citadel Native Assertion (CNA) — post-quantum JWT replacement.
//!
//! # What this is
//!
//! The CNA format is a self-describing signed assertion that replaces JWT in
//! applications where post-quantum security is required. It is NOT a JWT variant —
//! it is a native format designed around Citadel's security model.
//!
//! # Security properties (vs JWT)
//!
//! | Property | JWT (RS256/ES256) | CNA |
//! |----------|------------------|-----|
//! | Signing algorithm | RSA/ECDSA (Shor's breakable) | ML-DSA-65 (NIST FIPS 204) |
//! | Key protection | Private key on disk | Key in Citadel hierarchy |
//! | Claim confidentiality | None (base64 only) | Optional encrypted sealed_claims |
//! | Replay protection | Convention (jti + app logic) | assertion_id field |
//! | Key revocation | No standard mechanism | Citadel key revoke |
//! | Stateless verification | Yes (public key) | Yes (verifying key) |
//!
//! # Format
//!
//! ```json
//! {
//!   "version": "cna-v1",
//!   "suite": "ml-dsa-65",
//!   "signing_key_id": "abc123",
//!   "signing_key_version": 1,
//!   "issued_at": 1714847234,
//!   "expires_at": 1714850834,
//!   "assertion_id": "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
//!   "public_claims": { "sub": "user_123", "scope": ["read"] },
//!   "sealed_claims_hex": null,
//!   "signature_hex": "..."
//! }
//! ```
//!
//! # Signature coverage
//!
//! The ML-DSA-65 signature covers the canonical form of ALL fields EXCEPT
//! `signature_hex`. Canonical form = JSON with sorted keys, no whitespace.
//! This is deterministic and unambiguous.
//!
//! # Verification (stateless)
//!
//! A verifier with only the ML-DSA-65 verifying key can verify the assertion
//! without any network call to Citadel. The verifying key is available from
//! `GET /api/keys/{id}/verifying-key`.

use crate::dsa;
use crate::error::AssertionError;
use crate::wire::CNA_VERSION;
use chrono::{DateTime, TimeZone, Utc};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Citadel Native Assertion — the JWT replacement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CitadelAssertion {
    /// Format version — always "cna-v1".
    pub version: String,
    /// Signing algorithm suite — always "ml-dsa-65" for this implementation.
    pub suite: String,
    /// The Citadel signing key ID used to produce this assertion.
    pub signing_key_id: String,
    /// Which version of the signing key was used.
    pub signing_key_version: u32,
    /// Unix timestamp when this assertion was issued.
    pub issued_at: i64,
    /// Unix timestamp when this assertion expires.
    pub expires_at: i64,
    /// Random assertion ID (hex, 32 chars = 16 bytes).
    /// Applications that need one-time semantics track this ID themselves.
    pub assertion_id: String,
    /// Public claims — cleartext, signed by ML-DSA-65.
    /// Verifiable without Citadel. Must not contain sensitive data.
    pub public_claims: Value,
    /// Optional: Citadel-encrypted private claims.
    /// If present, these are AES-256-GCM encrypted via the Citadel keystore.
    /// Only Citadel can decrypt them. Contains the DEK key_id for decryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_claims_hex: Option<String>,
    /// Which DEK encrypted the sealed claims (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_claims_key_id: Option<String>,
    /// Which version of that DEK (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_claims_key_version: Option<u32>,
    /// ML-DSA-65 signature over the canonical form of all other fields.
    /// Hex-encoded, 3309 bytes.
    pub signature_hex: String,
}

impl CitadelAssertion {
    /// P382 — Build an unsigned assertion with a clearly-empty signature.
    ///
    /// `signature_hex` is set to `String::new()` — verifiably unsigned, not null-key-signed.
    /// Use this to:
    ///   1. Build the assertion structure
    ///   2. Call `canonical_signing_input()` to get the bytes to sign
    ///   3. Sign those bytes through Citadel (sign_authorized)
    ///   4. Set `assertion.signature_hex = signed_payload.signature_hex`
    ///
    /// This replaces the old pattern of instantiating `CitadelAssertionIssuer` with a
    /// fake `vec![0u8; 32]` placeholder seed and overwriting the signature. A never-signed
    /// assertion has an empty signature_hex (visibly invalid) rather than a null-key signature
    /// (secretly wrong). If the overwrite fails or is skipped, `verify()` will fail immediately.
    pub fn build_unsigned(
        signing_key_id: impl Into<String>,
        signing_key_version: u32,
        public_claims: Value,
        ttl_secs: u64,
        sealed_claims_hex: Option<String>,
        sealed_claims_key_id: Option<String>,
        sealed_claims_key_version: Option<u32>,
    ) -> Result<Self, AssertionError> {
        use rand_core::RngCore;
        let now = Utc::now().timestamp();
        let expires_at = now + ttl_secs as i64;
        let mut id_bytes = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id_bytes);
        let assertion_id = hex::encode(id_bytes);
        Ok(Self {
            version: crate::wire::CNA_VERSION.to_string(),
            suite: "ml-dsa-65".to_string(),
            signing_key_id: signing_key_id.into(),
            signing_key_version,
            issued_at: now,
            expires_at,
            assertion_id,
            public_claims,
            sealed_claims_hex,
            sealed_claims_key_id,
            sealed_claims_key_version,
            signature_hex: String::new(), // P382: visibly unsigned — not null-key-signed
        })
    }

    /// Compute the canonical signing input for this assertion.
    ///
    /// All fields EXCEPT `signature_hex` are serialized as sorted-key JSON
    /// with no whitespace. This is the byte string that is signed and verified.
    pub fn canonical_signing_input(&self) -> Result<Vec<u8>, AssertionError> {
        // Build a copy without the signature field
        let mut map = serde_json::Map::new();
        map.insert("version".into(), Value::String(self.version.clone()));
        map.insert("suite".into(), Value::String(self.suite.clone()));
        map.insert(
            "signing_key_id".into(),
            Value::String(self.signing_key_id.clone()),
        );
        map.insert(
            "signing_key_version".into(),
            Value::Number(self.signing_key_version.into()),
        );
        map.insert("issued_at".into(), Value::Number(self.issued_at.into()));
        map.insert("expires_at".into(), Value::Number(self.expires_at.into()));
        map.insert(
            "assertion_id".into(),
            Value::String(self.assertion_id.clone()),
        );
        map.insert("public_claims".into(), self.public_claims.clone());
        if let Some(ref s) = self.sealed_claims_hex {
            map.insert("sealed_claims_hex".into(), Value::String(s.clone()));
        }
        if let Some(ref kid) = self.sealed_claims_key_id {
            map.insert("sealed_claims_key_id".into(), Value::String(kid.clone()));
        }
        if let Some(ver) = self.sealed_claims_key_version {
            map.insert(
                "sealed_claims_key_version".into(),
                Value::Number(ver.into()),
            );
        }

        // Sorted keys, no whitespace — deterministic canonical form
        let canonical = serde_json::to_string(&Value::Object(map))
            .map_err(|e| AssertionError(format!("canonical serialize: {}", e)))?;

        Ok(canonical.into_bytes())
    }

    /// Verify this assertion against a provided ML-DSA-65 verifying key.
    ///
    /// # Checks
    /// 1. `version` == "cna-v1"
    /// 2. `suite` == "ml-dsa-65"  
    /// 3. `expires_at` > now
    /// 4. ML-DSA-65 signature valid over canonical form
    ///
    /// # Stateless
    ///
    /// Does not require Citadel. The `verifying_key_bytes` can be cached or
    /// fetched from `GET /api/keys/{id}/verifying-key`.
    pub fn verify(&self, verifying_key_bytes: &[u8]) -> Result<VerifiedClaims, AssertionError> {
        // Version and suite checks
        if self.version != CNA_VERSION {
            return Err(AssertionError(format!(
                "unsupported version '{}' (expected '{}')",
                self.version, CNA_VERSION
            )));
        }
        if self.suite != "ml-dsa-65" {
            return Err(AssertionError(format!(
                "unsupported suite '{}' (expected 'ml-dsa-65')",
                self.suite
            )));
        }

        // Expiry check
        let now = Utc::now().timestamp();
        if self.expires_at <= now {
            return Err(AssertionError(format!(
                "assertion expired at {} (now {})",
                self.expires_at, now
            )));
        }

        // Reconstruct canonical signing input
        let signing_input = self.canonical_signing_input()?;

        // Decode signature
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| AssertionError(format!("decode signature_hex: {}", e)))?;

        // Verify ML-DSA-65 signature
        let valid = dsa::verify_message(verifying_key_bytes, &signing_input, &sig_bytes)
            .map_err(|e| AssertionError(format!("verification error: {}", e)))?;

        if !valid {
            return Err(AssertionError("signature invalid".into()));
        }

        Ok(VerifiedClaims {
            public_claims: self.public_claims.clone(),
            assertion_id: self.assertion_id.clone(),
            signing_key_id: self.signing_key_id.clone(),
            signing_key_version: self.signing_key_version,
            issued_at: Utc
                .timestamp_opt(self.issued_at, 0)
                .single()
                .unwrap_or_else(Utc::now),
            expires_at: Utc
                .timestamp_opt(self.expires_at, 0)
                .single()
                .unwrap_or_else(Utc::now),
            has_sealed_claims: self.sealed_claims_hex.is_some(),
        })
    }
}

/// Claims extracted from a successfully verified `CitadelAssertion`.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    /// The public claims from the assertion.
    pub public_claims: Value,
    /// The assertion ID (for application-level replay tracking).
    pub assertion_id: String,
    /// Which signing key produced this assertion.
    pub signing_key_id: String,
    /// Which version of that key.
    pub signing_key_version: u32,
    /// When the assertion was issued.
    pub issued_at: DateTime<Utc>,
    /// When the assertion expires.
    pub expires_at: DateTime<Utc>,
    /// Whether sealed (encrypted) claims are present.
    pub has_sealed_claims: bool,
}

/// Builder for issuing Citadel Native Assertions.
///
/// The issuer signs assertions using an ML-DSA-65 seed (unwrapped from Citadel
/// by the caller). In production, the signing key is managed by citadel-keystore
/// and the seed is unwrapped via `Keystore::sign()`.
/// Low-level assertion issuer for offline signing with a raw ML-DSA-65 seed.
///
/// # ⚠️ Production vs Low-level paths
///
/// **Production server path (RECOMMENDED):**
/// ```text
/// CitadelAssertion::build_unsigned(...)  // construct assertion struct
///   → canonical_signing_input()          // get bytes to sign
///   → Keystore::sign_authorized(...)     // sign through Citadel key management
///   → assertion.signature_hex = result  // attach real signature
/// ```
///
/// **Low-level / test / offline path (this struct):**
/// ```text
/// CitadelAssertionIssuer::new(key_id, version, raw_seed_bytes)
///   → issue(...) / issue_with_sealed(...)
/// ```
///
/// The production path ensures the signing key is Citadel-managed and audited.
/// This struct is provided for offline verification tools, test fixtures, and
/// migration utilities where Citadel key management is not available.
/// Do NOT use this in production Citadel server code for issuing assertions.
pub struct CitadelAssertionIssuer {
    signing_key_id: String,
    signing_key_version: u32,
    seed_bytes: Vec<u8>, // 32-byte ML-DSA-65 seed — caller is responsible for zeroizing
}

impl CitadelAssertionIssuer {
    /// Create an issuer from an unwrapped 32-byte ML-DSA-65 seed.
    ///
    /// # Security
    ///
    /// The seed is secret key material. The caller must zeroize it after the
    /// issuer is dropped. In production this is handled by the keystore layer.
    pub fn new(
        signing_key_id: impl Into<String>,
        signing_key_version: u32,
        seed_bytes: Vec<u8>,
    ) -> Self {
        Self {
            signing_key_id: signing_key_id.into(),
            signing_key_version,
            seed_bytes,
        }
    }

    /// Issue a Citadel Native Assertion with public claims.
    ///
    /// # Arguments
    /// - `public_claims`: JSON value containing the assertion claims (will be signed)
    /// - `ttl_secs`: how many seconds until expiry
    pub fn issue(
        &self,
        public_claims: Value,
        ttl_secs: u64,
    ) -> Result<CitadelAssertion, AssertionError> {
        self.issue_inner(public_claims, ttl_secs, None, None, None)
    }

    /// Issue a CNA with both public claims and sealed (encrypted) claims.
    ///
    /// The `sealed_claims_hex` is the hex of a Citadel EncryptedBlob — the caller
    /// must encrypt it using `Keystore::encrypt()` before passing it here.
    pub fn issue_with_sealed(
        &self,
        public_claims: Value,
        ttl_secs: u64,
        sealed_claims_hex: String,
        sealed_claims_key_id: String,
        sealed_claims_key_version: u32,
    ) -> Result<CitadelAssertion, AssertionError> {
        self.issue_inner(
            public_claims,
            ttl_secs,
            Some(sealed_claims_hex),
            Some(sealed_claims_key_id),
            Some(sealed_claims_key_version),
        )
    }

    fn issue_inner(
        &self,
        public_claims: Value,
        ttl_secs: u64,
        sealed_claims_hex: Option<String>,
        sealed_claims_key_id: Option<String>,
        sealed_claims_key_version: Option<u32>,
    ) -> Result<CitadelAssertion, AssertionError> {
        let now = Utc::now().timestamp();
        let expires_at = now + ttl_secs as i64;

        // Generate random assertion ID (16 bytes = 32 hex chars)
        let mut id_bytes = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id_bytes);
        let assertion_id = hex::encode(id_bytes);

        // Build the unsigned assertion (signature_hex placeholder)
        let mut assertion = CitadelAssertion {
            version: CNA_VERSION.to_string(),
            suite: "ml-dsa-65".to_string(),
            signing_key_id: self.signing_key_id.clone(),
            signing_key_version: self.signing_key_version,
            issued_at: now,
            expires_at,
            assertion_id,
            public_claims,
            sealed_claims_hex,
            sealed_claims_key_id,
            sealed_claims_key_version,
            signature_hex: String::new(), // placeholder — filled below
        };

        // Compute canonical signing input (all fields except signature_hex)
        let signing_input = assertion.canonical_signing_input()?;

        // Sign with ML-DSA-65
        let sig_bytes = dsa::sign_message(&self.seed_bytes, &signing_input)
            .map_err(|e| AssertionError(format!("signing failed: {}", e)))?;

        assertion.signature_hex = hex::encode(&sig_bytes);
        Ok(assertion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa;
    use serde_json::json;

    fn make_test_issuer() -> (CitadelAssertionIssuer, Vec<u8>) {
        let (vk, seed) = dsa::generate_keypair().expect("keygen");
        let issuer = CitadelAssertionIssuer::new("test-signing-key-id", 1, seed.to_vec());
        (issuer, vk)
    }

    #[test]
    fn test_issue_and_verify() {
        let (issuer, vk) = make_test_issuer();
        let claims = json!({ "sub": "user_123", "scope": ["read"] });

        let assertion = issuer.issue(claims.clone(), 3600).expect("issue");
        assert_eq!(assertion.version, CNA_VERSION);
        assert_eq!(assertion.suite, "ml-dsa-65");
        assert!(!assertion.signature_hex.is_empty());

        let verified = assertion.verify(&vk).expect("verify");
        assert_eq!(verified.public_claims, claims);
        assert!(!verified.has_sealed_claims);
    }

    #[test]
    fn test_expired_assertion_rejected() {
        let (issuer, vk) = make_test_issuer();
        let claims = json!({ "sub": "user_123" });

        let mut assertion = issuer.issue(claims, 1).expect("issue");
        // Force expiry by setting expires_at in the past
        assertion.expires_at = Utc::now().timestamp() - 100;

        let result = assertion.verify(&vk);
        assert!(result.is_err(), "expired assertion must be rejected");
        assert!(result.unwrap_err().0.contains("expired"));
    }

    #[test]
    fn test_tampered_public_claims_rejected() {
        let (issuer, vk) = make_test_issuer();
        let claims = json!({ "sub": "user_123", "scope": ["read"] });

        let mut assertion = issuer.issue(claims, 3600).expect("issue");
        // Tamper with public_claims after signing
        assertion.public_claims = json!({ "sub": "attacker", "scope": ["admin"] });

        let result = assertion.verify(&vk);
        assert!(result.is_err(), "tampered claims must be rejected");
    }

    #[test]
    fn test_wrong_verifying_key_rejected() {
        let (issuer, _) = make_test_issuer();
        let (vk2, _) = dsa::generate_keypair().expect("keygen2");
        let claims = json!({ "sub": "user_123" });

        let assertion = issuer.issue(claims, 3600).expect("issue");
        let result = assertion.verify(&vk2);
        assert!(result.is_err(), "wrong key must reject");
    }

    #[test]
    fn test_wrong_version_rejected() {
        let (issuer, vk) = make_test_issuer();
        let claims = json!({ "sub": "user" });

        let mut assertion = issuer.issue(claims, 3600).expect("issue");
        assertion.version = "cna-v99".into();

        let result = assertion.verify(&vk);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("unsupported version"));
    }

    #[test]
    fn test_assertion_id_is_random() {
        let (issuer, _) = make_test_issuer();
        let a1 = issuer.issue(json!({"x": 1}), 60).expect("issue1");
        let a2 = issuer.issue(json!({"x": 1}), 60).expect("issue2");
        assert_ne!(
            a1.assertion_id, a2.assertion_id,
            "assertion_ids must be unique"
        );
    }

    #[test]
    fn test_canonical_form_excludes_signature() {
        let (issuer, _) = make_test_issuer();
        let assertion = issuer.issue(json!({"sub": "user"}), 60).expect("issue");
        let canonical = assertion.canonical_signing_input().expect("canonical");
        let canonical_str = String::from_utf8(canonical).expect("utf8");
        assert!(
            !canonical_str.contains("signature_hex"),
            "canonical form must not include signature"
        );
    }

    #[test]
    fn canonical_form_is_stable_for_claim_key_order() {
        let (issuer, _) = make_test_issuer();
        let a = issuer
            .issue(
                json!({"a": 1, "b": 2, "nested": {"x": true, "y": false}}),
                60,
            )
            .expect("issue a");
        let mut b = a.clone();
        b.public_claims = json!({"nested": {"y": false, "x": true}, "b": 2, "a": 1});

        assert_eq!(
            a.canonical_signing_input().expect("canonical a"),
            b.canonical_signing_input().expect("canonical b"),
            "canonical form must not depend on JSON object insertion order"
        );
    }

    #[test]
    fn duplicate_top_level_assertion_fields_are_rejected_by_deserializer() {
        let raw = r#"{
            "version": "cna-v1",
            "version": "cna-v2",
            "suite": "ml-dsa-65",
            "signing_key_id": "k",
            "signing_key_version": 1,
            "issued_at": 9999999999,
            "expires_at": 9999999999,
            "assertion_id": "duplicate-field-test",
            "public_claims": {},
            "signature_hex": "00"
        }"#;

        let parsed = serde_json::from_str::<CitadelAssertion>(raw);
        assert!(
            parsed.is_err(),
            "duplicate top-level assertion fields must be rejected"
        );
    }

    #[test]
    fn explicit_null_optional_fields_are_canonicalized_like_absent_fields() {
        let (issuer, vk) = make_test_issuer();
        let assertion = issuer.issue(json!({"sub": "user"}), 60).expect("issue");
        let raw = serde_json::json!({
            "version": assertion.version,
            "suite": assertion.suite,
            "signing_key_id": assertion.signing_key_id,
            "signing_key_version": assertion.signing_key_version,
            "issued_at": assertion.issued_at,
            "expires_at": assertion.expires_at,
            "assertion_id": assertion.assertion_id,
            "public_claims": assertion.public_claims,
            "sealed_claims_hex": null,
            "sealed_claims_key_id": null,
            "sealed_claims_key_version": null,
            "signature_hex": assertion.signature_hex,
        });

        let reparsed: CitadelAssertion =
            serde_json::from_value(raw).expect("parse with null optionals");
        reparsed
            .verify(&vk)
            .expect("explicit null optionals currently verify as absent");
        assert_eq!(
            assertion
                .canonical_signing_input()
                .expect("canonical absent"),
            reparsed.canonical_signing_input().expect("canonical null"),
            "current canonical model treats explicit null optionals as absent"
        );
    }
}
