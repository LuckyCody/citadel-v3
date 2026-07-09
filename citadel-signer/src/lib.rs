// SPDX-License-Identifier: AGPL-3.0-or-later
//! # citadel-signer
//!
//! ML-DSA-65 (NIST FIPS 204) signing primitives and the Citadel Native Assertion
//! format for Citadel V3.
//!
//! ## Modules
//!
//! - [`dsa`] — low-level ML-DSA-65 primitives on raw bytes (generate, sign, verify)
//! - [`assertion`] — Citadel Native Assertion format (JWT replacement)
//! - [`wire`] — ML-DSA-65 wire format constants
//! - [`error`] — error types
//!
//! ## Quick start — Production path (Citadel server)
//!
//! The recommended production path uses `build_unsigned` + Citadel keystore signing.
//! The signing key is Citadel-managed, audited, and never held as raw bytes in the caller:
//!
//! ```rust,ignore
//! use citadel_signer::assertion::CitadelAssertion;
//! use serde_json::json;
//!
//! // 1. Build unsigned assertion (no seed required)
//! let mut assertion = CitadelAssertion::build_unsigned(
//!     "my-signing-key-id", 1, json!({"sub": "user123"}), 3600,
//!     None, None, None,
//! ).unwrap();
//!
//! // 2. Get canonical bytes to sign
//! let canonical = assertion.canonical_signing_input().unwrap();
//!
//! // 3. Sign through Citadel keystore (sign_authorized) — never touches raw seed
//! // let signed_payload = keystore.sign_authorized(&authz_ctx, &canonical).await?;
//! // assertion.signature_hex = signed_payload.signature_hex;
//!
//! // 4. Verify (stateless — only needs verifying key bytes)
//! // let claims = assertion.verify(&vk_bytes).unwrap();
//! ```
//!
//! ## Low-level / offline path (raw seed)
//!
//! `CitadelAssertionIssuer` signs directly from a raw ML-DSA-65 seed byte vector.
//! Use this ONLY for offline tools, test fixtures, and migration utilities where
//! Citadel key management is unavailable. **Do not use in production server code.**
//!
//! ```rust,ignore
//! use citadel_signer::{dsa, assertion::CitadelAssertionIssuer};
//! use serde_json::json;
//!
//! let (vk_bytes, seed) = dsa::generate_keypair().unwrap();
//! let issuer = CitadelAssertionIssuer::new("key-id-1", 1, seed.to_vec());
//! let assertion = issuer.issue(json!({"sub": "user123"}), 3600).unwrap();
//! let claims = assertion.verify(&vk_bytes).unwrap();
//! ```

pub mod assertion;
pub mod dsa;
pub mod error;
pub mod wire;

// Convenient re-exports
pub use assertion::{CitadelAssertion, CitadelAssertionIssuer, VerifiedClaims};
pub use dsa::{generate_keypair, sign_message, verify_message, verifying_key_from_seed};
pub use error::{AssertionError, SignError, VerifyError};
pub use wire::{CNA_VERSION, MLDSA65_SEED_BYTES, MLDSA65_SIG_BYTES, MLDSA65_VK_BYTES};
