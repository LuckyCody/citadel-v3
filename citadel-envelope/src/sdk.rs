// SPDX-License-Identifier: AGPL-3.0-or-later
//! Citadel SDK Ã¢â‚¬â€ Public API Surface
//!
//! This module defines the **frozen** public interface for Citadel.
//! Everything else is internal implementation detail.
//!
//! # API Stability Promise
//!
//! These exports are stable across minor versions:
//! - `Citadel` Ã¢â‚¬â€ main encryption engine
//! - `PublicKey`, `SecretKey` Ã¢â‚¬â€ key types with serialization
//! - `Aad`, `Context` Ã¢â‚¬â€ typed metadata (prevents misuse)
//! - `SealError`, `OpenError` Ã¢â‚¬â€ uniform error types
//!
//! Internal modules (`wire`, `kdf`, `aead`, `kem`) are NOT part of the
//! public API and may change without notice.

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use core::fmt;

// Re-export only what customers need
pub use crate::error::DecryptionError as OpenError;
pub use crate::error::EncodingError as SealError;
pub use crate::kem::{PublicKey, SecretKey};

// ---------------------------------------------------------------------------
// Typed AAD and Context (prevents misuse)
// ---------------------------------------------------------------------------

/// Additional Authenticated Data Ã¢â‚¬â€ bound to ciphertext but not encrypted.
///
/// Use the builder methods to construct AAD for common use cases.
/// This prevents accidental misuse and standardizes behavior across deployments.
#[derive(Clone, Debug)]
pub struct Aad {
    inner: Vec<u8>,
}

impl Aad {
    /// Raw AAD from arbitrary bytes.
    ///
    /// Prefer the typed constructors when possible.
    pub fn raw(bytes: &[u8]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// Empty AAD (still authenticated, just zero-length).
    pub fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// AAD for object storage (S3, GCS, etc.)
    ///
    /// Format: `storage|{bucket}|{object_id}|v{version}`
    pub fn for_storage(bucket: &str, object_id: &str, version: u64) -> Self {
        Self {
            inner: format!("storage|{}|{}|v{}", bucket, object_id, version).into_bytes(),
        }
    }

    /// AAD for database field encryption.
    ///
    /// Format: `db|{table}|{row_id}|{column}`
    pub fn for_database(table: &str, row_id: &str, column: &str) -> Self {
        Self {
            inner: format!("db|{}|{}|{}", table, row_id, column).into_bytes(),
        }
    }

    /// AAD for backup/archive encryption.
    ///
    /// Format: `backup|{system}|{timestamp_unix}`
    pub fn for_backup(system: &str, timestamp_unix: u64) -> Self {
        Self {
            inner: format!("backup|{}|{}", system, timestamp_unix).into_bytes(),
        }
    }

    /// AAD for message/envelope encryption.
    ///
    /// Format: `msg|{sender}|{recipient}|{msg_id}`
    pub fn for_message(sender: &str, recipient: &str, msg_id: &str) -> Self {
        Self {
            inner: format!("msg|{}|{}|{}", sender, recipient, msg_id).into_bytes(),
        }
    }

    /// Access the raw bytes.
    ///
    /// Used by `citadel-keystore` to construct domain-bound AADs (P225/P281).
    /// Promoted from `pub(crate)` so cross-crate callers can incorporate AAD
    /// bytes into domain-prefixed constructions without duplicating the inner
    /// representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

/// Domain separation context Ã¢â‚¬â€ distinguishes encryption purposes.
///
/// Context is bound into the key derivation, so ciphertext encrypted
/// with one context cannot be decrypted with another.
///
/// This is your primary defense against cross-protocol attacks.
#[derive(Clone, Debug)]
pub struct Context {
    inner: Vec<u8>,
}

impl Context {
    /// Raw context from arbitrary bytes.
    ///
    /// Prefer the typed constructors when possible.
    pub fn raw(bytes: &[u8]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// Empty context (not recommended for production).
    pub fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Context for a specific application.
    ///
    /// Format: `app|{app_name}|{environment}`
    pub fn for_application(app_name: &str, environment: &str) -> Self {
        Self {
            inner: format!("app|{}|{}", app_name, environment).into_bytes(),
        }
    }

    /// Context for backup/archive operations.
    ///
    /// Format: `backup|{system}|epoch{epoch}`
    pub fn for_backup(system: &str, epoch: u32) -> Self {
        Self {
            inner: format!("backup|{}|epoch{}", system, epoch).into_bytes(),
        }
    }

    /// Context for inter-service communication.
    ///
    /// Format: `service|{from}|{to}|{protocol_version}`
    pub fn for_service(from: &str, to: &str, protocol_version: &str) -> Self {
        Self {
            inner: format!("service|{}|{}|{}", from, to, protocol_version).into_bytes(),
        }
    }

    /// Context for secrets management.
    ///
    /// Format: `secrets|{namespace}|{key_id}`
    pub fn for_secrets(namespace: &str, key_id: &str) -> Self {
        Self {
            inner: format!("secrets|{}|{}", namespace, key_id).into_bytes(),
        }
    }

    /// Access the raw bytes.
    ///
    /// Used by `citadel-keystore` to construct domain-bound contexts (P281).
    /// Promoted from `pub(crate)` — same rationale as `Aad::as_bytes()`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// Main SDK interface
// ---------------------------------------------------------------------------

/// Citadel encryption engine.
///
/// Provides hybrid post-quantum encryption using X25519 + ML-KEM-768.
/// Security holds if *either* primitive remains secure.
///
/// # Example
///
/// ```
/// use citadel_envelope::{Citadel, Aad, Context};
///
/// let citadel = Citadel::new();
/// let (pk, sk) = citadel.generate_keypair();
///
/// let aad = Aad::for_storage("my-bucket", "object-123", 1);
/// let ctx = Context::for_application("myapp", "prod");
///
/// let ciphertext = citadel.seal(&pk, b"secret data", &aad, &ctx).unwrap();
/// let plaintext = citadel.open(&sk, &ciphertext, &aad, &ctx).unwrap();
///
/// assert_eq!(plaintext, b"secret data");
/// ```
pub struct Citadel {
    inner: crate::CitadelEngine,
}

impl Default for Citadel {
    fn default() -> Self {
        Self::new()
    }
}

impl Citadel {
    /// Create a new Citadel instance.
    pub fn new() -> Self {
        Self {
            inner: crate::CitadelEngine::new(),
        }
    }

    /// Generate a new keypair.
    ///
    /// The public key can be shared freely.
    /// The secret key must be protected and should be zeroized when no longer needed.
    pub fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        self.inner.keygen()
    }

    /// Encrypt (seal) plaintext to a public key.
    ///
    /// Both `aad` and `context` are bound to the ciphertext and must match on decryption.
    ///
    /// # Arguments
    ///
    /// * `pk` Ã¢â‚¬â€ recipient's public key
    /// * `plaintext` Ã¢â‚¬â€ data to encrypt (any size)
    /// * `aad` Ã¢â‚¬â€ additional authenticated data (authenticated but not encrypted)
    /// * `context` Ã¢â‚¬â€ domain separation context (bound into key derivation)
    ///
    /// # Returns
    ///
    /// Self-describing ciphertext bytes (minimum 1154 bytes).
    pub fn seal(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, SealError> {
        self.inner
            .encrypt(pk, plaintext, aad.as_bytes(), context.as_bytes())
    }

    /// Decrypt (open) ciphertext using a secret key.
    ///
    /// Both `aad` and `context` must match exactly what was used during encryption.
    ///
    /// # Error Behavior
    ///
    /// Returns an opaque `OpenError` for ALL failure modes:
    /// - Wrong key
    /// - Wrong AAD
    /// - Wrong context
    /// - Tampered ciphertext
    /// - Malformed input
    ///
    /// This uniform behavior prevents oracle attacks.
    pub fn open(
        &self,
        sk: &SecretKey,
        ciphertext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, OpenError> {
        self.inner
            .decrypt(sk, ciphertext, aad.as_bytes(), context.as_bytes())
    }

    /// Create a historical envelope-v1 ciphertext for controlled migrations.
    ///
    /// This API is absent from default builds. It requires the explicit
    /// `legacy-envelope-v1` feature; new application data must use [`Self::seal`].
    #[cfg(feature = "legacy-envelope-v1")]
    pub fn seal_v1_compat(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, SealError> {
        self.inner
            .encrypt_v1_compat(pk, plaintext, aad.as_bytes(), context.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Inspection utilities (for ops/debugging)
// ---------------------------------------------------------------------------

/// Ciphertext metadata (extracted without decryption).
#[derive(Debug, Clone)]
pub struct CiphertextInfo {
    /// Protocol version (1 = historical envelope, 2 = current envelope or legacy stream)
    pub version: u8,
    /// KEM suite identifier
    pub kem_suite: &'static str,
    /// AEAD suite identifier
    pub aead_suite: &'static str,
    /// Total ciphertext length
    pub total_bytes: usize,
    /// Estimated plaintext length (total - overhead). Zero for streaming format
    /// (individual chunk sizes are not known from the stream header alone).
    pub plaintext_bytes: usize,
    /// Whether this is a V2 streaming ciphertext (version = 0x02).
    /// Stream headers do not contain plaintext; use `StreamDecryptor` to decrypt.
    pub streaming: bool,
}

impl fmt::Display for CiphertextInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.streaming {
            write!(
                f,
                "Citadel stream v{} | {} + {} | {} header bytes (streaming)",
                self.version, self.kem_suite, self.aead_suite, self.total_bytes
            )
        } else {
            write!(
                f,
                "Citadel v{} | {} + {} | {} bytes ({} plaintext)",
                self.version,
                self.kem_suite,
                self.aead_suite,
                self.total_bytes,
                self.plaintext_bytes
            )
        }
    }
}

/// Inspect ciphertext metadata without decrypting.
///
/// Handles v2 envelopes, historical v1 envelopes, and legacy v2 stream headers.
/// Returns `streaming = true` only for the legacy stream form.
///
/// Does NOT reveal any secret information.
pub fn inspect(ciphertext: &[u8]) -> Result<CiphertextInfo, OpenError> {
    use crate::wire::{
        check_v1_suites, decode_stream_header, decode_wire_raw, MIN_CIPHERTEXT_BYTES,
        STREAM_VERSION, SUITE_AEAD_AES256GCM, SUITE_KEM_HYBRID_X25519_MLKEM768,
    };

    // Envelope v2 has a complete magic discriminator. It must be checked before
    // the historical byte-based stream-v2 dispatch.
    if ciphertext.starts_with(crate::wire_v2::MAGIC) {
        let parts = crate::wire_v2::decode(ciphertext)?;
        return Ok(CiphertextInfo {
            version: crate::wire_v2::VERSION,
            kem_suite: "X25519+ML-KEM-768",
            aead_suite: "AES-256-GCM",
            total_bytes: ciphertext.len(),
            plaintext_bytes: parts.plaintext_len,
            streaming: false,
        });
    }

    // Route legacy formats on the version byte without consuming the data.
    let version_byte = ciphertext.first().copied().ok_or(OpenError)?;

    if version_byte == STREAM_VERSION {
        // V2 streaming: inspect the stream header.
        let header = decode_stream_header(ciphertext)?;
        let kem_suite = if header.suite_kem == SUITE_KEM_HYBRID_X25519_MLKEM768 {
            "X25519+ML-KEM-768"
        } else {
            "unknown"
        };
        let aead_suite = if header.suite_aead == SUITE_AEAD_AES256GCM {
            "AES-256-GCM"
        } else {
            "unknown"
        };
        return Ok(CiphertextInfo {
            version: header.version,
            kem_suite,
            aead_suite,
            total_bytes: ciphertext.len(),
            // Individual chunk sizes are not visible from the stream header alone.
            plaintext_bytes: 0,
            streaming: true,
        });
    }

    // V1 standard envelope: parse and validate suites.
    let parts = decode_wire_raw(ciphertext)?;
    // Report unknown suites symbolically rather than failing — inspect() is for
    // diagnostics, not decryption, so unknown suites should be visible not hidden.
    let kem_suite = if parts.suite_kem == SUITE_KEM_HYBRID_X25519_MLKEM768 {
        "X25519+ML-KEM-768"
    } else {
        "unknown"
    };
    let aead_suite = if parts.suite_aead == SUITE_AEAD_AES256GCM {
        "AES-256-GCM"
    } else {
        "unknown"
    };

    // Validate suites for the standard path (will err if unrecognised in production).
    check_v1_suites(&parts)?;

    let plaintext_bytes = ciphertext.len().saturating_sub(MIN_CIPHERTEXT_BYTES);

    Ok(CiphertextInfo {
        version: parts.version,
        kem_suite,
        aead_suite,
        total_bytes: ciphertext.len(),
        plaintext_bytes,
        streaming: false,
    })
}

// ---------------------------------------------------------------------------
// Version info
// ---------------------------------------------------------------------------

/// SDK version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Historical envelope-v1 protocol version retained for API compatibility.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Historical envelope-v1 minimum ciphertext size retained for compatibility.
pub const MIN_CIPHERTEXT_BYTES: usize = crate::wire::MIN_CIPHERTEXT_BYTES;

/// Current default non-streaming envelope version.
pub const ENVELOPE_VERSION: u8 = crate::wire_v2::VERSION;

/// Minimum current envelope-v2 size (empty plaintext).
pub const MIN_ENVELOPE_V2_BYTES: usize = crate::wire_v2::MIN_ENVELOPE_LEN;
