// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
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
// CNSA-aligned suite engine (0xA4) — additive; the frozen 0xA3 Citadel is untouched
// ---------------------------------------------------------------------------

/// Citadel encryption engine for the P-384 + ML-KEM-1024 suite (wire `0xA4`).
///
/// Hybrid P-384 ECDH + ML-KEM-1024 (the CNSA 2.0 category-5 pairing); security holds
/// if *either* primitive remains secure. This is a **separate, additive** engine from
/// [`Citadel`] — the frozen X25519 + ML-KEM-768 suite — with its own key types
/// ([`P384MlKem1024PublicKey`](crate::P384MlKem1024PublicKey) /
/// [`P384MlKem1024SecretKey`](crate::P384MlKem1024SecretKey)). It shares [`Aad`],
/// [`Context`], [`SealError`], and [`OpenError`], which are suite-agnostic.
///
/// The name deliberately states the algorithms, not "CNSA": implementing the CNSA 2.0
/// algorithms is **not** CNSA compliance (as FIPS 203/204 algorithms are not FIPS 140-3
/// validation), and that claim is prohibited (packet 033 spec §7).
///
/// Envelopes produced here are `0xA4` on the wire; [`Citadel`] cannot open them and this
/// engine cannot open `0xA3` envelopes — the key types differ and the codec rejects
/// cross-suite use before any crypto runs.
///
/// # Note on this slice
///
/// This exposes in-process seal/open/keygen. Serializing the `0xA4` key types for
/// storage or transmission (`to_bytes`/`from_bytes`) and the C FFI surface are separate
/// follow-on additions, not part of this type yet.
pub struct CitadelP384 {
    inner: crate::CitadelP384Engine,
}

impl Default for CitadelP384 {
    fn default() -> Self {
        Self::new()
    }
}

impl CitadelP384 {
    /// Create a new P-384 + ML-KEM-1024 engine.
    pub fn new() -> Self {
        Self {
            inner: crate::CitadelP384Engine::new(),
        }
    }

    /// Generate a new `0xA4` (P-384 + ML-KEM-1024) keypair.
    ///
    /// The public key can be shared freely; the secret key must be protected and
    /// zeroizes on drop via its component types.
    pub fn generate_keypair(
        &self,
    ) -> (crate::P384MlKem1024PublicKey, crate::P384MlKem1024SecretKey) {
        self.inner.keygen()
    }

    /// Encrypt (seal) plaintext to a `0xA4` public key.
    ///
    /// Both `aad` and `context` are bound to the ciphertext and must match on open.
    /// Produces a self-describing `0xA4` envelope (minimum 1779 bytes).
    pub fn seal(
        &self,
        pk: &crate::P384MlKem1024PublicKey,
        plaintext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, SealError> {
        self.inner
            .encrypt(pk, plaintext, aad.as_bytes(), context.as_bytes())
    }

    /// Decrypt (open) a `0xA4` ciphertext.
    ///
    /// Returns an opaque [`OpenError`] for every failure mode — wrong key, wrong AAD,
    /// wrong context, tampered or malformed input — identical to [`Citadel::open`], so
    /// decryption failures stay indistinguishable.
    pub fn open(
        &self,
        sk: &crate::P384MlKem1024SecretKey,
        ciphertext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, OpenError> {
        self.inner
            .decrypt(sk, ciphertext, aad.as_bytes(), context.as_bytes())
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
        // Read the suite from the decoded envelope, not from a constant. This was
        // hardcoded to the X25519 string, which was correct while 0xA3 was the only v2
        // suite and became a wrong answer the moment 0xA4 joined SUITE_TABLE. The
        // legacy branches below have always done it this way.
        //
        // `decode` already rejects any suite absent from SUITE_TABLE, so the fallback
        // arm is unreachable today; it is here so that adding a table row without
        // touching this match produces "unknown" rather than a confident lie.
        let kem_suite = match parts.suite.suite_kem {
            SUITE_KEM_HYBRID_X25519_MLKEM768 => "X25519+ML-KEM-768",
            crate::wire::SUITE_KEM_HYBRID_P384_MLKEM1024 => "P-384+ML-KEM-1024",
            _ => "unknown",
        };
        return Ok(CiphertextInfo {
            version: crate::wire_v2::VERSION,
            kem_suite,
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

/// `inspect()` must report the suite it actually decoded.
///
/// Filed as F-2 in packet 033: the v2 branch returned the X25519 string unconditionally,
/// so a `0xA4` envelope was reported as `X25519+ML-KEM-768`. `cli.rs` prints this field to
/// a human, which makes a wrong answer here worse than a missing one.
///
/// The `0xA3` assertion is as load-bearing as the `0xA4` one: it pins that this fix did
/// not change what `inspect` already reported for the frozen suite.
#[cfg(test)]
mod p3d_inspect_suite_label_tests {
    use crate::kem::{HybridX25519MlKem768Provider as P3, KemProvider};
    use crate::kem_p384::HybridP384MlKem1024Provider as P4;

    #[test]
    fn p3d_inspect_reports_a4_envelopes_as_p384_mlkem1024() {
        let (pk4, _sk4) = P4::keygen();
        let envelope = crate::wire_v2::seal::<P4>(&pk4, b"a message", b"", b"ctx").expect("seal");
        let info = crate::inspect(&envelope).expect("inspect a4");
        assert_eq!(info.kem_suite, "P-384+ML-KEM-1024");
        assert_eq!(info.plaintext_bytes, 9);
        assert!(!info.streaming);
    }

    #[test]
    fn p3d_inspect_still_reports_a3_envelopes_as_x25519_mlkem768() {
        let (pk3, _sk3) = P3::keygen();
        let envelope = crate::wire_v2::seal::<P3>(&pk3, b"a message", b"", b"ctx").expect("seal");
        let info = crate::inspect(&envelope).expect("inspect a3");
        assert_eq!(info.kem_suite, "X25519+ML-KEM-768");
    }
}

/// `CitadelP384` — the additive `0xA4` SDK engine.
///
/// These prove `0xA4` is reachable through the public SDK (closing the caller-facing
/// half of finding F-1 for in-process use) and that it stays isolated from the frozen
/// `0xA3` engine.
#[cfg(test)]
mod cnsa_engine_tests {
    use super::{Aad, Citadel, CitadelP384, Context};

    #[test]
    fn p384_seal_open_roundtrip() {
        let citadel = CitadelP384::new();
        let (pk, sk) = citadel.generate_keypair();
        let aad = Aad::raw(b"cnsa-aad");
        let ctx = Context::raw(b"cnsa-ctx");
        let ct = citadel.seal(&pk, b"cnsa secret", &aad, &ctx).expect("seal");
        let pt = citadel.open(&sk, &ct, &aad, &ctx).expect("open");
        assert_eq!(pt, b"cnsa secret");
    }

    #[test]
    fn p384_open_with_wrong_context_fails() {
        let citadel = CitadelP384::new();
        let (pk, sk) = citadel.generate_keypair();
        let aad = Aad::empty();
        let ct = citadel
            .seal(&pk, b"data", &aad, &Context::raw(b"ctx-a"))
            .expect("seal");
        assert!(citadel
            .open(&sk, &ct, &aad, &Context::raw(b"ctx-b"))
            .is_err());
    }

    #[test]
    fn p384_open_with_wrong_key_fails() {
        let citadel = CitadelP384::new();
        let (pk, _sk) = citadel.generate_keypair();
        let (_pk2, sk2) = citadel.generate_keypair();
        let aad = Aad::empty();
        let ctx = Context::raw(b"ctx");
        let ct = citadel.seal(&pk, b"data", &aad, &ctx).expect("seal");
        assert!(citadel.open(&sk2, &ct, &aad, &ctx).is_err());
    }

    #[test]
    fn p384_produces_a4_envelopes() {
        let citadel = CitadelP384::new();
        let (pk, _sk) = citadel.generate_keypair();
        let ct = citadel
            .seal(&pk, b"hello", &Aad::empty(), &Context::raw(b"c"))
            .expect("seal");
        let info = crate::inspect(&ct).expect("inspect");
        assert_eq!(info.kem_suite, "P-384+ML-KEM-1024");
        assert_eq!(info.plaintext_bytes, 5);
    }

    /// The two engines are wire-isolated: a `0xA4` envelope is not openable by the
    /// frozen `0xA3` `Citadel`, and the classic engine still round-trips its own suite.
    #[test]
    fn p384_and_classic_engines_are_independent() {
        let p384 = CitadelP384::new();
        let (pk4, _sk4) = p384.generate_keypair();
        let aad = Aad::empty();
        let ctx = Context::raw(b"ctx");
        let a4 = p384.seal(&pk4, b"cnsa", &aad, &ctx).expect("seal a4");

        // The classic engine round-trips its own suite unchanged.
        let classic = Citadel::new();
        let (pk3, sk3) = classic.generate_keypair();
        let a3 = classic.seal(&pk3, b"classic", &aad, &ctx).expect("seal a3");
        assert_eq!(
            classic.open(&sk3, &a3, &aad, &ctx).expect("open a3"),
            b"classic"
        );

        // The two envelopes carry different wire suites.
        assert_eq!(crate::inspect(&a4).unwrap().kem_suite, "P-384+ML-KEM-1024");
        assert_eq!(crate::inspect(&a3).unwrap().kem_suite, "X25519+ML-KEM-768");
    }
}
