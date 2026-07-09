// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signing wire format constants for citadel-signer.
//!
//! These constants are distinct from citadel-envelope's wire format constants.
//! Signing produces signatures, not encrypted blobs. The wire formats are orthogonal.

/// ML-DSA-65 (NIST FIPS 204) key and signature sizes.
///
/// Confirmed from ml-dsa source (lib.rs test output_sizes):
///   ML-DSA-65: sk=4032, vk=1952, sig=3309
///
/// Note: We store the 32-byte SEED (not the 4032-byte expanded sk).
/// The expanded signing key is reconstructed from the seed on demand.

/// ML-DSA-65 seed size (what we store) — 32 bytes.
pub const MLDSA65_SEED_BYTES: usize = 32;

/// ML-DSA-65 verifying key (public key) size — 1952 bytes.
pub const MLDSA65_VK_BYTES: usize = 1952;

/// ML-DSA-65 expanded signing key size — 4032 bytes (NOT stored; reconstructed from seed).
pub const MLDSA65_SK_BYTES: usize = 4032;

/// ML-DSA-65 signature size — 3309 bytes.
pub const MLDSA65_SIG_BYTES: usize = 3309;

/// Suite identifier byte for ML-DSA-65 in the Citadel Native Assertion format.
pub const SUITE_SIGNING_MLDSA65: u8 = 0xD1;

/// Version string for the Citadel Native Assertion format.
pub const CNA_VERSION: &str = "cna-v1";
