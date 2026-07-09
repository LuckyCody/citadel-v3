// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unified error types for Citadel Envelope.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionError;

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decryption failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecryptionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingError;

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encoding error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodingError {}

/// Normalize encode errors into decrypt errors (oracle discipline).
impl From<EncodingError> for DecryptionError {
    fn from(_: EncodingError) -> Self {
        DecryptionError
    }
}
