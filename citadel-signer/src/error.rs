// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Error types for citadel-signer.

use std::fmt;

/// Error from a signing operation.
#[derive(Debug, Clone)]
pub struct SignError(pub String);

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignError: {}", self.0)
    }
}

impl std::error::Error for SignError {}

/// Error from a verification operation.
#[derive(Debug, Clone)]
pub struct VerifyError(pub String);

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyError: {}", self.0)
    }
}

impl std::error::Error for VerifyError {}

/// Error from an assertion operation (issue or verify).
#[derive(Debug, Clone)]
pub struct AssertionError(pub String);

impl fmt::Display for AssertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AssertionError: {}", self.0)
    }
}

impl std::error::Error for AssertionError {}
