//! Shared error type for public primitive APIs.

use core::fmt;

/// Errors returned by post-quantum and AEAD primitive operations.
///
/// Cryptographic failures are intentionally coarse. Callers must not branch on
/// fine-grained failure reasons when handling untrusted input (for example
/// ciphertext forgery vs. wrong key), since that can create padding oracles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A key, nonce, ciphertext, or other fixed-size input had the wrong length.
    InvalidLength,
    /// A key or ciphertext could not be decoded into a valid internal form.
    InvalidEncoding,
    /// Authenticated decryption failed (wrong key, nonce, AAD, or ciphertext).
    AeadFailure,
    /// Signature verification failed or signature encoding was rejected.
    SignatureInvalid,
    /// An operation was refused due to unsafe or out-of-range parameters.
    InvalidParameter,
    /// Freshly generated keypair failed its pair-wise consistency test (PCT).
    PairwiseConsistencyFailure,
}

impl Error {
    /// Stable string for logging without allocating.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLength => "invalid length for cryptographic input",
            Self::InvalidEncoding => "invalid key or ciphertext encoding",
            Self::AeadFailure => "AEAD authentication failed",
            Self::SignatureInvalid => "signature verification failed",
            Self::InvalidParameter => "invalid cryptographic parameter",
            Self::PairwiseConsistencyFailure => {
                "keypair failed pair-wise consistency test"
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Error {}

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors from [`crate::self_test::run_self_tests`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfTestError {
    /// A known-answer (CAST) comparison failed.
    KnownAnswerMismatch {
        /// Which CAST case failed (`"sig"` / `"kem"` / …).
        case: &'static str,
    },
    /// An underlying primitive returned an unexpected [`Error`].
    Primitive(Error),
}

impl fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KnownAnswerMismatch { case } => {
                write!(f, "self-test known-answer mismatch ({case})")
            }
            Self::Primitive(err) => write!(f, "self-test primitive error: {err}"),
        }
    }
}

impl std::error::Error for SelfTestError {}

impl From<Error> for SelfTestError {
    fn from(value: Error) -> Self {
        Self::Primitive(value)
    }
}
