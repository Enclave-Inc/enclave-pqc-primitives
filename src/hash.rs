//! SHAKE256 extendable-output hash (FIPS 202).
//!
//! Provides a one-shot hash helper and a raw XOF wrapper for variable-length
//! absorb/squeeze usage (KDF building blocks, transcripts, commitments).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Algorithm identifier for the Enclave suite registry.
pub const ALGORITHM: &str = "SHAKE256";

/// Default output length in bytes for [`shake256`] when callers want a
/// fixed-size digest-like value.
pub const DEFAULT_OUTPUT_BYTES: usize = 32;

/// One-shot SHAKE256 hash of `input` into `output_len` bytes.
///
/// # Security properties
///
/// SHAKE256 is a XOF based on Keccak. Different `output_len` values for the
/// same `input` produce prefixes of the same infinite output stream.
///
/// # Misuse risks
///
/// - This is **not** a password KDF. Do not hash passwords with SHAKE alone.
/// - Truncating output below 32 bytes weakens collision resistance; keep
///   `output_len >= 32` for general hashing unless a protocol specifies otherwise.
/// - Domain-separate distinct protocol fields (see [`crate::kdf::labeled_kdf`])
///   instead of hashing concatenated untyped blobs when possible.
///
/// # Panics
///
/// Panics if allocating the output buffer fails (standard `Vec` allocation).
#[must_use]
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof().read(&mut output);
    output
}

/// Absorb-only helper that hashes UTF-8 text with SHAKE256.
///
/// Equivalent to [`shake256`] over `value.as_bytes()`.
#[must_use]
pub fn hash_utf8(value: &str, output_len: usize) -> Vec<u8> {
    shake256(value.as_bytes(), output_len)
}

/// Raw SHAKE256 XOF state for incremental absorb/squeeze.
///
/// # Security properties
///
/// Matches FIPS 202 SHAKE256. After the first squeeze, further absorbs are not
/// supported by this wrapper (callers should create a new [`Shake256Xof`]).
///
/// # Misuse risks
///
/// - Do not reuse a squeezed XOF for a new logical hash; start fresh.
/// - Encode lengths or delimiters when absorbing multiple variable-length
///   fields, or use [`crate::kdf::labeled_kdf`] for key derivation.
#[derive(Clone, Default)]
pub struct Shake256Xof {
    inner: Shake256,
    finalized: bool,
}

impl Shake256Xof {
    /// Create an empty SHAKE256 XOF state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb additional input bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidParameter`] if squeeze has already begun.
    pub fn update(&mut self, data: &[u8]) -> crate::Result<()> {
        if self.finalized {
            return Err(crate::Error::InvalidParameter);
        }
        self.inner.update(data);
        Ok(())
    }

    /// Squeeze `output_len` bytes and consume this XOF instance.
    ///
    /// # Security properties
    ///
    /// Subsequent calls are impossible because `self` is consumed; this prevents
    /// accidental continued absorption after output has been released.
    #[must_use]
    pub fn finalize_xof(self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        self.inner.finalize_xof().read(&mut output);
        output
    }

    /// Squeeze into a caller-provided buffer and consume this XOF instance.
    pub fn finalize_xof_into(self, output: &mut [u8]) {
        self.inner.finalize_xof().read(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_length_prefix() {
        let a = shake256(b"abc", 32);
        let b = shake256(b"abc", 64);
        assert_eq!(a, b[..32]);
        assert_ne!(a, shake256(b"abd", 32));
    }

    #[test]
    fn xof_matches_oneshot() {
        let mut xof = Shake256Xof::new();
        xof.update(b"hello").unwrap();
        xof.update(b" world").unwrap();
        let out = xof.finalize_xof(48);
        assert_eq!(out, shake256(b"hello world", 48));
    }
}
