//! Labeled KDF: `enclave-kdf-v1` (SHAKE256 domain-separated).
//!
//! Matches the TypeScript `@enclave/pqc-primitives` construction so Rust and JS
//! SDKs derive identical key material from the same inputs.

use crate::hash::shake256_raw;
use crate::usage::CryptoUsageRecord;

/// Domain-separation prefix for the Enclave labeled KDF.
///
/// Wire format:
/// `SHAKE256( UTF8("enclave-kdf-v1:" || label || ":") || ikm , dkLen )`
pub const KDF_LABEL_PREFIX: &str = "enclave-kdf-v1";

/// Default derived-key length in bytes.
pub const DEFAULT_OUTPUT_BYTES: usize = 32;

/// Algorithm identifier for CBOM / usage records.
pub const ALGORITHM: &str = "enclave-kdf-v1";

/// KDF output plus CBOM usage metadata.
#[derive(Clone, Debug)]
pub struct KdfOutput {
    /// Derived key material.
    pub key: Vec<u8>,
    /// Algorithm / suite / crate metadata for this operation.
    pub usage: CryptoUsageRecord,
}

fn usage(operation: &'static str) -> CryptoUsageRecord {
    CryptoUsageRecord::new(ALGORITHM, operation)
}

/// Derive key material with the `enclave-kdf-v1` labeled SHAKE256 construction.
///
/// # Construction
///
/// ```text
/// domain = UTF-8("enclave-kdf-v1:" || label || ":")
/// output = SHAKE256(domain || ikm, length)
/// ```
///
/// Output length is **not** bound into the SHAKE input; it is only the XOF
/// squeeze length. Different lengths for the same `(label, ikm)` are prefixes
/// of the same stream.
///
/// # Security properties
///
/// Provides domain-separated extraction from arbitrary IKM (for example an
/// ML-KEM shared secret). Labels isolate independent uses of the same IKM.
///
/// # Misuse risks
///
/// - **Choose unique labels** for each key purpose (`"aes-256-gcm-key"`,
///   `"msg-mac"`, …). Reusing a label for two purposes collapses domains.
/// - Avoid embedding raw `:`-heavy untrusted strings in `label` if those
///   strings could collide across products; prefer stable ASCII constants.
/// - This is **not** a password hashing function (no salt/memory hardness).
/// - `length == 0` is rejected.
///
/// # Errors
///
/// Returns [`crate::Error::InvalidParameter`] when `length` is zero or `label`
/// is empty.
pub fn labeled_kdf(label: &str, ikm: &[u8], length: usize) -> crate::Result<KdfOutput> {
    if label.is_empty() || length == 0 {
        return Err(crate::Error::InvalidParameter);
    }
    let mut material = Vec::with_capacity(KDF_LABEL_PREFIX.len() + 1 + label.len() + 1 + ikm.len());
    material.extend_from_slice(KDF_LABEL_PREFIX.as_bytes());
    material.push(b':');
    material.extend_from_slice(label.as_bytes());
    material.push(b':');
    material.extend_from_slice(ikm);
    Ok(KdfOutput {
        key: shake256_raw(&material, length),
        usage: usage("kdf"),
    })
}

/// [`labeled_kdf`] with [`DEFAULT_OUTPUT_BYTES`] (32).
pub fn labeled_kdf_32(label: &str, ikm: &[u8]) -> crate::Result<KdfOutput> {
    labeled_kdf(label, ikm, DEFAULT_OUTPUT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_vector_shape() {
        // Domain bytes for label "test" must start with ASCII enclave-kdf-v1:test:
        let out = labeled_kdf("test", b"ikm", 32).unwrap();
        assert_eq!(out.key.len(), 32);
        let again = labeled_kdf("test", b"ikm", 32).unwrap();
        assert_eq!(out.key, again.key);
        assert_ne!(out.key, labeled_kdf("other", b"ikm", 32).unwrap().key);
        assert_eq!(out.usage.algorithm, ALGORITHM);
    }

    #[test]
    fn longer_output_extends_prefix() {
        let short = labeled_kdf("x", b"y", 16).unwrap();
        let long = labeled_kdf("x", b"y", 48).unwrap();
        assert_eq!(short.key, long.key[..16]);
    }
}
