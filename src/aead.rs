//! AES-256-GCM authenticated encryption (FIPS 197 / SP 800-38D).
//!
//! Nonces are always caller-supplied. This module never invents a nonce behind
//! the caller's back, so nonce reuse cannot happen silently inside the library.

use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

type AesNonce = Nonce<U12>;

/// Algorithm identifier for the Enclave suite registry.
pub const ALGORITHM: &str = "AES-256-GCM";

/// AES-256-GCM key length in bytes.
pub const KEY_BYTES: usize = 32;

/// AES-GCM nonce (IV) length in bytes. Always 96 bits for this module.
pub const NONCE_BYTES: usize = 12;

/// Authentication tag length in bytes (appended to ciphertext by `aes-gcm`).
pub const TAG_BYTES: usize = 16;

/// Result of AES-256-GCM encryption.
///
/// The ciphertext bytes include the 16-byte authentication tag suffix produced
/// by the RustCrypto `aes-gcm` crate.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct EncryptResult {
    /// Ciphertext || tag.
    pub ciphertext: Vec<u8>,
}

fn cipher_from_key(key: &[u8]) -> Result<Aes256Gcm> {
    if key.len() != KEY_BYTES {
        return Err(Error::InvalidLength);
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidLength)
}

fn nonce_from_slice(nonce: &[u8]) -> Result<&AesNonce> {
    if nonce.len() != NONCE_BYTES {
        return Err(Error::InvalidLength);
    }
    Ok(AesNonce::from_slice(nonce))
}

/// Encrypt plaintext with AES-256-GCM under an explicit key and nonce.
///
/// # Security properties
///
/// Provides confidentiality and integrity for `plaintext` and integrity for
/// optional `aad` (associated data that is authenticated but not encrypted).
///
/// # Misuse risks
///
/// - **Never reuse a `(key, nonce)` pair.** Reusing a nonce under the same key
///   destroys confidentiality and can leak the authentication key. Callers must
///   generate unique nonces (for example via a counter or fresh CSPRNG bytes)
///   and persist them with the ciphertext.
/// - This function deliberately does **not** generate a nonce for you, so a
///   reused nonce cannot be introduced silently inside this crate.
/// - Keys must be 32 uniform bytes (for example from ML-KEM + [`crate::kdf`]).
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] for wrong key/nonce sizes, or
/// [`Error::AeadFailure`] if the underlying cipher reports an error.
pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<EncryptResult> {
    let cipher = cipher_from_key(key)?;
    let nonce = nonce_from_slice(nonce)?;
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AeadFailure)?;
    Ok(EncryptResult { ciphertext })
}

/// Decrypt AES-256-GCM ciphertext (including the trailing tag) under an
/// explicit key and nonce.
///
/// # Security properties
///
/// Verifies authenticity of `ciphertext` and `aad` before returning plaintext.
/// On failure, no plaintext is released.
///
/// # Misuse risks
///
/// - `nonce` and `aad` must be exactly the values used during encryption.
/// - Treat any error as authentication failure; do not leak timing differences
///   between "bad tag" and "bad length" to untrusted callers when avoidable.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] or [`Error::AeadFailure`].
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_BYTES {
        return Err(Error::InvalidLength);
    }
    let cipher = cipher_from_key(key)?;
    let nonce = nonce_from_slice(nonce)?;
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AeadFailure)
}

/// Convenience helper that validates a key length without allocating a cipher.
///
/// Returns the key as a RustCrypto [`Key`] reference when the length is exact.
///
/// # Misuse risks
///
/// Prefer [`encrypt`] / [`decrypt`]. This helper exists for callers that already
/// manage `Aes256Gcm` instances carefully.
pub fn key_from_slice(key: &[u8]) -> Result<&Key<Aes256Gcm>> {
    if key.len() != KEY_BYTES {
        return Err(Error::InvalidLength);
    }
    Ok(Key::<Aes256Gcm>::from_slice(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_aad() {
        let key = [0x11u8; KEY_BYTES];
        let nonce = [0x22u8; NONCE_BYTES];
        let plaintext = b"confidential";
        let aad = b"header";

        let enc = encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
        let dec = decrypt(&key, &nonce, &enc.ciphertext, aad).expect("decrypt");
        assert_eq!(dec, plaintext);
        assert!(decrypt(&key, &nonce, &enc.ciphertext, b"other").is_err());
    }

    #[test]
    fn rejects_wrong_nonce_length() {
        let key = [0u8; KEY_BYTES];
        let err = encrypt(&key, &[0u8; 11], b"x", b"").unwrap_err();
        assert_eq!(err, Error::InvalidLength);
    }
}
