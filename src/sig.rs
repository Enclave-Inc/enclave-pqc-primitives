//! ML-DSA-65 (FIPS 204) digital signatures.
//!
//! Default [`sign`] / [`verify`] use the FIPS 204 external interface with an
//! empty context string and the optional deterministic signing variant
//! (matching the RustCrypto `Signer` implementation). Use
//! [`sign_deterministic`] / [`verify_with_context`] for NIST ACVP cases that
//! supply a non-empty context.

use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair as _, MlDsa65, Signature, SignatureEncoding, SigningKey,
    VerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// Algorithm identifier for the Enclave suite registry.
pub const ALGORITHM: &str = "ML-DSA-65";

/// Encoded ML-DSA-65 verifying (public) key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 1952;

/// Preferred ML-DSA-65 signing-key seed length in bytes.
pub const SECRET_KEY_SEED_BYTES: usize = 32;

/// Expanded ML-DSA-65 signing key length (NIST ACVP `sk`).
pub const SECRET_KEY_EXPANDED_BYTES: usize = 4032;

/// Encoded ML-DSA-65 signature length in bytes.
pub const SIGNATURE_BYTES: usize = 3309;

/// Maximum FIPS 204 context string length in bytes.
pub const MAX_CONTEXT_BYTES: usize = 255;

/// An ML-DSA-65 keypair.
///
/// # Security
///
/// The secret-key seed is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    /// FIPS 204 verifying key (`pk`), [`PUBLIC_KEY_BYTES`] long.
    pub public_key: Vec<u8>,
    /// Preferred 32-byte seed form of the signing key (`sk`).
    pub secret_key: Vec<u8>,
}

/// Generate a fresh ML-DSA-65 keypair using the operating system's CSPRNG.
///
/// # Security properties
///
/// Provides EUF-CMA security at NIST category 3 under the ML-DSA assumptions.
///
/// # Misuse risks
///
/// - Treat `secret_key` as long-term signing authority.
/// - Prefer the seed encoding returned here over expanded secret-key blobs.
#[must_use]
pub fn generate_keypair() -> Keypair {
    let sk = SigningKey::<MlDsa65>::generate();
    Keypair {
        public_key: sk.verifying_key().to_bytes().to_vec(),
        secret_key: sk.to_bytes().to_vec(),
    }
}

/// Derive an ML-DSA-65 keypair from a 32-byte seed.
///
/// Used for NIST ACVP keyGen KATs. Production callers should prefer
/// [`generate_keypair`].
///
/// # Misuse risks
///
/// Seeds must be uniformly random. Reused seeds allow signature forgery for
/// every message signed under that key.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `seed` is not 32 bytes.
pub fn keypair_from_seed(seed: &[u8]) -> Result<Keypair> {
    if seed.len() != SECRET_KEY_SEED_BYTES {
        return Err(Error::InvalidLength);
    }
    let sk = SigningKey::<MlDsa65>::new_from_slice(seed).map_err(|_| Error::InvalidLength)?;
    Ok(Keypair {
        public_key: sk.verifying_key().to_bytes().to_vec(),
        secret_key: sk.to_bytes().to_vec(),
    })
}

/// Return the expanded signing-key encoding for a seed-form secret key.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `secret_key` is not a 32-byte seed.
pub fn expanded_secret_key(secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk = SigningKey::<MlDsa65>::new_from_slice(secret_key).map_err(|_| Error::InvalidLength)?;
    #[allow(deprecated)]
    Ok(sk.expanded_key().to_expanded().to_vec())
}

/// Sign a message with an empty context (FIPS 204 external interface).
///
/// # Security properties
///
/// Uses the optional **deterministic** ML-DSA.Sign variant (empty `rnd` /
/// empty context), as implemented by RustCrypto's `Signer` for ML-DSA.
/// Signing the same `(secret_key, message)` pair always yields the same
/// signature.
///
/// # Misuse risks
///
/// - For hedged/randomized signatures or non-empty contexts, use
///   [`sign_deterministic`] (context) or a future hedged API — do not assume
///   this matches ACVP cases with non-empty `context` or non-zero `rnd`.
/// - `secret_key` must be the 32-byte seed from [`generate_keypair`].
pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    sign_deterministic(secret_key, message, &[])
}

/// Deterministic ML-DSA.Sign with an explicit context string.
///
/// # Security properties
///
/// Matches FIPS 204 Algorithm 2 (deterministic variant) for the external
/// interface. Required to reproduce NIST ACVP sigGen vectors that supply
/// `context`.
///
/// # Misuse risks
///
/// - Context strings isolate domains; reuse of `(sk, message, context)` is
///   expected for this deterministic mode but still leaks that the same
///   message was signed twice.
/// - `context` must be at most [`MAX_CONTEXT_BYTES`] bytes.
/// - `secret_key` may be a 32-byte seed or a 4032-byte expanded ACVP `sk`.
pub fn sign_deterministic(secret_key: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    if message.is_empty() {
        return Err(Error::InvalidLength);
    }
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(Error::InvalidParameter);
    }
    let signature = match secret_key.len() {
        SECRET_KEY_SEED_BYTES => {
            let sk = SigningKey::<MlDsa65>::new_from_slice(secret_key)
                .map_err(|_| Error::InvalidLength)?;
            sk.expanded_key()
                .sign_deterministic(message, context)
                .map_err(|_| Error::InvalidEncoding)?
        }
        SECRET_KEY_EXPANDED_BYTES => {
            #[allow(deprecated)]
            let sk = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_expanded(
                &secret_key.try_into().map_err(|_| Error::InvalidLength)?,
            );
            sk.sign_deterministic(message, context)
                .map_err(|_| Error::InvalidEncoding)?
        }
        _ => return Err(Error::InvalidLength),
    };
    Ok(signature.to_bytes().as_slice().to_vec())
}

/// Verify an ML-DSA-65 signature with an empty context.
///
/// # Security properties
///
/// Returns `Ok(())` only when `signature` is valid under `public_key` for
/// `message` with empty context.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    verify_with_context(public_key, message, signature, &[])
}

/// Verify an ML-DSA-65 signature with an explicit context string.
///
/// # Security properties
///
/// Implements FIPS 204 `ML-DSA.Verify` (external, pure). Used by NIST ACVP
/// sigVer vectors.
///
/// # Misuse risks
///
/// - Context must match the value used during signing.
/// - Do not parse application structure out of a signed blob before verifying.
pub fn verify_with_context(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<()> {
    if public_key.is_empty() || message.is_empty() || signature.is_empty() {
        return Err(Error::InvalidLength);
    }
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(Error::InvalidLength);
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(Error::InvalidLength);
    }
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(Error::InvalidParameter);
    }

    let vk =
        VerifyingKey::<MlDsa65>::new_from_slice(public_key).map_err(|_| Error::InvalidEncoding)?;
    let sig = Signature::<MlDsa65>::try_from(signature).map_err(|_| Error::InvalidEncoding)?;
    if vk.verify_with_context(message, context, &sig) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}
