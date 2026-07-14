//! ML-DSA-87 (FIPS 204) digital signatures — NIST Category 5 / CNSA 2.0.
//!
//! Default [`sign`] / [`verify`] use the FIPS 204 external interface with an
//! empty context string and the optional deterministic signing variant
//! (matching the RustCrypto `Signer` implementation). Use
//! [`sign_deterministic`] / [`verify_with_context`] when a non-empty context
//! is required.

use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair as _, MlDsa87, Signature, SignatureEncoding, SigningKey,
    VerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::usage::CryptoUsageRecord;
use crate::{Error, Result};

/// Algorithm identifier (explicit Category 5 parameter set).
pub const ALGORITHM: &str = "ML-DSA-87";

/// Encoded ML-DSA-87 verifying (public) key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 2592;

/// Preferred ML-DSA-87 signing-key seed length in bytes.
pub const SECRET_KEY_SEED_BYTES: usize = 32;

/// Expanded ML-DSA-87 signing key length (FIPS 204 `sk`).
pub const SECRET_KEY_EXPANDED_BYTES: usize = 4896;

/// Alias for the FIPS expanded secret-key size ([`SECRET_KEY_EXPANDED_BYTES`]).
pub const SECRET_KEY_BYTES: usize = SECRET_KEY_EXPANDED_BYTES;

/// Encoded ML-DSA-87 signature length in bytes.
pub const SIGNATURE_BYTES: usize = 4627;

/// Maximum FIPS 204 context string length in bytes.
pub const MAX_CONTEXT_BYTES: usize = 255;

/// Fixed message used by the pair-wise consistency test after keygen.
const PCT_MESSAGE: &[u8] = b"enclave-pqc-sig-pct-v1";

/// An ML-DSA-87 keypair.
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

/// Keypair plus CBOM usage metadata.
#[derive(Clone)]
pub struct KeypairOutput {
    /// Fresh keypair that passed its PCT.
    pub keypair: Keypair,
    /// Algorithm / suite / crate metadata for this operation.
    pub usage: CryptoUsageRecord,
}

/// Signature plus CBOM usage metadata.
#[derive(Clone, Debug)]
pub struct SignOutput {
    /// Encoded signature ([`SIGNATURE_BYTES`] long).
    pub signature: Vec<u8>,
    /// Algorithm / suite / crate metadata for this operation.
    pub usage: CryptoUsageRecord,
}

/// Verify result plus CBOM usage metadata.
#[derive(Clone, Copy, Debug)]
pub struct VerifyOutput {
    /// Algorithm / suite / crate metadata for this operation.
    pub usage: CryptoUsageRecord,
}

fn usage(operation: &'static str) -> CryptoUsageRecord {
    CryptoUsageRecord::new(ALGORITHM, operation)
}

fn generate_keypair_unchecked() -> Keypair {
    let sk = SigningKey::<MlDsa87>::generate();
    Keypair {
        public_key: sk.verifying_key().to_bytes().to_vec(),
        secret_key: sk.to_bytes().to_vec(),
    }
}

fn pairwise_consistency(keypair: &Keypair) -> Result<()> {
    let signature = sign_unchecked(&keypair.secret_key, PCT_MESSAGE, &[])?;
    verify_unchecked(&keypair.public_key, PCT_MESSAGE, &signature, &[])
}

/// Generate a fresh ML-DSA-87 keypair using the operating system's CSPRNG.
///
/// After generation, a pair-wise consistency test (PCT) sign/verify round-trip
/// must succeed before the keypair is returned. Failure yields
/// [`Error::PairwiseConsistencyFailure`].
///
/// # Security properties
///
/// Provides EUF-CMA security at NIST Category 5 under the ML-DSA assumptions
/// (CNSA 2.0 algorithm requirement for digital signatures).
pub fn generate_keypair() -> Result<KeypairOutput> {
    let keypair = generate_keypair_unchecked();
    pairwise_consistency(&keypair).map_err(|err| match err {
        Error::SignatureInvalid | Error::InvalidEncoding | Error::InvalidLength => {
            Error::PairwiseConsistencyFailure
        }
        other => other,
    })?;
    Ok(KeypairOutput {
        keypair,
        usage: usage("sig_generate_keypair"),
    })
}

/// Derive an ML-DSA-87 keypair from a 32-byte seed.
///
/// Used for known-answer / self-tests. Production callers should prefer
/// [`generate_keypair`]. A PCT still runs before return.
pub fn keypair_from_seed(seed: &[u8]) -> Result<KeypairOutput> {
    let keypair = keypair_from_seed_unchecked(seed)?;
    pairwise_consistency(&keypair).map_err(|err| match err {
        Error::SignatureInvalid | Error::InvalidEncoding | Error::InvalidLength => {
            Error::PairwiseConsistencyFailure
        }
        other => other,
    })?;
    Ok(KeypairOutput {
        keypair,
        usage: usage("sig_keypair_from_seed"),
    })
}

/// Deterministic keygen **without** PCT — for self-test KATs only.
pub(crate) fn keypair_from_seed_unchecked(seed: &[u8]) -> Result<Keypair> {
    if seed.len() != SECRET_KEY_SEED_BYTES {
        return Err(Error::InvalidLength);
    }
    let sk = SigningKey::<MlDsa87>::new_from_slice(seed).map_err(|_| Error::InvalidLength)?;
    Ok(Keypair {
        public_key: sk.verifying_key().to_bytes().to_vec(),
        secret_key: sk.to_bytes().to_vec(),
    })
}

/// Return the expanded signing-key encoding for a seed-form secret key.
pub fn expanded_secret_key(secret_key: &[u8]) -> Result<(Vec<u8>, CryptoUsageRecord)> {
    let sk = SigningKey::<MlDsa87>::new_from_slice(secret_key).map_err(|_| Error::InvalidLength)?;
    #[allow(deprecated)]
    Ok((
        sk.expanded_key().to_expanded().to_vec(),
        usage("sig_expanded_secret_key"),
    ))
}

/// Sign a message with an empty context (FIPS 204 external interface).
///
/// Uses the optional **deterministic** ML-DSA.Sign variant (empty `rnd` /
/// empty context), as implemented by RustCrypto's `Signer` for ML-DSA.
pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<SignOutput> {
    sign_deterministic(secret_key, message, &[])
}

/// Deterministic ML-DSA.Sign with an explicit context string.
pub fn sign_deterministic(secret_key: &[u8], message: &[u8], context: &[u8]) -> Result<SignOutput> {
    Ok(SignOutput {
        signature: sign_unchecked(secret_key, message, context)?,
        usage: usage("sig_sign"),
    })
}

pub(crate) fn sign_unchecked(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    if message.is_empty() {
        return Err(Error::InvalidLength);
    }
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(Error::InvalidParameter);
    }
    let signature = match secret_key.len() {
        SECRET_KEY_SEED_BYTES => {
            let sk = SigningKey::<MlDsa87>::new_from_slice(secret_key)
                .map_err(|_| Error::InvalidLength)?;
            sk.expanded_key()
                .sign_deterministic(message, context)
                .map_err(|_| Error::InvalidEncoding)?
        }
        SECRET_KEY_EXPANDED_BYTES => {
            #[allow(deprecated)]
            let sk = ml_dsa::ExpandedSigningKey::<MlDsa87>::from_expanded(
                &secret_key.try_into().map_err(|_| Error::InvalidLength)?,
            );
            sk.sign_deterministic(message, context)
                .map_err(|_| Error::InvalidEncoding)?
        }
        _ => return Err(Error::InvalidLength),
    };
    Ok(signature.to_bytes().as_slice().to_vec())
}

/// Verify an ML-DSA-87 signature with an empty context.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<VerifyOutput> {
    verify_with_context(public_key, message, signature, &[])
}

/// Verify an ML-DSA-87 signature with an explicit context string.
pub fn verify_with_context(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<VerifyOutput> {
    verify_unchecked(public_key, message, signature, context)?;
    Ok(VerifyOutput {
        usage: usage("sig_verify"),
    })
}

pub(crate) fn verify_unchecked(
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
        VerifyingKey::<MlDsa87>::new_from_slice(public_key).map_err(|_| Error::InvalidEncoding)?;
    let sig = Signature::<MlDsa87>::try_from(signature).map_err(|_| Error::InvalidEncoding)?;
    if vk.verify_with_context(message, context, &sig) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips_204_category_5() {
        assert_eq!(PUBLIC_KEY_BYTES, 2592);
        assert_eq!(SECRET_KEY_BYTES, 4896);
        assert_eq!(SIGNATURE_BYTES, 4627);
    }

    #[test]
    fn generate_runs_pct() {
        let out = generate_keypair().expect("keygen");
        assert_eq!(out.keypair.public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(out.keypair.secret_key.len(), SECRET_KEY_SEED_BYTES);
        assert_eq!(out.usage.algorithm, ALGORITHM);
    }
}
