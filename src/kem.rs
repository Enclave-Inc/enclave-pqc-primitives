//! ML-KEM-768 (FIPS 203) key encapsulation.
//!
//! Secret keys accept the preferred 64-byte seed form (from
//! [`generate_keypair`] / [`keypair_from_seed`]) or the legacy FIPS expanded
//! encoding (2400 bytes) used by NIST ACVP vectors.

use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit, TryKeyInit};
use ml_kem::{array::Array, DecapsulationKey, EncapsulationKey, MlKem768, Seed, B32};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// Algorithm identifier for the Enclave suite registry.
pub const ALGORITHM: &str = "ML-KEM-768";

/// Encoded ML-KEM-768 encapsulation (public) key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 1184;

/// Preferred ML-KEM-768 decapsulation-key seed length in bytes (`d || z`).
pub const SECRET_KEY_SEED_BYTES: usize = 64;

/// Legacy expanded ML-KEM-768 decapsulation key length (NIST ACVP `dk`).
pub const SECRET_KEY_EXPANDED_BYTES: usize = 2400;

/// ML-KEM-768 ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = 1088;

/// Shared secret length in bytes (always 32 for ML-KEM).
pub const SHARED_SECRET_BYTES: usize = 32;

/// Encapsulation randomness `m` length in bytes (FIPS 203).
pub const ENCAP_RANDOMNESS_BYTES: usize = 32;

/// An ML-KEM-768 keypair.
///
/// # Security
///
/// The secret-key seed is zeroized on drop. Do not copy raw secret-key bytes
/// into long-lived buffers unless those buffers are also zeroized.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    /// FIPS 203 encapsulation key (`ek`), [`PUBLIC_KEY_BYTES`] long.
    pub public_key: Vec<u8>,
    /// Preferred 64-byte seed form of the decapsulation key (`dk`).
    pub secret_key: Vec<u8>,
}

/// Result of encapsulating to an ML-KEM-768 public key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Encapsulation {
    /// Ciphertext to send to the holder of the secret key.
    pub ciphertext: Vec<u8>,
    /// Shared secret. Treat as uniform IKM and feed through a KDF before use
    /// as an AES key unless a higher-level protocol specifies otherwise.
    pub shared_secret: Vec<u8>,
}

fn keypair_from_dk(dk: DecapsulationKey<MlKem768>) -> Keypair {
    let ek = dk.encapsulation_key().clone();
    Keypair {
        public_key: ek.to_bytes().to_vec(),
        secret_key: dk.to_bytes().to_vec(),
    }
}

/// Generate a fresh ML-KEM-768 keypair using the operating system's CSPRNG.
///
/// # Security properties
///
/// Provides IND-CCA2 security at NIST category 3 under the ML-KEM claims.
///
/// # Misuse risks
///
/// - Treat `secret_key` with the same care as an AES-256 key.
/// - Never transmit secret-key seeds over an unauthenticated channel.
#[must_use]
pub fn generate_keypair() -> Keypair {
    let (dk, _ek) = MlKem768::generate_keypair();
    keypair_from_dk(dk)
}

/// Derive an ML-KEM-768 keypair from a 64-byte seed (`d || z`).
///
/// Used for NIST ACVP keyGen KATs and for deterministic key generation in
/// offline tests. Production callers should prefer [`generate_keypair`].
///
/// # Security properties
///
/// Matches FIPS 203 `ML-KEM.KeyGen_internal`. Identical seeds yield identical
/// keys.
///
/// # Misuse risks
///
/// - Seeds must be uniformly random. Reused or low-entropy seeds destroy
///   confidentiality of every encapsulating peer.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `seed` is not 64 bytes.
pub fn keypair_from_seed(seed: &[u8]) -> Result<Keypair> {
    if seed.len() != SECRET_KEY_SEED_BYTES {
        return Err(Error::InvalidLength);
    }
    let seed = Seed::try_from(seed).map_err(|_| Error::InvalidLength)?;
    Ok(keypair_from_dk(DecapsulationKey::<MlKem768>::from_seed(
        seed,
    )))
}

/// Return the legacy expanded decapsulation key for a seed-form secret key.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `secret_key` is not a 64-byte seed.
pub fn expanded_secret_key(secret_key: &[u8]) -> Result<Vec<u8>> {
    let dk = dk_from_secret_key(secret_key)?;
    #[allow(deprecated)]
    {
        use ml_kem::ExpandedKeyEncoding;
        Ok(dk.to_expanded_bytes().to_vec())
    }
}

/// Encapsulate a shared secret to an ML-KEM-768 public key.
///
/// # Security properties
///
/// On success, `shared_secret` is suitable as IKM to a KDF (for example
/// [`crate::kdf::labeled_kdf`]). The ciphertext is safe to send in the clear.
///
/// # Misuse risks
///
/// - `public_key` must be an authentic peer key.
/// - Do not reuse the shared secret for multiple purposes without domain
///   separation.
pub fn encapsulate(public_key: &[u8]) -> Result<Encapsulation> {
    if public_key.is_empty() {
        return Err(Error::InvalidLength);
    }
    let ek = EncapsulationKey::<MlKem768>::new_from_slice(public_key)
        .map_err(|_| Error::InvalidEncoding)?;
    let (ciphertext, shared_secret) = ek.encapsulate();
    Ok(Encapsulation {
        ciphertext: ciphertext.to_vec(),
        shared_secret: shared_secret.to_vec(),
    })
}

/// Deterministic encapsulation for NIST ACVP / KAT compliance.
///
/// # Security properties
///
/// Implements FIPS 203 encapsulation with caller-supplied randomness `m`
/// (32 bytes). Used only to reproduce official Known-Answer Tests.
///
/// # Misuse risks
///
/// **Hazmat.** If `m` is ever reused or non-uniform, shared secrets are
/// compromised. Production code must call [`encapsulate`], never this function.
///
/// # Errors
///
/// Returns length/encoding errors when `public_key` or `m` is invalid.
pub fn encapsulate_deterministic(public_key: &[u8], m: &[u8]) -> Result<Encapsulation> {
    if m.len() != ENCAP_RANDOMNESS_BYTES {
        return Err(Error::InvalidLength);
    }
    let ek = EncapsulationKey::<MlKem768>::new_from_slice(public_key)
        .map_err(|_| Error::InvalidEncoding)?;
    let m = B32::try_from(m).map_err(|_| Error::InvalidLength)?;
    let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&m);
    Ok(Encapsulation {
        ciphertext: ciphertext.to_vec(),
        shared_secret: shared_secret.to_vec(),
    })
}

/// Decapsulate an ML-KEM-768 ciphertext with the corresponding secret key.
///
/// `secret_key` may be either:
/// - 64-byte seed (`d || z`) — preferred, from [`generate_keypair`]
/// - 2400-byte expanded `dk` — accepted for NIST ACVP vectors / interop
///
/// # Security properties
///
/// Implements FIPS 203 decapsulation with implicit rejection.
///
/// # Misuse risks
///
/// - Wrong keys yield an unrelated shared secret, not a distinguishable error.
/// - Prefer seed-form keys; expanded keys are larger and need validation.
pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || secret_key.is_empty() {
        return Err(Error::InvalidLength);
    }
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(Error::InvalidLength);
    }
    let dk = dk_from_secret_key(secret_key)?;
    let shared = dk
        .decapsulate_slice(ciphertext)
        .map_err(|_| Error::InvalidLength)?;
    Ok(shared.to_vec())
}

fn dk_from_secret_key(secret_key: &[u8]) -> Result<DecapsulationKey<MlKem768>> {
    match secret_key.len() {
        SECRET_KEY_SEED_BYTES => {
            let seed = Seed::try_from(secret_key).map_err(|_| Error::InvalidLength)?;
            Ok(DecapsulationKey::<MlKem768>::new(&seed))
        }
        SECRET_KEY_EXPANDED_BYTES => {
            let enc: Array<u8, _> = secret_key.try_into().map_err(|_| Error::InvalidLength)?;
            #[allow(deprecated)]
            {
                use ml_kem::ExpandedKeyEncoding;
                DecapsulationKey::<MlKem768>::from_expanded_bytes(&enc)
                    .map_err(|_| Error::InvalidEncoding)
            }
        }
        _ => Err(Error::InvalidLength),
    }
}
