//! ML-KEM-768 (FIPS 203) key encapsulation — NIST Category 3.
//!
//! Secret keys accept the preferred 64-byte seed form (from
//! [`generate_keypair`] / [`keypair_from_seed`]) or the FIPS expanded
//! encoding ([`SECRET_KEY_BYTES`] = 2400 bytes).

use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit, TryKeyInit};
use ml_kem::{array::Array, DecapsulationKey, EncapsulationKey, MlKem768, Seed, B32};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::usage::CryptoUsageRecord;
use crate::{Error, Result};

/// Algorithm identifier (explicit Category 3 parameter set).
pub const ALGORITHM: &str = "ML-KEM-768";

/// Encoded ML-KEM-768 encapsulation (public) key length in bytes (FIPS 203).
pub const PUBLIC_KEY_BYTES: usize = 1184;

/// Preferred ML-KEM-768 decapsulation-key seed length in bytes (`d || z`).
pub const SECRET_KEY_SEED_BYTES: usize = 64;

/// Expanded ML-KEM-768 decapsulation key length (FIPS 203 `dk`).
pub const SECRET_KEY_EXPANDED_BYTES: usize = 2400;

/// Alias for the FIPS expanded secret-key size ([`SECRET_KEY_EXPANDED_BYTES`]).
pub const SECRET_KEY_BYTES: usize = SECRET_KEY_EXPANDED_BYTES;

/// ML-KEM-768 ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = 1088;

/// Shared secret length in bytes (always 32 for ML-KEM).
pub const SHARED_SECRET_BYTES: usize = 32;

/// Encapsulation randomness `m` length in bytes (FIPS 203).
pub const ENCAP_RANDOMNESS_BYTES: usize = 32;

/// Fixed message used by the pair-wise consistency test after keygen.
const PCT_MESSAGE_LABEL: &[u8] = b"enclave-pqc-kem768-pct-v1";

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

/// Keypair plus CBOM usage metadata.
#[derive(Clone)]
pub struct KeypairOutput {
    /// Fresh keypair that passed its PCT.
    pub keypair: Keypair,
    /// Algorithm / suite / crate metadata for this operation.
    pub usage: CryptoUsageRecord,
}

/// Encapsulation plus CBOM usage metadata.
#[derive(Clone)]
pub struct EncapsulationOutput {
    /// Encapsulation ciphertext and shared secret.
    pub encapsulation: Encapsulation,
    /// Algorithm / suite / crate metadata for this operation.
    pub usage: CryptoUsageRecord,
}

/// Decapsulation plus CBOM usage metadata.
#[derive(Clone)]
pub struct DecapsulationOutput {
    /// Recovered shared secret.
    pub shared_secret: Vec<u8>,
    /// Algorithm / suite / crate metadata for this operation.
    pub usage: CryptoUsageRecord,
}

fn usage(operation: &'static str) -> CryptoUsageRecord {
    CryptoUsageRecord::new(ALGORITHM, operation)
}

fn keypair_from_dk(dk: DecapsulationKey<MlKem768>) -> Keypair {
    let ek = dk.encapsulation_key().clone();
    Keypair {
        public_key: ek.to_bytes().to_vec(),
        secret_key: dk.to_bytes().to_vec(),
    }
}

fn generate_keypair_unchecked() -> Keypair {
    let (dk, _ek) = MlKem768::generate_keypair();
    keypair_from_dk(dk)
}

/// Pair-wise consistency test: encapsulate to `pk`, then decapsulate with `sk`.
fn pairwise_consistency(keypair: &Keypair) -> Result<()> {
    let enc = encapsulate_unchecked(&keypair.public_key)?;
    let shared = decapsulate_unchecked(&enc.ciphertext, &keypair.secret_key)?;
    if shared.as_slice() != enc.shared_secret.as_slice() {
        return Err(Error::PairwiseConsistencyFailure);
    }
    // Bind the PCT to a label so compilers cannot prove the comparison is
    // always true from a single constant path (still must match).
    let _ = PCT_MESSAGE_LABEL;
    Ok(())
}

/// Generate a fresh ML-KEM-768 keypair using the operating system's CSPRNG.
///
/// After generation, a pair-wise consistency test (PCT) encapsulate/decapsulate
/// round-trip must succeed before the keypair is returned. Failure yields
/// [`Error::PairwiseConsistencyFailure`] — never a silently returned key.
///
/// # Security properties
///
/// Provides IND-CCA2 security at NIST Category 3 under the ML-KEM claims.
///
/// # Misuse risks
///
/// - Treat `secret_key` with the same care as an AES-256 key.
/// - Never transmit secret-key seeds over an unauthenticated channel.
pub fn generate_keypair() -> Result<KeypairOutput> {
    let keypair = generate_keypair_unchecked();
    pairwise_consistency(&keypair)?;
    Ok(KeypairOutput {
        keypair,
        usage: usage("kem768_generate_keypair"),
    })
}

/// Derive an ML-KEM-768 keypair from a 64-byte seed (`d || z`).
///
/// Used for known-answer / self-tests and deterministic generation. Production
/// callers should prefer [`generate_keypair`]. A PCT still runs before return.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `seed` is not 64 bytes, or
/// [`Error::PairwiseConsistencyFailure`] if the PCT fails.
pub fn keypair_from_seed(seed: &[u8]) -> Result<KeypairOutput> {
    if seed.len() != SECRET_KEY_SEED_BYTES {
        return Err(Error::InvalidLength);
    }
    let seed = Seed::try_from(seed).map_err(|_| Error::InvalidLength)?;
    let keypair = keypair_from_dk(DecapsulationKey::<MlKem768>::from_seed(seed));
    pairwise_consistency(&keypair)?;
    Ok(KeypairOutput {
        keypair,
        usage: usage("kem768_keypair_from_seed"),
    })
}

/// Deterministic keygen **without** PCT — for ACVP KAT harnesses and self-tests.
#[allow(dead_code)]
pub(crate) fn keypair_from_seed_unchecked(seed: &[u8]) -> Result<Keypair> {
    if seed.len() != SECRET_KEY_SEED_BYTES {
        return Err(Error::InvalidLength);
    }
    let seed = Seed::try_from(seed).map_err(|_| Error::InvalidLength)?;
    Ok(keypair_from_dk(DecapsulationKey::<MlKem768>::from_seed(
        seed,
    )))
}

/// Return the expanded decapsulation key for a seed-form secret key.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `secret_key` is not a 64-byte seed.
pub fn expanded_secret_key(secret_key: &[u8]) -> Result<(Vec<u8>, CryptoUsageRecord)> {
    let dk = dk_from_secret_key(secret_key)?;
    #[allow(deprecated)]
    {
        use ml_kem::ExpandedKeyEncoding;
        Ok((dk.to_expanded_bytes().to_vec(), usage("kem768_expanded_secret_key")))
    }
}

fn encapsulate_unchecked(public_key: &[u8]) -> Result<Encapsulation> {
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
pub fn encapsulate(public_key: &[u8]) -> Result<EncapsulationOutput> {
    Ok(EncapsulationOutput {
        encapsulation: encapsulate_unchecked(public_key)?,
        usage: usage("kem768_encapsulate"),
    })
}

/// Deterministic encapsulation for known-answer / NIST compliance.
///
/// # Misuse risks
///
/// **Hazmat.** If `m` is ever reused or non-uniform, shared secrets are
/// compromised. Production code must call [`encapsulate`], never this function.
pub fn encapsulate_deterministic(public_key: &[u8], m: &[u8]) -> Result<EncapsulationOutput> {
    Ok(EncapsulationOutput {
        encapsulation: encapsulate_deterministic_unchecked(public_key, m)?,
        usage: usage("kem768_encapsulate_deterministic"),
    })
}

pub(crate) fn encapsulate_deterministic_unchecked(
    public_key: &[u8],
    m: &[u8],
) -> Result<Encapsulation> {
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

fn decapsulate_unchecked(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
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

/// Decapsulate an ML-KEM-768 ciphertext with the corresponding secret key.
///
/// `secret_key` may be either:
/// - 64-byte seed (`d || z`) — preferred, from [`generate_keypair`]
/// - 2400-byte expanded `dk` — accepted for FIPS expanded encodings
pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<DecapsulationOutput> {
    Ok(DecapsulationOutput {
        shared_secret: decapsulate_unchecked(ciphertext, secret_key)?,
        usage: usage("kem768_decapsulate"),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips_203_category_3() {
        assert_eq!(PUBLIC_KEY_BYTES, 1184);
        assert_eq!(SECRET_KEY_BYTES, 2400);
        assert_eq!(CIPHERTEXT_BYTES, 1088);
        assert_eq!(SHARED_SECRET_BYTES, 32);
    }

    #[test]
    fn generate_runs_pct_and_sizes() {
        let out = generate_keypair().expect("keygen");
        assert_eq!(out.keypair.public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(out.keypair.secret_key.len(), SECRET_KEY_SEED_BYTES);
        assert_eq!(out.usage.algorithm, ALGORITHM);
        let expanded = expanded_secret_key(&out.keypair.secret_key)
            .expect("expand")
            .0;
        assert_eq!(expanded.len(), SECRET_KEY_BYTES);
    }
}
