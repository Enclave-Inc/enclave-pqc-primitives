//! Argon2id password-based key derivation (classical, memory-hard).
//!
//! # Why this exists separately from [`crate::kdf`]
//!
//! [`crate::kdf`] (`enclave-kdf-v1` / SHAKE256) assumes **already-high-entropy**
//! input (for example an ML-KEM shared secret). It is intentionally fast.
//!
//! Human passwords are low-entropy. Turning them into encryption keys requires
//! a deliberately **slow, memory-hard** function so offline brute-force of
//! stolen ciphertext is expensive. That is Argon2id’s job.
//!
//! # Design intent: slow is the point
//!
//! Argon2id parameters are chosen so legitimate unlock takes a
//! human-tolerable moment while massive parallel guessing becomes costly.
//! Do **not** “optimize” latency by silently lowering [`RECOMMENDED_PARAMS`]
//! without treating that as a direct security tradeoff. Lower
//! `memory_cost_kib` / `iterations` / `parallelism` makes stolen sealed data
//! cheaper to attack offline.
//!
//! This module is classical cryptography (not post-quantum). It does not
//! change the crate’s Category 5 / CNSA 2.0 algorithm story; it fills the
//! password → key gap alongside those primitives.
//!
//! Scope is password + salt → key bytes only. No account, session, or AMK
//! concepts belong here.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead;
use crate::usage::CryptoUsageRecord;
use crate::{Error, Result};

/// Algorithm identifier for CBOM / usage records.
pub const ALGORITHM: &str = "Argon2id";

/// Salt length in bytes produced by [`generate_salt`].
///
/// Argon2 accepts shorter salts; this crate standardizes on 16 bytes
/// (128-bit), matching common practice and RFC 9106-oriented guidance.
pub const SALT_BYTES: usize = 16;

/// Derived key length in bytes — equal to [`aead::KEY_BYTES`] so the output
/// can feed AES-256-GCM directly without a second derivation step.
pub const OUTPUT_BYTES: usize = aead::KEY_BYTES;

/// Configurable Argon2id cost parameters.
///
/// All three fields are required so callers cannot bury work factors in
/// hidden defaults. Prefer [`RECOMMENDED_PARAMS`] unless you have measured a
/// different profile on target hardware and understand the security impact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2Params {
    /// Memory cost in KiB (Argon2 `m`).
    pub memory_cost_kib: u32,
    /// Iteration / time cost (Argon2 `t`).
    pub iterations: u32,
    /// Degree of parallelism / lanes (Argon2 `p`).
    pub parallelism: u32,
}

/// OWASP Password Storage Cheat Sheet baseline for Argon2id.
///
/// Verified against
/// <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
/// (retrieved 2026-07-14): **19 MiB memory, 2 iterations, parallelism 1**
/// (`m=19456`, `t=2`, `p=1`). OWASP lists several CPU/RAM-equivalent
/// profiles; this constant tracks the widely cited 19 MiB / t=2 baseline.
///
/// These numbers are revised over time — do not replace from memory.
pub const RECOMMENDED_PARAMS: Argon2Params = Argon2Params {
    memory_cost_kib: 19_456,
    iterations: 2,
    parallelism: 1,
};

/// Password-derived key plus CBOM usage metadata.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PwhashOutput {
    /// 32-byte key suitable for [`crate::aead`].
    pub key: Vec<u8>,
    /// Algorithm / operation metadata for this derivation.
    #[zeroize(skip)]
    pub usage: CryptoUsageRecord,
}

fn usage(operation: &'static str) -> CryptoUsageRecord {
    CryptoUsageRecord::new(ALGORITHM, operation)
}

fn build_argon2(params: &Argon2Params) -> Result<Argon2<'static>> {
    if params.memory_cost_kib == 0 || params.iterations == 0 || params.parallelism == 0 {
        return Err(Error::InvalidParameter);
    }
    let params = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(OUTPUT_BYTES),
    )
    .map_err(|_| Error::InvalidParameter)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a fixed-length (32-byte) key from a password using Argon2id.
///
/// # Security properties
///
/// Memory-hard, salt-bound derivation resistant to offline guessing relative
/// to the configured cost. Output length is always [`OUTPUT_BYTES`].
///
/// # Misuse risks
///
/// - Reusing a salt for many passwords defeats the point of salting.
/// - Lowering costs relative to [`RECOMMENDED_PARAMS`] without a measured
///   threat model increases offline cracking speed.
/// - Empty passwords and wrong-length salts are rejected.
/// - This is **not** a drop-in replacement for [`crate::kdf`] on high-entropy
///   IKM (and vice versa).
///
/// # Errors
///
/// - [`Error::InvalidLength`] — salt is not [`SALT_BYTES`] long, or output
///   buffer contract would be violated.
/// - [`Error::InvalidParameter`] — empty password, zeroed costs, or Argon2
///   rejects the parameter set.
pub fn pwhash_derive_key(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<PwhashOutput> {
    if password.is_empty() {
        return Err(Error::InvalidParameter);
    }
    if salt.len() != SALT_BYTES {
        return Err(Error::InvalidLength);
    }

    let argon2 = build_argon2(params)?;
    let mut key = vec![0u8; OUTPUT_BYTES];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| Error::InvalidParameter)?;

    Ok(PwhashOutput {
        key,
        usage: usage("pwhash_derive_key"),
    })
}

/// Salt generation result plus CBOM usage metadata.
#[derive(Clone, Debug)]
pub struct SaltOutput {
    /// Fresh random salt ([`SALT_BYTES`] long).
    pub salt: [u8; SALT_BYTES],
    /// Algorithm / operation metadata.
    pub usage: CryptoUsageRecord,
}

/// Generate a cryptographically random [`SALT_BYTES`]-long salt.
///
/// # Errors
///
/// Returns [`Error::InvalidParameter`] if the OS / WASM CSPRNG fails
/// (extremely rare; treated as a hard error for callers).
pub fn generate_salt() -> Result<SaltOutput> {
    let mut salt = [0u8; SALT_BYTES];
    getrandom::getrandom(&mut salt).map_err(|_| Error::InvalidParameter)?;
    Ok(SaltOutput {
        salt,
        usage: usage("pwhash_generate_salt"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_inputs() {
        let salt = [0x11u8; SALT_BYTES];
        let a = pwhash_derive_key(b"correct horse battery staple", &salt, &RECOMMENDED_PARAMS)
            .expect("derive");
        let b = pwhash_derive_key(b"correct horse battery staple", &salt, &RECOMMENDED_PARAMS)
            .expect("derive again");
        assert_eq!(a.key, b.key);
        assert_eq!(a.key.len(), OUTPUT_BYTES);
        assert_eq!(OUTPUT_BYTES, aead::KEY_BYTES);
        assert_eq!(a.usage.algorithm, ALGORITHM);
        assert_eq!(a.usage.operation, "pwhash_derive_key");
    }

    #[test]
    fn different_salts_differ() {
        let salt_a = [0x22u8; SALT_BYTES];
        let salt_b = [0x33u8; SALT_BYTES];
        let a = pwhash_derive_key(b"same-password", &salt_a, &RECOMMENDED_PARAMS).unwrap();
        let b = pwhash_derive_key(b"same-password", &salt_b, &RECOMMENDED_PARAMS).unwrap();
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn rejects_empty_password_and_bad_salt() {
        let salt = [0u8; SALT_BYTES];
        assert_eq!(
            pwhash_derive_key(b"", &salt, &RECOMMENDED_PARAMS).unwrap_err(),
            Error::InvalidParameter
        );
        assert_eq!(
            pwhash_derive_key(b"x", &[0u8; 8], &RECOMMENDED_PARAMS).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn generate_salt_length() {
        let a = generate_salt().expect("salt");
        assert_eq!(a.salt.len(), SALT_BYTES);
        let b = generate_salt().expect("salt2");
        assert_ne!(a.salt, b.salt);
        assert_eq!(a.usage.operation, "pwhash_generate_salt");
    }

    #[test]
    fn recommended_params_timing_observation() {
        // Not a CI gate — log observed cost under recommended OWASP params.
        let salt = [0x44u8; SALT_BYTES];
        let start = std::time::Instant::now();
        let _ = pwhash_derive_key(b"timing-observation", &salt, &RECOMMENDED_PARAMS).unwrap();
        let elapsed = start.elapsed();
        eprintln!(
            "pwhash RECOMMENDED_PARAMS native elapsed={:.3}s (human-tolerable target typically <1s; slow is deliberate)",
            elapsed.as_secs_f64()
        );
        // Soft sanity: must complete (no hang) and not be absurdly fast on
        // capable CI (a microseconds-class result would indicate stubbing).
        assert!(elapsed.as_millis() >= 1);
        assert!(elapsed.as_secs() < 30);
    }
}
