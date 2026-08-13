//! Provider abstraction over this crate's cryptographic operations.
//!
//! # Why this exists
//!
//! The default [`SoftwareProvider`] implements every operation with the
//! in-process RustCrypto-backed code in this crate. That implementation is
//! **not** a FIPS 140-3 validated cryptographic module.
//!
//! Product SDKs should depend on [`CryptoProvider`] (or this crate's free
//! functions, which are equivalent to [`SoftwareProvider`]) so that a
//! separately validated module, HSM, or certified library can be substituted
//! later **without** rewriting Auth / Sign / Verify / Messaging SDK code.
//!
//! Do **not** represent [`SoftwareProvider`] as FIPS-validated in any
//! compliance artifact, CBOM claim, or customer-facing attestation. FIPS
//! 140-3 module validation (and any NSS accreditation) remain separate,
//! unstarted processes outside this crate.

use crate::aead;
use crate::hash;
use crate::kdf;
use crate::kem::{
    self, DecapsulationOutput, EncapsulationOutput, KeypairOutput as KemKeypairOutput,
};
use crate::sig::{self, KeypairOutput as SigKeypairOutput, SignOutput, VerifyOutput};
use crate::usage::CryptoUsageRecord;
use crate::Result;

/// Seam for substituting a FIPS-validated or HSM-backed implementation later.
///
/// Implementations must honour the Category 5-only contract of this crate:
/// ML-KEM-1024 and ML-DSA-87 exclusively — no suite-selection branching.
pub trait CryptoProvider {
    /// Generate an ML-KEM-1024 keypair (includes PCT).
    fn kem_generate_keypair(&self) -> Result<KemKeypairOutput>;

    /// Encapsulate to an ML-KEM-1024 public key.
    fn kem_encapsulate(&self, public_key: &[u8]) -> Result<EncapsulationOutput>;

    /// Decapsulate an ML-KEM-1024 ciphertext.
    fn kem_decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<DecapsulationOutput>;

    /// Generate an ML-DSA-87 keypair (includes PCT).
    fn sig_generate_keypair(&self) -> Result<SigKeypairOutput>;

    /// Sign a message with ML-DSA-87 (empty context, deterministic variant).
    fn sig_sign(&self, secret_key: &[u8], message: &[u8]) -> Result<SignOutput>;

    /// Verify an ML-DSA-87 signature (empty context).
    fn sig_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<VerifyOutput>;

    /// AES-256-GCM encrypt with an explicit nonce.
    fn aead_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<aead::EncryptOutput>;

    /// AES-256-GCM decrypt with an explicit nonce.
    fn aead_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<aead::DecryptOutput>;

    /// Labeled `enclave-kdf-v1` KDF.
    fn kdf(&self, label: &str, ikm: &[u8], length: usize) -> Result<kdf::KdfOutput>;

    /// One-shot SHAKE256 hash.
    fn hash(&self, input: &[u8], output_len: usize) -> hash::HashOutput;
}

/// Default software provider: this crate's RustCrypto-backed implementation.
///
/// **Not** FIPS 140-3 validated. Suitable for development and production use
/// where Category 5 algorithms are required but module validation is not yet
/// available. Swap this type for a validated provider behind [`CryptoProvider`]
/// when that work is complete.
#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareProvider;

impl CryptoProvider for SoftwareProvider {
    fn kem_generate_keypair(&self) -> Result<KemKeypairOutput> {
        kem::generate_keypair()
    }

    fn kem_encapsulate(&self, public_key: &[u8]) -> Result<EncapsulationOutput> {
        kem::encapsulate(public_key)
    }

    fn kem_decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<DecapsulationOutput> {
        kem::decapsulate(ciphertext, secret_key)
    }

    fn sig_generate_keypair(&self) -> Result<SigKeypairOutput> {
        sig::generate_keypair()
    }

    fn sig_sign(&self, secret_key: &[u8], message: &[u8]) -> Result<SignOutput> {
        sig::sign(secret_key, message)
    }

    fn sig_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<VerifyOutput> {
        sig::verify(public_key, message, signature)
    }

    fn aead_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<aead::EncryptOutput> {
        aead::encrypt(key, nonce, plaintext, aad)
    }

    fn aead_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<aead::DecryptOutput> {
        aead::decrypt(key, nonce, ciphertext, aad)
    }

    fn kdf(&self, label: &str, ikm: &[u8], length: usize) -> Result<kdf::KdfOutput> {
        kdf::labeled_kdf(label, ikm, length)
    }

    fn hash(&self, input: &[u8], output_len: usize) -> hash::HashOutput {
        hash::shake256(input, output_len)
    }
}

/// Convenience: return a usage record describing `SoftwareProvider` itself.
#[must_use]
pub fn software_provider_usage() -> CryptoUsageRecord {
    CryptoUsageRecord::new("SoftwareProvider", "provider_identity")
}
