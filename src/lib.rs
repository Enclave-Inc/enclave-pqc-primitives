//! `enclave-pqc-primitives` — NIST post-quantum primitives (Category 3 + 5).
//!
//! Foundational cryptography for Enclave product SDKs (Auth, Sign, Verify,
//! Messaging, Encrypt). This crate deliberately contains **primitives only** —
//! no product protocols, ceremonies, credential formats, or SDK façades.
//!
//! # Algorithm suite (`ENCLAVE_PQ_SUITE_v1`)
//!
//! Category 5 (ML-KEM-1024 / ML-DSA-87) via [`kem`] / [`sig`].
//! Category 3 (ML-KEM-768 / ML-DSA-65) via [`kem768`] / [`sig65`].
//!
//! | Role | Algorithm | Standard |
//! |------|-----------|----------|
//! | KEM (Cat 5) | ML-KEM-1024 | FIPS 203 |
//! | KEM (Cat 3) | ML-KEM-768 | FIPS 203 |
//! | Signatures (Cat 5) | ML-DSA-87 | FIPS 204 |
//! | Signatures (Cat 3) | ML-DSA-65 | FIPS 204 |
//! | Symmetric AEAD | AES-256-GCM | FIPS 197 / SP 800-38D |
//! | Hash / KDF | SHAKE256 / `enclave-kdf-v1` | FIPS 202 |
//! | Password → key | Argon2id | RFC 9106 (classical) |
//!
//! Classical public-key algorithms (RSA, ECDSA/ECDH, X25519, Ed25519) and
//! AES-128 remain **out of scope**. Argon2id is the deliberate exception: it
//! is classical memory-hard password hashing needed for human secrets, and is
//! **not** part of the Category 5 / CNSA 2.0 suite story.
//!
//! # Modules
//!
//! - [`kem`] — ML-KEM-1024 key encapsulation (Category 5)
//! - [`kem768`] — ML-KEM-768 key encapsulation (Category 3)
//! - [`sig`] — ML-DSA-87 signatures (Category 5)
//! - [`sig65`] — ML-DSA-65 signatures (Category 3)
//! - [`aead`] — AES-256-GCM with explicit nonces
//! - [`hash`] — SHAKE256 one-shot and XOF
//! - [`kdf`] — labeled `enclave-kdf-v1` KDF (high-entropy IKM)
//! - [`pwhash`] — Argon2id password → key (low-entropy passwords)
//! - [`provider`] — [`CryptoProvider`] seam + [`SoftwareProvider`]
//! - [`self_test`] — CAST known-answer self-tests
//! - [`usage`] — CBOM-oriented [`CryptoUsageRecord`]

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod kem768;
pub mod provider;
pub mod pwhash;
pub mod self_test;
pub mod sig;
pub mod sig65;
pub mod usage;

pub use error::{Error, Result, SelfTestError};
pub use provider::{CryptoProvider, SoftwareProvider};
pub use self_test::run_self_tests;
pub use usage::{CryptoUsageRecord, CRATE_VERSION};

/// Canonical suite identifier. Algorithms under this id are Category 5 only.
pub const ENCLAVE_PQ_SUITE_ID: &str = "ENCLAVE_PQ_SUITE_v1";
