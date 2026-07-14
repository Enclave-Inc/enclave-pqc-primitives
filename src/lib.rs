//! `enclave-pqc-primitives` — NIST-aligned post-quantum primitives.
//!
//! Foundational cryptography for Enclave product SDKs (Sign, Verify, Messaging,
//! Encrypt). This crate deliberately contains **primitives only** — no product
//! protocols, ceremonies, credential formats, or SDK façades.
//!
//! # Algorithm suite (`ENCLAVE_PQ_SUITE_v1`)
//!
//! | Role | Algorithm | Standard |
//! |------|-----------|----------|
//! | KEM | ML-KEM-768 | FIPS 203 |
//! | Signatures | ML-DSA-65 | FIPS 204 |
//! | Symmetric AEAD | AES-256-GCM | FIPS 197 / SP 800-38D |
//! | Hash / KDF | SHAKE256 / `enclave-kdf-v1` | FIPS 202 |
//!
//! Classical-only algorithms (RSA, ECDSA/ECDH, AES-128, X25519, Ed25519) are
//! **out of scope** and must not be added here.
//!
//! # Modules
//!
//! - [`kem`] — ML-KEM-768 key encapsulation
//! - [`sig`] — ML-DSA-65 signatures
//! - [`aead`] — AES-256-GCM with explicit nonces
//! - [`hash`] — SHAKE256 one-shot and XOF
//! - [`kdf`] — labeled `enclave-kdf-v1` KDF

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod sig;

pub use error::{Error, Result};

/// Canonical suite identifier matching the historical TypeScript registry.
pub const ENCLAVE_PQ_SUITE_ID: &str = "ENCLAVE_PQ_SUITE_v1";
