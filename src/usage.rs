//! CBOM-oriented usage metadata for cryptographic operations.
//!
//! Product layers (for example Encrypt) may attach these records to telemetry or
//! a Cryptographic Bill of Materials. This crate only produces the record — it
//! does not persist or transmit it.

use crate::ENCLAVE_PQ_SUITE_ID;

/// Crate version string baked in at compile time.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Structured description of which algorithm performed an operation.
///
/// Fields are static so construction is zero-allocation. Names are explicit
/// (for example `"ML-DSA-87"`, not `"the signature algorithm"`) so consumers
/// never have to infer the suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoUsageRecord {
    /// Concrete algorithm identifier (for example `"ML-KEM-1024"`).
    pub algorithm: &'static str,
    /// Suite identifier (currently [`ENCLAVE_PQ_SUITE_ID`]).
    pub suite_id: &'static str,
    /// Semantic operation name (`"kem_generate_keypair"`, `"sig_sign"`, …).
    pub operation: &'static str,
    /// Version of `enclave-pqc-primitives` that produced this record.
    pub crate_version: &'static str,
}

impl CryptoUsageRecord {
    /// Build a record for a named operation under a named algorithm.
    #[must_use]
    pub const fn new(algorithm: &'static str, operation: &'static str) -> Self {
        Self {
            algorithm,
            suite_id: ENCLAVE_PQ_SUITE_ID,
            operation,
            crate_version: CRATE_VERSION,
        }
    }
}
