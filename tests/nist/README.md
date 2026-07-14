//! Sources for NIST ACVP Known-Answer fixtures.
//!
//! JSON files in this directory are **extracted subsets** of the official NIST
//! Cryptographic Algorithm Validation Program (ACVP) sample vectors published
//! in [`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server).
//!
//! | File | Upstream directory | Parameter set |
//! |------|--------------------|---------------|
//! | `ml_kem_768_keygen.json` | `ML-KEM-keyGen-FIPS203` | ML-KEM-768 |
//! | `ml_kem_768_encapsulation.json` | `ML-KEM-encapDecap-FIPS203` | ML-KEM-768 |
//! | `ml_kem_768_decapsulation.json` | `ML-KEM-encapDecap-FIPS203` | ML-KEM-768 |
//! | `ml_dsa_65_keygen.json` | `ML-DSA-keyGen-FIPS204` | ML-DSA-65 |
//! | `ml_dsa_65_siggen_deterministic_external_pure.json` | `ML-DSA-sigGen-FIPS204` | ML-DSA-65 |
//! | `ml_dsa_65_sigver_external_pure.json` | `ML-DSA-sigVer-FIPS204` | ML-DSA-65 |
//!
//! Only the Enclave suite algorithms (ML-KEM-768 / ML-DSA-65) are retained.
//! Upstream files also contain ML-KEM-512/1024 and ML-DSA-44/87; those cases
//! are intentionally dropped.
