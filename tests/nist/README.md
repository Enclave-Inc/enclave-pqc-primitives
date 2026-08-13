# NIST ACVP fixtures (Category 3)

Official Known-Answer Test vectors for **ML-KEM-768** and **ML-DSA-65**, vendored
from [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
`gen-val/json-files/`:

| File | Upstream | Cases |
|------|----------|-------|
| `ml_kem_768_keygen.json` | `ML-KEM-keyGen-FIPS203` | 25 |
| `ml_kem_768_encapsulation.json` | `ML-KEM-encapDecap-FIPS203` | 25 |
| `ml_kem_768_decapsulation.json` | `ML-KEM-encapDecap-FIPS203` | 10 |
| `ml_dsa_65_keygen.json` | `ML-DSA-keyGen-FIPS204` | 25 |
| `ml_dsa_65_siggen_deterministic_external_pure.json` | `ML-DSA-sigGen-FIPS204` | 15 |
| `ml_dsa_65_sigver_external_pure.json` | `ML-DSA-sigVer-FIPS204` | 15 |

Harness: `tests/nist_ml_kem_768.rs`, `tests/nist_ml_dsa_65.rs`.

Category 5 CAST coverage (internal golden digests) lives in `src/self_test.rs`.
AES-256-GCM and SHAKE256 KATs live in `tests/nist_symmetric_hash_kdf.rs`.
