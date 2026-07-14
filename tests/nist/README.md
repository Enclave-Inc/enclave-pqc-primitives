# NIST fixtures

Category 3 (ML-KEM-768 / ML-DSA-65) ACVP fixtures were removed when this crate
cut over to Category 5 exclusively.

AES-256-GCM and SHAKE256 known-answer coverage lives in
`tests/nist_symmetric_hash_kdf.rs`.

ML-KEM-1024 / ML-DSA-87 known-answer CAST coverage (fixed seeds + digests) lives
in `src/self_test.rs` and is exercised by `run_self_tests()` / `tests/roundtrip.rs`.

Official NIST ACVP Category 5 vectors may be added here later under names that
do not imply Category 3.
