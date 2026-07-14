# AGENTS.md — enclave-pqc-primitives

Shared NIST-aligned post-quantum primitives for Enclave product SDKs.

## Rules

1. Primitive-only — no product workflows, ceremonies, credentials, or SDKs.
2. No classical-only algorithms (RSA, ECDSA/ECDH, AES-128, X25519, Ed25519).
3. Prefer audited RustCrypto crates; pin versions with `=`.
4. Flag any non-RustCrypto / non-NIST-adjacent dependency in Cargo.toml + README.
5. Public functions need docs (behavior, security properties, misuse risks).
6. AES-GCM nonces stay explicit — never generated silently.
7. Keep `enclave-kdf-v1` byte-compatible with the historical construction.
8. NIST ACVP KATs for ML-KEM-768 and ML-DSA-65 live under `tests/nist/`.

## Commands

```bash
cargo test
cargo test --test nist_ml_kem_768
cargo test --test nist_ml_dsa_65
cargo clippy --all-targets -- -D warnings
```
