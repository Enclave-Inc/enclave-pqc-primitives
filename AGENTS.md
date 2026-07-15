# AGENTS.md — enclave-pqc-primitives

Shared NIST-aligned post-quantum primitives for Enclave product SDKs.

## Rules

1. Primitive-only — no product workflows, ceremonies, credentials, sessions,
   envelopes, tokens, or SDKs.
2. No classical public-key algorithms (RSA, ECDSA/ECDH, AES-128, X25519,
   Ed25519). **Exception:** Argon2id in `pwhash` for password → key (classical
   memory-hard KDF; not part of the Category 5 / CNSA suite).
3. **Category 5 only** — ML-KEM-1024 / ML-DSA-87. Do not reintroduce Category 3
   parameter sets or suite-selection branching.
4. Prefer audited RustCrypto crates; pin versions with `=`.
5. Flag any non-RustCrypto / non-NIST-adjacent dependency in Cargo.toml + README.
6. Public functions need docs (behavior, security properties, misuse risks).
7. AES-GCM nonces stay explicit — never generated silently.
8. Keep `enclave-kdf-v1` byte-compatible with the historical construction.
9. Use `pwhash` (Argon2id) for human passwords — never `kdf` / SHAKE256 for
   low-entropy secrets. Do not weaken `RECOMMENDED_PARAMS` for latency without
   treating that as a security tradeoff (slow + memory-hard is the point).
10. Key generation must run a pair-wise consistency test (PCT) and return
    `Error::PairwiseConsistencyFailure` on failure — never log-and-continue.
11. `SoftwareProvider` is **not** FIPS 140-3 validated; document that on the
    `CryptoProvider` trait. Do not claim validation in compliance artifacts.
12. JS bindings under `bindings/wasm` stay **algorithm-namespaced** (`kem*` /
    `sig*` / `aead*` / `pwhash*` / …). Multi-product consumers must not push
    use-case names into this crate.
13. WASM errors must throw greppable JS `Error` messages (`InvalidLength: …`);
    never leak raw Rust panic text as the primary contract.

## Commands

```bash
cargo test
cargo clippy --workspace --all-targets -- -D warnings
npm run build
npm test
```
