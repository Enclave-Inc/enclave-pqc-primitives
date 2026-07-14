# enclave-pqc-primitives

NIST-aligned **post-quantum cryptographic primitives** for Enclave product
SDKs. Licensed under **Apache-2.0**.

This is the foundational (tier-1) crate. Product SDKs (Sign, Verify, Messaging,
Encrypt) and applications build **on top of** it in separate layers.

## What this crate is

| Role | Algorithm | Standard | Implementation |
|------|-----------|----------|----------------|
| Key encapsulation | ML-KEM-768 | FIPS 203 | RustCrypto [`ml-kem`](https://crates.io/crates/ml-kem) |
| Signatures | ML-DSA-65 | FIPS 204 | RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa) |
| Bulk AEAD | AES-256-GCM | FIPS 197 / SP 800-38D | RustCrypto [`aes-gcm`](https://crates.io/crates/aes-gcm) |
| Hash / XOF | SHAKE256 | FIPS 202 | RustCrypto [`sha3`](https://crates.io/crates/sha3) |
| Labeled KDF | `enclave-kdf-v1` | SHAKE256 domain-separated | this crate |

## What this crate deliberately does **not** include

- Product / workflow logic (signing ceremonies, document handling, credential
  formats, messaging epochs, DEK wrapping policies, …)
- SDK façades, networking, storage, or APIs
- Classical-only algorithms (RSA, ECDSA/ECDH, AES-128, X25519, Ed25519)
- WASM build targets (deferred to a later pass)

Those belong in higher-layer crates and apps.

## Layout

```text
src/
  kem.rs     ML-KEM-768
  sig.rs     ML-DSA-65
  aead.rs    AES-256-GCM (explicit nonce required)
  hash.rs    SHAKE256 + XOF
  kdf.rs     labeled enclave-kdf-v1
  error.rs   shared Error / Result
tests/
  nist/      Official NIST ACVP KAT fixtures (ML-KEM-768 / ML-DSA-65)
  nist_*.rs  Known-Answer Test runners
  roundtrip.rs
```

## Dependencies (pinned)

All production dependencies are pinned with `=`.

| Crate | Role | Provenance |
|-------|------|------------|
| `ml-kem =0.3.2` | ML-KEM-768 | **RustCrypto** |
| `ml-dsa =0.1.1` | ML-DSA-65 | **RustCrypto** |
| `aes-gcm =0.10.3` | AES-256-GCM | **RustCrypto** (NCC Group audited) |
| `sha3 =0.10.8` | SHAKE256 | **RustCrypto** |
| `zeroize =1.8.1` | Secret wipe-on-drop | **RustCrypto** |

### Flagged dependencies (review before accepting)

| Crate | Where | Why flagged |
|-------|-------|-------------|
| `serde =1.0.219` | **dev-dependency only** | Not RustCrypto; deserializes NIST ACVP JSON fixtures in tests |
| `serde_json =1.0.140` | **dev-dependency only** | Same |

No flagged crates appear in the runtime dependency graph of this library.
Transitive crates pulled by RustCrypto (for example `hybrid-array`,
`getrandom`, `kem`, `signature`) are part of the RustCrypto stack / traits
ecosystem and are listed in `Cargo.lock` for review.

## API notes worth reviewing

1. **Secret-key encoding** — preferred form is the FIPS seed (ML-KEM 64 bytes,
   ML-DSA 32 bytes). Expanded encodings are accepted where needed for NIST
   ACVP interop (`decapsulate`, `sign_deterministic`).
2. **AES-GCM nonces are always explicit** — the library never invents a nonce.
   Callers must ensure `(key, nonce)` uniqueness.
3. **ML-DSA `sign` is deterministic** (empty context) — matches RustCrypto’s
   `Signer` impl (optional FIPS deterministic variant). Hedged/randomized
   signing is not exposed yet.
4. **`encapsulate_deterministic` is hazmat** — for KAT reproduction only;
   production code must use `encapsulate`.
5. **Labeled KDF** — `SHAKE256("enclave-kdf-v1:" || label || ":" || ikm, n)`.

## Running tests

```bash
# Everything (unit + NIST KATs + round-trips)
cargo test

# NIST ML-KEM-768 KATs only
cargo test --test nist_ml_kem_768

# NIST ML-DSA-65 KATs only
cargo test --test nist_ml_dsa_65

# AES-GCM / SHAKE256 / KDF known answers
cargo test --test nist_symmetric_hash_kdf

# Lint
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

NIST vectors under `tests/nist/` are subsets of the official ACVP sample files
from [`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server)
(`ML-KEM-*-FIPS203`, `ML-DSA-*-FIPS204`), filtered to ML-KEM-768 and ML-DSA-65.

## Usage sketch

```rust
use enclave_pqc_primitives::{aead, kdf, kem, sig};

let kem_kp = kem::generate_keypair();
let enc = kem::encapsulate(&kem_kp.public_key)?;
let shared = kem::decapsulate(&enc.ciphertext, &kem_kp.secret_key)?;
let aes_key = kdf::labeled_kdf("aes-256-gcm-key", &shared, 32)?;

// Caller-supplied unique nonce — never reuse with the same key.
let nonce = [0u8; aead::NONCE_BYTES];
let sealed = aead::encrypt(&aes_key, &nonce, b"hello", b"aad")?;

let sig_kp = sig::generate_keypair();
let signature = sig::sign(&sig_kp.secret_key, b"message")?;
sig::verify(&sig_kp.public_key, b"message", &signature)?;
# Ok::<(), enclave_pqc_primitives::Error>(())
```

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
