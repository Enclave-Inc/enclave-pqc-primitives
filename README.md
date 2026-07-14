# enclave-pqc-primitives

NIST-aligned **post-quantum cryptographic primitives** for Enclave product
SDKs. Licensed under **Apache-2.0**.

This is the foundational (tier-1) crate **and** the npm package
`@enclave/pqc-primitives` (WASM bindings). Product SDKs (Auth, Sign, Verify,
Messaging, …) build **on top of** it. This package stays **algorithm-only** —
no sessions, envelopes, tokens, or credentials.

This crate implements NIST Category 5 exclusively (ML-KEM-1024 / ML-DSA-87),
satisfying CNSA 2.0's algorithm requirements for national security systems.
This is an architectural choice, not a certification — FIPS 140-3 module
validation and any NSS accreditation remain separate, unstarted processes.

## Algorithm suite (`ENCLAVE_PQ_SUITE_v1`)

Category 5 only — there is **no** Category 3 parameter set and **no**
suite-selection API.

| Role | Algorithm | Standard | Implementation |
|------|-----------|----------|----------------|
| Key encapsulation | ML-KEM-1024 | FIPS 203 | RustCrypto [`ml-kem`](https://crates.io/crates/ml-kem) |
| Signatures | ML-DSA-87 | FIPS 204 | RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa) |
| Bulk AEAD | AES-256-GCM | FIPS 197 / SP 800-38D | RustCrypto [`aes-gcm`](https://crates.io/crates/aes-gcm) |
| Hash / XOF | SHAKE256 | FIPS 202 | RustCrypto [`sha3`](https://crates.io/crates/sha3) |
| Labeled KDF | `enclave-kdf-v1` | SHAKE256 domain-separated | this crate |

### Encoding sizes (FIPS)

| | Public key | Secret (expanded) | Seed | Ciphertext / signature |
|--|------------|-------------------|------|------------------------|
| ML-KEM-1024 | 1568 | 3168 | 64 | ciphertext 1568; shared secret 32 |
| ML-DSA-87 | 2592 | 4896 | 32 | signature 4627 |

## Layout

```text
src/                 Rust primitives (kem, sig, aead, hash, kdf, provider, self_test, usage)
bindings/wasm/       wasm-bindgen façade (algorithm names only)
js/                  TS helpers / constants (source of truth for sizes)
scripts/build-wasm.mjs
dist/{bundler,nodejs,web}/   wasm-pack outputs + JS façade
tests/               Round-trips, CAST coverage, AES/SHAKE KATs
```

## Rust usage

```rust
use enclave_pqc_primitives::{aead, kdf, kem, run_self_tests, sig, SoftwareProvider, CryptoProvider};

run_self_tests()?; // optional CAST at startup

let kem_kp = kem::generate_keypair()?; // includes PCT
let enc = kem::encapsulate(&kem_kp.keypair.public_key)?;
let shared = kem::decapsulate(&enc.encapsulation.ciphertext, &kem_kp.keypair.secret_key)?;
let aes_key = kdf::labeled_kdf("aes-256-gcm-key", &shared.shared_secret, 32)?;

let nonce = [0u8; aead::NONCE_BYTES]; // caller must ensure uniqueness
let sealed = aead::encrypt(&aes_key.key, &nonce, b"hello", b"aad")?;

let sig_kp = sig::generate_keypair()?; // includes PCT
let signature = sig::sign(&sig_kp.keypair.secret_key, b"message")?;
sig::verify(&sig_kp.keypair.public_key, b"message", &signature.signature)?;

// Same operations via the substitution seam (SoftwareProvider is not FIPS-validated):
let provider = SoftwareProvider;
let _ = provider.kem_generate_keypair()?;
# Ok::<(), enclave_pqc_primitives::Error>(())
```

Each operation returns a [`CryptoUsageRecord`] (`algorithm`, `suite_id`,
`operation`, `crate_version`) for CBOM / audit attach points. Persistence and
telemetry belong in Encrypt / product layers — not this crate.

## JavaScript / TypeScript (`@enclave/pqc-primitives`)

WASM façade over the same Category 5 Rust core. Algorithm-namespaced only
(`kem*` / `sig*` / `aead*` / …) — no product concepts.

### Install / build

```bash
# Requires: rustup target wasm32-unknown-unknown, wasm-pack (auto-installed)
npm install
npm run build
npm test
```

### Multi-runtime exports

| Consumer | Import condition / path |
|----------|-------------------------|
| Node / Vitest | `import … from "@enclave/pqc-primitives"` → `dist/nodejs` |
| Next.js / webpack / Vite | `"browser"` → `dist/bundler` |
| Deno / raw ESM | `"./web"` or `"deno"` → `dist/web` |

```ts
import {
  KEM, SIG, AEAD, HASH, KDF_LABEL_PREFIX,
  kemGenerateKeypair, kemEncapsulate, kemDecapsulate,
  sigGenerateKeypair, sigSign, sigSignWithContext, sigVerify,
  aeadEncrypt, aeadDecrypt,
  labeledKdf, labeledKdf32, shake256, zeroize,
  runSelfTests, getLastUsageRecord,
  isPairwiseConsistencyFailure, isSelfTestFailure,
} from "@enclave/pqc-primitives";

await runSelfTests();
const kp = kemGenerateKeypair(); // PCT inside; seed-form secretKey (64 B)
const usage = getLastUsageRecord(); // { algorithm, suiteId, operation, crateVersion }
```

Keygen returns the preferred **seed** secret-key form (`KEM.SECRET_KEY_SEED_BYTES` /
`SIG.SECRET_KEY_SEED_BYTES`). FIPS expanded sizes are `SECRET_KEY_BYTES` (3168 / 4896)
via `kemExpandedSecretKey` / `sigExpandedSecretKey`.

Typed failures use `err.name`:
- `PairwiseConsistencyFailureError` — PCT failed in keygen
- `SelfTestFailureError` — CAST failed in `runSelfTests`

Errors otherwise throw greppable prefixes: `InvalidLength:`, `InvalidEncoding:`,
`AeadFailure:`, `SignatureInvalid:`, `InvalidParameter:`.

### Secret zeroization (important)

Rust zeroizes secret keys on `Drop` **inside** WASM. Bytes copied into a JS
`Uint8Array` are **not** cleared by the GC. Call `zeroize(secretKey)` when
finished with long-lived secrets.

## Dependencies (pinned)

| Crate | Role | Provenance |
|-------|------|------------|
| `ml-kem =0.3.2` | ML-KEM-1024 | **RustCrypto** |
| `ml-dsa =0.1.1` | ML-DSA-87 | **RustCrypto** |
| `aes-gcm =0.10.3` | AES-256-GCM | **RustCrypto** |
| `sha3 =0.10.8` | SHAKE256 | **RustCrypto** |
| `zeroize =1.8.1` | Secret wipe-on-drop | **RustCrypto** |

### Flagged dependencies

| Crate | Where | Why flagged |
|-------|-------|-------------|
| `serde` / `serde_json` | **dev-only** | reserved for future NIST ACVP JSON fixtures |
| `wasm-bindgen` / `js-sys` / `getrandom/js` | **bindings/wasm only** | JS interop — not used by native Rust consumers |

## Running tests

```bash
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
