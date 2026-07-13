# @enclave/pqc-primitives

Shared **NIST-aligned post-quantum cryptography** for Enclave product SDKs (`social-sdk`, `verify-sdk`, `sign-sdk`, and future products).

Licensed under **AGPL-3.0-or-later**. Product apps and APIs should depend on this package (via their product SDK), not import `@noble/post-quantum` directly.

## Layout

```text
registry/           Canonical algorithm suite (ENCLAVE_PQ_SUITE_v1.json)
src/
  encoding/         Base64 / hex helpers
  hash/             SHAKE256
  kdf/              Labeled KDF
  kem/              ML-KEM-768
  sign/             ML-DSA-65
  symmetric/        AES-256-GCM
  registry/         Typed suite constants
  provider/         PqcProvider interface + noble implementation
tests/              Conformance and round-trip tests
```

## Algorithm suite

Canonical registry: [`registry/ENCLAVE_PQ_SUITE_v1.json`](./registry/ENCLAVE_PQ_SUITE_v1.json)

| Role | Algorithm | NIST |
|------|-----------|------|
| Key agreement | ML-KEM-768 | FIPS 203 |
| Signatures | ML-DSA-65 | FIPS 204 |
| Bulk encryption | AES-256-GCM | FIPS 197 / SP 800-38D |
| Hash / KDF input | SHAKE256 | FIPS 202 |

Classical algorithms (X25519, Ed25519, RSA, …) are **disallowed for new code** in Enclave SDKs.

## Install

```bash
npm install @enclave/pqc-primitives
```

## Usage

```ts
import {
  generateMlKemKeypair,
  encapsulateMlKem,
  decapsulateMlKem,
  generateMlDsaKeypair,
  signMlDsa,
  verifyMlDsa,
  encryptBytesWithKey,
  decryptBytesWithKey,
  getDefaultPqcProvider,
  ENCLAVE_PQ_SUITE_V1,
} from "@enclave/pqc-primitives";

const provider = getDefaultPqcProvider();
console.log(provider.suiteId, ENCLAVE_PQ_SUITE_V1.algorithms.kem.id);
```

Subpath exports: `@enclave/pqc-primitives/kem`, `/sign`, `/symmetric`, `/hash`, `/kdf`, `/encoding`, `/registry`, `/provider`.

## Provider model

`noblePqcProvider` is the default implementation (`@noble/post-quantum`, `@noble/ciphers`, `@noble/hashes`). A future `fips` provider can implement the same `PqcProvider` interface for FIPS 140-3 validated deployments without changing product SDK APIs.

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```

## Product integration

| Product SDK | Uses pqc-primitives for |
|-------------|-------------------------|
| `@enclave/sign-sdk` | Document DEK wrap (ML-KEM), manifest signatures (ML-DSA), AES-GCM |
| `@enclave/verify-sdk` | Credential signatures (ML-DSA), Merkle hashes (SHAKE256) |
| `@enclave/messaging-sdk` | Message epochs, sidechains, attachments, call keys |

**Rule:** no product repo or API handler imports low-level PQ libraries directly — only `@enclave/pqc-primitives` (via the product SDK).

## Commercial licensing

AGPL-3.0 applies to this package. Contact Enclave for commercial licensing if you need to use it in proprietary software without AGPL obligations.
