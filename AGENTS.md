# AGENTS.md — enclave-pqc-primitives

Shared NIST-aligned post-quantum primitives for Enclave product SDKs.

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
  registry/         Typed suite constants (loads registry JSON)
  provider/         PqcProvider interface + noble implementation
tests/              Conformance and round-trip tests
```

## Commands

```bash
npm run typecheck
npm test
npm run build
```

## Rules

1. Do not add product-specific logic — this package is primitive-only.
2. Do not import `@noble/post-quantum` outside `src/provider/noble.ts` and primitive impl files.
3. Update `registry/ENCLAVE_PQ_SUITE_v1.json` when changing approved algorithms.
4. Run `npm test` and `npm run build` before finishing changes.

## Consumers

`@enclave/sign-sdk`, `@enclave/verify-sdk`, `@enclave/messaging-sdk` depend on this package.
They reference it via `file:../../Enclave-Inc/enclave-pqc-primitives` in local dev.
