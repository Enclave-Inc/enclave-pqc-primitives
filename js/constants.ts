/**
 * Algorithm suite sizes for @enclave/pqc-primitives.
 * Values MUST match the Rust crate constants (ENCLAVE_PQ_SUITE_v1, Category 5).
 *
 * Keygen returns the preferred *seed* secret-key form
 * (`SECRET_KEY_SEED_BYTES`). `SECRET_KEY_BYTES` / `SECRET_KEY_EXPANDED_BYTES`
 * are the FIPS expanded encodings.
 */

/** Canonical suite identifier. */
export const ENCLAVE_PQ_SUITE_ID = "ENCLAVE_PQ_SUITE_v1" as const;

/** Domain-separation prefix for `labeledKdf` / `enclave-kdf-v1`. */
export const KDF_LABEL_PREFIX = "enclave-kdf-v1" as const;

/** ML-KEM-1024 sizes (FIPS 203, NIST Category 5). */
export const KEM = {
  ALGORITHM: "ML-KEM-1024",
  PUBLIC_KEY_BYTES: 1568,
  SECRET_KEY_SEED_BYTES: 64,
  SECRET_KEY_EXPANDED_BYTES: 3168,
  SECRET_KEY_BYTES: 3168,
  CIPHERTEXT_BYTES: 1568,
  SHARED_SECRET_BYTES: 32,
  ENCAP_RANDOMNESS_BYTES: 32,
} as const;

/** ML-DSA-87 sizes (FIPS 204, NIST Category 5). */
export const SIG = {
  ALGORITHM: "ML-DSA-87",
  PUBLIC_KEY_BYTES: 2592,
  SECRET_KEY_SEED_BYTES: 32,
  SECRET_KEY_EXPANDED_BYTES: 4896,
  SECRET_KEY_BYTES: 4896,
  SIGNATURE_BYTES: 4627,
  MAX_CONTEXT_BYTES: 255,
} as const;

/** AES-256-GCM sizes. */
export const AEAD = {
  ALGORITHM: "AES-256-GCM",
  KEY_BYTES: 32,
  NONCE_BYTES: 12,
  TAG_BYTES: 16,
} as const;

/** SHAKE256 defaults. */
export const HASH = {
  ALGORITHM: "SHAKE256",
  DEFAULT_OUTPUT_BYTES: 32,
} as const;

export type KemKeypair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type KemEncapsulation = {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
};

export type SigKeypair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type CryptoUsageRecord = {
  algorithm: string;
  suiteId: string;
  operation: string;
  crateVersion: string;
};

/** True when a thrown error is a keygen PCT failure. */
export function isPairwiseConsistencyFailure(err: unknown): boolean {
  return err instanceof Error && err.name === "PairwiseConsistencyFailureError";
}

/** True when a thrown error is a CAST self-test failure. */
export function isSelfTestFailure(err: unknown): boolean {
  return err instanceof Error && err.name === "SelfTestFailureError";
}
