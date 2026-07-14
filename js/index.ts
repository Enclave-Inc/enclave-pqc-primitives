/**
 * @enclave/pqc-primitives — JS facade over the WASM binding.
 *
 * Algorithm-namespaced only. Product SDKs must not push session/envelope/token
 * logic into this package.
 *
 * Category 5 exclusively (ML-KEM-1024 / ML-DSA-87). No suite parameter.
 *
 * # Secret zeroization
 *
 * Rust zeroizes secret keys on Drop inside the WASM module. That guarantee
 * does **not** apply to `Uint8Array` copies returned to JavaScript. Call
 * {@link zeroize} on long-lived secret buffers when finished.
 */

export {
  AEAD,
  ENCLAVE_PQ_SUITE_ID,
  HASH,
  KDF_LABEL_PREFIX,
  KEM,
  SIG,
  isPairwiseConsistencyFailure,
  isSelfTestFailure,
  type CryptoUsageRecord,
  type KemEncapsulation,
  type KemKeypair,
  type SigKeypair,
} from "./constants.js";

export {
  aeadDecrypt,
  aeadEncrypt,
  getLastUsageRecord,
  hashUtf8,
  kemDecapsulate,
  /**
   * Hazmat — NIST ACVP / KAT reproduction only. Production code must use
   * {@link kemEncapsulate}.
   */
  kemEncapsulate,
  kemEncapsulateDeterministic,
  kemExpandedSecretKey,
  kemGenerateKeypair,
  kemKeypairFromSeed,
  labeledKdf,
  labeledKdf32,
  runSelfTests,
  shake256,
  sigExpandedSecretKey,
  sigGenerateKeypair,
  sigKeypairFromSeed,
  sigSign,
  sigSignWithContext,
  sigVerify,
  sigVerifyWithContext,
  zeroize,
} from "./wasm.js";
