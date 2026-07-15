/**
 * Re-export the wasm-pack module for this build target.
 * During development against a completed `dist/nodejs` build, tests import
 * from the package root after `npm run build`.
 */

export {
  aeadDecrypt,
  aeadEncrypt,
  generateSalt,
  getLastUsageRecord,
  hashUtf8,
  kemDecapsulate,
  kemEncapsulate,
  kemEncapsulateDeterministic,
  kemExpandedSecretKey,
  kemGenerateKeypair,
  kemKeypairFromSeed,
  labeledKdf,
  labeledKdf32,
  pwhashDeriveKey,
  RECOMMENDED_PARAMS,
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
} from "../dist/nodejs/index.js";
