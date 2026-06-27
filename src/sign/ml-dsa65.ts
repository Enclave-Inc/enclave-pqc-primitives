import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes } from "@noble/post-quantum/utils.js";

import { bytesToBase64Url } from "../encoding/base64.js";
import { ML_DSA_ALGORITHM } from "../registry/suite.js";

export { ML_DSA_ALGORITHM };

export type MlDsaKeypair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export function generateMlDsaKeypair(seed?: Uint8Array): MlDsaKeypair {
  const keys = ml_dsa65.keygen(seed ?? randomBytes(32));
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

export function signMlDsa(
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

export function verifyMlDsa(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  return ml_dsa65.verify(signature, message, publicKey);
}

export function encodeMlDsaPublicKey(publicKey: Uint8Array): string {
  return bytesToBase64Url(publicKey);
}

export function encodeMlDsaSignature(signature: Uint8Array): string {
  return bytesToBase64Url(signature);
}
