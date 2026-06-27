import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { randomBytes } from "@noble/post-quantum/utils.js";

import { bytesToBase64Url } from "../encoding/base64.js";
import { ML_KEM_ALGORITHM } from "../registry/suite.js";

export { ML_KEM_ALGORITHM };

export type MlKemKeypair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type MlKemEncapsulation = {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
};

export function generateMlKemKeypair(seed?: Uint8Array): MlKemKeypair {
  const keys = ml_kem768.keygen(seed ?? randomBytes(64));
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

export function encapsulateMlKem(publicKey: Uint8Array): MlKemEncapsulation {
  return ml_kem768.encapsulate(publicKey);
}

export function decapsulateMlKem(
  cipherText: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  return ml_kem768.decapsulate(cipherText, secretKey);
}

export function encodeMlKemPublicKey(publicKey: Uint8Array): string {
  return bytesToBase64Url(publicKey);
}

export function encodeMlKemSecretKey(secretKey: Uint8Array): string {
  return bytesToBase64Url(secretKey);
}
