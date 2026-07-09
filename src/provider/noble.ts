import { labeledKdf } from "../kdf/labeled.js";
import { hashPair, hashUtf8, shake256Bytes } from "../hash/shake256.js";
import {
  decapsulateMlKem,
  encapsulateMlKem,
  generateMlKemKeypair,
} from "../kem/ml-kem768.js";
import { SUITE_ID } from "../registry/suite.js";
import {
  generateMlDsaKeypair,
  signMlDsa,
  verifyMlDsa,
} from "../sign/ml-dsa65.js";
import {
  decryptAesGcmBytes,
  decryptBytesWithKey,
  encryptAesGcmBytes,
  encryptBytesWithKey,
} from "../symmetric/aes-gcm.js";
import type { PqcProvider } from "./types.js";

export const noblePqcProvider: PqcProvider = {
  id: "noble",
  suiteId: SUITE_ID,
  kem: {
    generateKeypair: generateMlKemKeypair,
    encapsulate: encapsulateMlKem,
    decapsulate: decapsulateMlKem,
  },
  sign: {
    generateKeypair: generateMlDsaKeypair,
    sign: signMlDsa,
    verify: verifyMlDsa,
  },
  symmetric: {
    encrypt: encryptAesGcmBytes,
    decrypt: decryptAesGcmBytes,
    encryptWithKey: encryptBytesWithKey,
    decryptWithKey: decryptBytesWithKey,
  },
  hash: {
    shake256: shake256Bytes,
    hashUtf8,
    hashPair,
  },
  kdf: {
    labeled: labeledKdf,
  },
};

let defaultProvider: PqcProvider = noblePqcProvider;

export function getDefaultPqcProvider(): PqcProvider {
  return defaultProvider;
}

export function setDefaultPqcProvider(provider: PqcProvider): void {
  defaultProvider = provider;
}
