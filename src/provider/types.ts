import type {
  decryptAesGcmBytes,
  encryptAesGcmBytes,
  encryptBytesWithKey,
} from "../symmetric/aes-gcm.js";
import type {
  decapsulateMlKem,
  encapsulateMlKem,
  generateMlKemKeypair,
} from "../kem/ml-kem768.js";
import type {
  generateMlDsaKeypair,
  signMlDsa,
  verifyMlDsa,
} from "../sign/ml-dsa65.js";
import type { labeledKdf } from "../kdf/labeled.js";
import type { hashPair, hashUtf8, shake256Bytes } from "../hash/shake256.js";

export type PqcProviderId = "noble" | "fips";

export type PqcProvider = {
  id: PqcProviderId;
  suiteId: "ENCLAVE_PQ_SUITE_v1";
  kem: {
    generateKeypair: typeof generateMlKemKeypair;
    encapsulate: typeof encapsulateMlKem;
    decapsulate: typeof decapsulateMlKem;
  };
  sign: {
    generateKeypair: typeof generateMlDsaKeypair;
    sign: typeof signMlDsa;
    verify: typeof verifyMlDsa;
  };
  symmetric: {
    encrypt: typeof encryptAesGcmBytes;
    decrypt: typeof decryptAesGcmBytes;
    encryptWithKey: typeof encryptBytesWithKey;
  };
  hash: {
    shake256: typeof shake256Bytes;
    hashUtf8: typeof hashUtf8;
    hashPair: typeof hashPair;
  };
  kdf: {
    labeled: typeof labeledKdf;
  };
};
