import suiteJson from "../../registry/ENCLAVE_PQ_SUITE_v1.json" with { type: "json" };

export type EnclavePqSuite = typeof suiteJson;

export const ENCLAVE_PQ_SUITE_V1 = suiteJson;

export const SUITE_ID = ENCLAVE_PQ_SUITE_V1.id as "ENCLAVE_PQ_SUITE_v1";

export const ML_KEM_ALGORITHM =
  ENCLAVE_PQ_SUITE_V1.algorithms.kem.id as "ML-KEM-768";

export const ML_DSA_ALGORITHM =
  ENCLAVE_PQ_SUITE_V1.algorithms.signature.id as "ML-DSA-65";

export const AES_GCM_ALGORITHM =
  ENCLAVE_PQ_SUITE_V1.algorithms.symmetric.id as "AES-256-GCM";

export const SHAKE256_ALGORITHM =
  ENCLAVE_PQ_SUITE_V1.algorithms.hash.id as "SHAKE256";

export const DOCUMENT_ENCRYPTION_ALGORITHM =
  ENCLAVE_PQ_SUITE_V1.compositeLabels
    .documentEncryption as "AES-256-GCM+ML-KEM-768";

export const MANIFEST_SIGNATURE_ALGORITHM =
  ENCLAVE_PQ_SUITE_V1.compositeLabels.manifestSignature as "ML-DSA-65";

export function isDisallowedAlgorithm(name: string): boolean {
  return ENCLAVE_PQ_SUITE_V1.disallowedForNewCode.includes(name);
}
