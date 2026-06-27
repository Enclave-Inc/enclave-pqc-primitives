import { shake256Bytes } from "../hash/shake256.js";

const encoder = new TextEncoder();

export const KDF_LABEL_PREFIX = "enclave-kdf-v1" as const;

export function labeledKdf(input: {
  label: string;
  ikm: Uint8Array;
  length?: number;
}): Uint8Array {
  const length = input.length ?? 32;
  const domain = encoder.encode(`${KDF_LABEL_PREFIX}:${input.label}:`);
  const material = new Uint8Array(domain.length + input.ikm.length);
  material.set(domain);
  material.set(input.ikm, domain.length);
  return shake256Bytes(material, length);
}
