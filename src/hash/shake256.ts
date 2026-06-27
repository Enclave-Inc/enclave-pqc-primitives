import { shake256 } from "@noble/hashes/sha3.js";

import { SHAKE256_ALGORITHM } from "../registry/suite.js";

export { SHAKE256_ALGORITHM };

const encoder = new TextEncoder();

export function shake256Bytes(input: Uint8Array, outputBytes = 32): Uint8Array {
  return shake256(input, { dkLen: outputBytes });
}

/** SHAKE256 leaf for empty padding slots (RFC-style Merkle padding). */
export function paddingLeafHash(): Uint8Array {
  return shake256Bytes(new Uint8Array([0x00]));
}

export function hashClaim(claimKey: string, claimValue: unknown): Uint8Array {
  const input = JSON.stringify({ [claimKey]: claimValue });
  return shake256Bytes(encoder.encode(input));
}

export function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left);
  combined.set(right, left.length);
  return shake256Bytes(combined);
}

export function hashUtf8(value: string, outputBytes = 32): Uint8Array {
  return shake256Bytes(encoder.encode(value), outputBytes);
}
