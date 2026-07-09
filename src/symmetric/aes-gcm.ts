import { gcm } from "@noble/ciphers/aes.js";

import {
  assertByteLength,
  randomBytes,
  toArrayBuffer,
} from "../bytes/index.js";
import { base64ToBytes, bytesToBase64 } from "../encoding/base64.js";
import { AES_GCM_ALGORITHM } from "../registry/suite.js";

export { AES_GCM_ALGORITHM };

const AES_GCM_KEY_BYTES = 32;
const AES_GCM_IV_BYTES = 12;

type AesGcmAlgorithmParams = {
  name: "AES-GCM";
  iv: ArrayBuffer;
  additionalData?: ArrayBuffer;
};

export type AesGcmEncryptResult = {
  ciphertext: Uint8Array;
  keyBase64: string;
  ivBase64: string;
};

export async function encryptAesGcmBytes(input: {
  plaintext: Uint8Array;
  keyBase64?: string;
  ivBase64?: string;
  additionalData?: Uint8Array;
}): Promise<AesGcmEncryptResult> {
  const keyBytes =
    input.keyBase64 != null
      ? base64ToBytes(input.keyBase64)
      : randomBytes(AES_GCM_KEY_BYTES);
  const iv =
    input.ivBase64 != null
      ? base64ToBytes(input.ivBase64)
      : randomBytes(AES_GCM_IV_BYTES);

  assertByteLength(keyBytes, AES_GCM_KEY_BYTES, "AES-256-GCM key");
  assertByteLength(iv, AES_GCM_IV_BYTES, "AES-256-GCM IV");

  if (crypto.subtle) {
    const encryptParams: AesGcmAlgorithmParams = {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
    };
    if (input.additionalData) {
      encryptParams.additionalData = toArrayBuffer(input.additionalData);
    }

    const key = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(keyBytes),
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    const ciphertext = await crypto.subtle.encrypt(
      encryptParams,
      key,
      toArrayBuffer(input.plaintext),
    );

    return {
      ciphertext: new Uint8Array(ciphertext),
      keyBase64: bytesToBase64(keyBytes),
      ivBase64: bytesToBase64(iv),
    };
  }

  const aes = input.additionalData
    ? gcm(keyBytes, iv, input.additionalData)
    : gcm(keyBytes, iv);

  return {
    ciphertext: aes.encrypt(input.plaintext),
    keyBase64: bytesToBase64(keyBytes),
    ivBase64: bytesToBase64(iv),
  };
}

export async function decryptAesGcmBytes(input: {
  ciphertext: Uint8Array;
  keyBase64: string;
  ivBase64: string;
  additionalData?: Uint8Array;
}): Promise<Uint8Array> {
  const keyBytes = base64ToBytes(input.keyBase64);
  const iv = base64ToBytes(input.ivBase64);

  assertByteLength(keyBytes, AES_GCM_KEY_BYTES, "AES-256-GCM key");
  assertByteLength(iv, AES_GCM_IV_BYTES, "AES-256-GCM IV");

  if (crypto.subtle) {
    const decryptParams: AesGcmAlgorithmParams = {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
    };
    if (input.additionalData) {
      decryptParams.additionalData = toArrayBuffer(input.additionalData);
    }

    const key = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(keyBytes),
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const plaintext = await crypto.subtle.decrypt(
      decryptParams,
      key,
      toArrayBuffer(input.ciphertext),
    );

    return new Uint8Array(plaintext);
  }

  const aes = input.additionalData
    ? gcm(keyBytes, iv, input.additionalData)
    : gcm(keyBytes, iv);

  return aes.decrypt(input.ciphertext);
}

export async function encryptBytesWithKey(input: {
  plaintext: Uint8Array;
  key: Uint8Array;
  additionalData?: Uint8Array;
}): Promise<{ ciphertext: Uint8Array; ivBase64: string }> {
  assertByteLength(input.key, AES_GCM_KEY_BYTES, "AES-256-GCM key");

  const result = await encryptAesGcmBytes({
    plaintext: input.plaintext,
    keyBase64: bytesToBase64(input.key),
    additionalData: input.additionalData,
  });

  return {
    ciphertext: result.ciphertext,
    ivBase64: result.ivBase64,
  };
}

export async function decryptBytesWithKey(input: {
  ciphertext: Uint8Array;
  key: Uint8Array;
  ivBase64: string;
  additionalData?: Uint8Array;
}): Promise<Uint8Array> {
  assertByteLength(input.key, AES_GCM_KEY_BYTES, "AES-256-GCM key");

  return decryptAesGcmBytes({
    ciphertext: input.ciphertext,
    keyBase64: bytesToBase64(input.key),
    ivBase64: input.ivBase64,
    additionalData: input.additionalData,
  });
}
