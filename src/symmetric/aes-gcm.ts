import { gcm } from "@noble/ciphers/aes.js";

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

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

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

  if (keyBytes.length !== AES_GCM_KEY_BYTES) {
    throw new Error(`AES-256-GCM requires a ${AES_GCM_KEY_BYTES}-byte key`);
  }
  if (iv.length !== AES_GCM_IV_BYTES) {
    throw new Error(`AES-256-GCM requires a ${AES_GCM_IV_BYTES}-byte IV`);
  }

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
  return decryptAesGcmBytes({
    ciphertext: input.ciphertext,
    keyBase64: bytesToBase64(input.key),
    ivBase64: input.ivBase64,
    additionalData: input.additionalData,
  });
}
