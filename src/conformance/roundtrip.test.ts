import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  decapsulateMlKem,
  encapsulateMlKem,
  generateMlKemKeypair,
} from "../kem/ml-kem768.js";
import {
  generateMlDsaKeypair,
  signMlDsa,
  verifyMlDsa,
} from "../sign/ml-dsa65.js";
import {
  decryptBytesWithKey,
  encryptBytesWithKey,
} from "../symmetric/aes-gcm.js";
import { labeledKdf } from "../kdf/labeled.js";
import { ENCLAVE_PQ_SUITE_V1 } from "../registry/suite.js";

describe("ENCLAVE_PQ_SUITE_v1", () => {
  it("declares NIST-aligned algorithms", () => {
    assert.equal(ENCLAVE_PQ_SUITE_V1.algorithms.kem.id, "ML-KEM-768");
    assert.equal(ENCLAVE_PQ_SUITE_V1.algorithms.signature.id, "ML-DSA-65");
    assert.equal(ENCLAVE_PQ_SUITE_V1.algorithms.symmetric.id, "AES-256-GCM");
  });
});

describe("ML-KEM-768", () => {
  it("round-trips shared secret", () => {
    const recipient = generateMlKemKeypair();
    const encapsulated = encapsulateMlKem(recipient.publicKey);
    const shared = decapsulateMlKem(encapsulated.cipherText, recipient.secretKey);
    assert.deepEqual(shared, encapsulated.sharedSecret);
  });
});

describe("ML-DSA-65", () => {
  it("signs and verifies", () => {
    const keys = generateMlDsaKeypair();
    const message = new TextEncoder().encode("enclave-pqc-core");
    const signature = signMlDsa(keys.secretKey, message);
    assert.equal(verifyMlDsa(keys.publicKey, message, signature), true);
  });
});

describe("AES-256-GCM", () => {
  it("encrypts and decrypts with AAD", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const aad = new TextEncoder().encode("context:test");
    const plaintext = new TextEncoder().encode("hello pq");

    const encrypted = await encryptBytesWithKey({
      plaintext,
      key,
      additionalData: aad,
    });
    const decrypted = await decryptBytesWithKey({
      ciphertext: encrypted.ciphertext,
      key,
      ivBase64: encrypted.ivBase64,
      additionalData: aad,
    });

    assert.deepEqual(decrypted, plaintext);
  });
});

describe("labeled KDF", () => {
  it("derives deterministic output", () => {
    const ikm = new TextEncoder().encode("input-key-material");
    const first = labeledKdf({ label: "test", ikm, length: 32 });
    const second = labeledKdf({ label: "test", ikm, length: 32 });
    assert.deepEqual(first, second);
    assert.notDeepEqual(
      labeledKdf({ label: "other", ikm, length: 32 }),
      first,
    );
  });
});
