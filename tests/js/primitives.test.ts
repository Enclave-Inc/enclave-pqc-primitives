import { describe, expect, it } from "vitest";
import {
  AEAD,
  HASH,
  KDF_LABEL_PREFIX,
  KEM,
  PWHASH,
  SIG,
  aeadDecrypt,
  aeadEncrypt,
  generateSalt,
  getLastUsageRecord,
  hashUtf8,
  isSelfTestFailure,
  kemDecapsulate,
  kemEncapsulate,
  kemExpandedSecretKey,
  kemGenerateKeypair,
  labeledKdf,
  labeledKdf32,
  pwhashDeriveKey,
  RECOMMENDED_PARAMS,
  runSelfTests,
  shake256,
  sigGenerateKeypair,
  sigSign,
  sigSignWithContext,
  sigVerify,
  sigVerifyWithContext,
  zeroize,
} from "@enclave-technologies/pqc-primitives";

describe("@enclave-technologies/pqc-primitives wasm bindings (Category 5)", () => {
  it("exports Category 5 suite size constants", () => {
    expect(KEM.ALGORITHM).toBe("ML-KEM-1024");
    expect(KEM.PUBLIC_KEY_BYTES).toBe(1568);
    expect(KEM.SECRET_KEY_BYTES).toBe(3168);
    expect(KEM.CIPHERTEXT_BYTES).toBe(1568);
    expect(SIG.ALGORITHM).toBe("ML-DSA-87");
    expect(SIG.PUBLIC_KEY_BYTES).toBe(2592);
    expect(SIG.SECRET_KEY_BYTES).toBe(4896);
    expect(SIG.SIGNATURE_BYTES).toBe(4627);
    expect(AEAD.NONCE_BYTES).toBe(12);
    expect(HASH.DEFAULT_OUTPUT_BYTES).toBe(32);
    expect(KDF_LABEL_PREFIX).toBe("enclave-kdf-v1");
    expect(PWHASH.ALGORITHM).toBe("Argon2id");
    expect(PWHASH.SALT_BYTES).toBe(16);
    expect(PWHASH.OUTPUT_BYTES).toBe(32);
    expect(PWHASH.RECOMMENDED_PARAMS).toEqual({
      memoryCostKib: 19456,
      iterations: 2,
      parallelism: 1,
    });
  });

  it("passes CAST self-tests", async () => {
    await expect(runSelfTests()).resolves.toBeUndefined();
  });

  it("round-trips ML-DSA-87 sign/verify", () => {
    const kp = sigGenerateKeypair();
    expect(kp.publicKey.length).toBe(SIG.PUBLIC_KEY_BYTES);
    expect(kp.secretKey.length).toBe(SIG.SECRET_KEY_SEED_BYTES);
    const message = new TextEncoder().encode("challenge");
    const signature = sigSign(kp.secretKey, message);
    expect(signature.length).toBe(SIG.SIGNATURE_BYTES);
    expect(sigVerify(kp.publicKey, message, signature)).toBe(true);
    expect(sigVerify(kp.publicKey, new TextEncoder().encode("other"), signature)).toBe(
      false,
    );
    const usage = getLastUsageRecord();
    expect(usage?.algorithm).toBe("ML-DSA-87");
    expect(usage?.suiteId).toBe("ENCLAVE_PQ_SUITE_v1");
    zeroize(kp.secretKey);
  });

  it("sigSignWithContext rejects empty message and oversized context", () => {
    const kp = sigGenerateKeypair();
    const empty = new Uint8Array();
    expect(() => sigSignWithContext(kp.secretKey, empty, empty)).toThrow(/InvalidLength/);
    const oversized = new Uint8Array(SIG.MAX_CONTEXT_BYTES + 1);
    expect(() =>
      sigSignWithContext(kp.secretKey, new TextEncoder().encode("x"), oversized),
    ).toThrow(/InvalidParameter/);
    const ctx = new TextEncoder().encode("domain");
    const sig = sigSignWithContext(kp.secretKey, new TextEncoder().encode("x"), ctx);
    expect(sigVerifyWithContext(kp.publicKey, new TextEncoder().encode("x"), sig, ctx)).toBe(
      true,
    );
    zeroize(kp.secretKey);
  });

  it("round-trips ML-KEM-1024 encapsulate/decapsulate", () => {
    const kp = kemGenerateKeypair();
    expect(kp.publicKey.length).toBe(KEM.PUBLIC_KEY_BYTES);
    expect(kp.secretKey.length).toBe(KEM.SECRET_KEY_SEED_BYTES);
    const expanded = kemExpandedSecretKey(kp.secretKey);
    expect(expanded.length).toBe(KEM.SECRET_KEY_BYTES);
    const enc = kemEncapsulate(kp.publicKey);
    expect(enc.ciphertext.length).toBe(KEM.CIPHERTEXT_BYTES);
    expect(enc.sharedSecret.length).toBe(KEM.SHARED_SECRET_BYTES);
    const shared = kemDecapsulate(enc.ciphertext, kp.secretKey);
    expect(Buffer.from(shared)).toEqual(Buffer.from(enc.sharedSecret));
    const usage = getLastUsageRecord();
    expect(usage?.algorithm).toBe("ML-KEM-1024");
    zeroize(kp.secretKey);
    zeroize(enc.sharedSecret);
    zeroize(expanded);
  });

  it("round-trips AES-256-GCM encrypt/decrypt", () => {
    const key = labeledKdf32("aes-256-gcm-key", new Uint8Array(32).fill(7));
    const nonce = new Uint8Array(AEAD.NONCE_BYTES).fill(9);
    const plaintext = new TextEncoder().encode("hello aead");
    const aad = new TextEncoder().encode("hdr");
    const sealed = aeadEncrypt(key, nonce, plaintext, aad);
    expect(sealed.length).toBe(plaintext.length + AEAD.TAG_BYTES);
    const opened = aeadDecrypt(key, nonce, sealed, aad);
    expect(new TextDecoder().decode(opened)).toBe("hello aead");
    expect(() => aeadDecrypt(key, nonce, sealed, new TextEncoder().encode("bad"))).toThrow(
      /AeadFailure/,
    );
    zeroize(key);
  });

  it("rejects wrong AEAD key/nonce lengths without truncating", () => {
    const plaintext = new Uint8Array([1, 2, 3]);
    expect(() =>
      aeadEncrypt(new Uint8Array(16), new Uint8Array(12), plaintext, new Uint8Array()),
    ).toThrow(/InvalidLength/);
    expect(() =>
      aeadEncrypt(new Uint8Array(32), new Uint8Array(8), plaintext, new Uint8Array()),
    ).toThrow(/InvalidLength/);
  });

  it("labeledKdf is deterministic and rejects empty label", () => {
    const ikm = new Uint8Array([1, 2, 3, 4]);
    const a = labeledKdf("test", ikm, 32);
    const b = labeledKdf("test", ikm, 32);
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
    expect(labeledKdf("test", ikm, 16)).toEqual(a.subarray(0, 16));
    expect(() => labeledKdf("", ikm, 32)).toThrow(/InvalidParameter/);
    expect(() => labeledKdf("x", ikm, 0)).toThrow(/InvalidParameter/);
  });

  it("shake256 / hashUtf8 produce fixed-length digests", () => {
    const dig = shake256(new TextEncoder().encode("abc"), 32);
    expect(dig.length).toBe(32);
    expect(hashUtf8("abc", 32)).toEqual(dig);
  });

  it("pwhashDeriveKey is deterministic; salts diversify; records usage", () => {
    const password = new TextEncoder().encode("correct horse battery staple");
    const saltA = new Uint8Array(PWHASH.SALT_BYTES).fill(0x11);
    const saltB = new Uint8Array(PWHASH.SALT_BYTES).fill(0x22);
    const params = PWHASH.RECOMMENDED_PARAMS;
    expect(RECOMMENDED_PARAMS()).toEqual(params);

    const a1 = pwhashDeriveKey(password, saltA, params);
    const a2 = pwhashDeriveKey(password, saltA, params);
    expect(a1.length).toBe(PWHASH.OUTPUT_BYTES);
    expect(Buffer.from(a1)).toEqual(Buffer.from(a2));

    const b = pwhashDeriveKey(password, saltB, params);
    expect(Buffer.from(a1)).not.toEqual(Buffer.from(b));

    const usage = getLastUsageRecord();
    expect(usage?.algorithm).toBe("Argon2id");
    expect(usage?.operation).toBe("pwhash_derive_key");
    zeroize(a1);
    zeroize(a2);
    zeroize(b);
  });

  it("generateSalt returns 16 random bytes", () => {
    const s1 = generateSalt();
    const s2 = generateSalt();
    expect(s1.length).toBe(PWHASH.SALT_BYTES);
    expect(s2.length).toBe(PWHASH.SALT_BYTES);
    expect(Buffer.from(s1)).not.toEqual(Buffer.from(s2));
    expect(getLastUsageRecord()?.operation).toBe("pwhash_generate_salt");
  });

  it("logs WASM Argon2id RECOMMENDED_PARAMS timing (observation only)", () => {
    const password = new TextEncoder().encode("wasm-timing-observation");
    const salt = new Uint8Array(PWHASH.SALT_BYTES).fill(0x55);
    const start = performance.now();
    const key = pwhashDeriveKey(password, salt, PWHASH.RECOMMENDED_PARAMS);
    const ms = performance.now() - start;
    // Soft bounds only — not a CI gate. Flag multi-second WASM as a finding.
    console.log(
      `[pwhash] WASM RECOMMENDED_PARAMS elapsed=${ms.toFixed(1)}ms ` +
        `(memory-hard by design; multi-second would be a UX finding)`,
    );
    expect(key.length).toBe(32);
    expect(ms).toBeGreaterThanOrEqual(1);
    expect(ms).toBeLessThan(30_000);
    zeroize(key);
  });

  it("zeroize clears the buffer in place", () => {
    const buf = new Uint8Array([1, 2, 3, 4]);
    zeroize(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0]);
  });

  it("isSelfTestFailure recognizes typed errors", () => {
    const err = new Error("SelfTestFailure: demo");
    err.name = "SelfTestFailureError";
    expect(isSelfTestFailure(err)).toBe(true);
    expect(isSelfTestFailure(new Error("nope"))).toBe(false);
  });
});
