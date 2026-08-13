#!/usr/bin/env node
/**
 * Build WASM bindings for bundler / nodejs / web targets, then emit JS façades.
 */
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const wasmCrate = join(root, "bindings", "wasm");
const targets = [
  { name: "bundler", out: join(root, "dist", "bundler") },
  { name: "nodejs", out: join(root, "dist", "nodejs") },
  { name: "web", out: join(root, "dist", "web") },
];

function run(cmd, args) {
  console.log(`> ${cmd} ${args.join(" ")}`);
  // Do not use `shell: true` on Windows: paths under
  // `Enclave Technologies Inc\...` get truncated at the first space.
  const result = spawnSync(cmd, args, {
    cwd: root,
    stdio: "inherit",
    shell: false,
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function ensureWasmPack() {
  const check = spawnSync("wasm-pack", ["--version"], {
    // version check has no path args; shell is fine for PATH lookup of .cmd
    shell: process.platform === "win32",
  });
  if (check.status !== 0) {
    console.log("Installing wasm-pack…");
    run("cargo", ["install", "wasm-pack"]);
  }
}

// Sizes must match Rust `kem::*` / `sig::*` / `aead::*` / `hash::*` constants.
const CONSTANTS_JS = `/** @type {const} */
export const ENCLAVE_PQ_SUITE_ID = "ENCLAVE_PQ_SUITE_v1";
/** @type {const} */
export const KDF_LABEL_PREFIX = "enclave-kdf-v1";
/** @type {const} */
export const KEM768 = Object.freeze({
  ALGORITHM: "ML-KEM-768",
  PUBLIC_KEY_BYTES: 1184,
  SECRET_KEY_SEED_BYTES: 64,
  SECRET_KEY_EXPANDED_BYTES: 2400,
  SECRET_KEY_BYTES: 2400,
  CIPHERTEXT_BYTES: 1088,
  SHARED_SECRET_BYTES: 32,
  ENCAP_RANDOMNESS_BYTES: 32,
});
/** @type {const} */
export const SIG65 = Object.freeze({
  ALGORITHM: "ML-DSA-65",
  PUBLIC_KEY_BYTES: 1952,
  SECRET_KEY_SEED_BYTES: 32,
  SECRET_KEY_EXPANDED_BYTES: 4032,
  SECRET_KEY_BYTES: 4032,
  SIGNATURE_BYTES: 3309,
  MAX_CONTEXT_BYTES: 255,
});
/** @type {const} */
export const KEM = Object.freeze({
  ALGORITHM: "ML-KEM-1024",
  PUBLIC_KEY_BYTES: 1568,
  SECRET_KEY_SEED_BYTES: 64,
  SECRET_KEY_EXPANDED_BYTES: 3168,
  SECRET_KEY_BYTES: 3168,
  CIPHERTEXT_BYTES: 1568,
  SHARED_SECRET_BYTES: 32,
  ENCAP_RANDOMNESS_BYTES: 32,
});
/** @type {const} */
export const SIG = Object.freeze({
  ALGORITHM: "ML-DSA-87",
  PUBLIC_KEY_BYTES: 2592,
  SECRET_KEY_SEED_BYTES: 32,
  SECRET_KEY_EXPANDED_BYTES: 4896,
  SECRET_KEY_BYTES: 4896,
  SIGNATURE_BYTES: 4627,
  MAX_CONTEXT_BYTES: 255,
});
/** @type {const} */
export const AEAD = Object.freeze({
  ALGORITHM: "AES-256-GCM",
  KEY_BYTES: 32,
  NONCE_BYTES: 12,
  TAG_BYTES: 16,
});
/** @type {const} */
export const HASH = Object.freeze({
  ALGORITHM: "SHAKE256",
  DEFAULT_OUTPUT_BYTES: 32,
});
/** @type {const} */
export const PWHASH = Object.freeze({
  ALGORITHM: "Argon2id",
  SALT_BYTES: 16,
  OUTPUT_BYTES: 32,
  /**
   * OWASP Password Storage Cheat Sheet baseline (verified 2026-07-14):
   * m=19456 (19 MiB), t=2, p=1. Deliberately slow + memory-hard — do not
   * lower these for login latency without treating that as a security tradeoff.
   */
  RECOMMENDED_PARAMS: Object.freeze({
    memoryCostKib: 19456,
    iterations: 2,
    parallelism: 1,
  }),
});

/** @param {unknown} err */
export function isPairwiseConsistencyFailure(err) {
  return err instanceof Error && err.name === "PairwiseConsistencyFailureError";
}

/** @param {unknown} err */
export function isSelfTestFailure(err) {
  return err instanceof Error && err.name === "SelfTestFailureError";
}
`;

const INDEX_DTS = `/** Category 5 sizes — must match Rust ENCLAVE_PQ_SUITE_v1. */
export declare const ENCLAVE_PQ_SUITE_ID: "ENCLAVE_PQ_SUITE_v1";
export declare const KDF_LABEL_PREFIX: "enclave-kdf-v1";
export declare const KEM768: {
  readonly ALGORITHM: "ML-KEM-768";
  readonly PUBLIC_KEY_BYTES: 1184;
  readonly SECRET_KEY_SEED_BYTES: 64;
  readonly SECRET_KEY_EXPANDED_BYTES: 2400;
  readonly SECRET_KEY_BYTES: 2400;
  readonly CIPHERTEXT_BYTES: 1088;
  readonly SHARED_SECRET_BYTES: 32;
  readonly ENCAP_RANDOMNESS_BYTES: 32;
};
export declare const SIG65: {
  readonly ALGORITHM: "ML-DSA-65";
  readonly PUBLIC_KEY_BYTES: 1952;
  readonly SECRET_KEY_SEED_BYTES: 32;
  readonly SECRET_KEY_EXPANDED_BYTES: 4032;
  readonly SECRET_KEY_BYTES: 4032;
  readonly SIGNATURE_BYTES: 3309;
  readonly MAX_CONTEXT_BYTES: 255;
};
export declare const KEM: {
  readonly ALGORITHM: "ML-KEM-1024";
  readonly PUBLIC_KEY_BYTES: 1568;
  readonly SECRET_KEY_SEED_BYTES: 64;
  readonly SECRET_KEY_EXPANDED_BYTES: 3168;
  readonly SECRET_KEY_BYTES: 3168;
  readonly CIPHERTEXT_BYTES: 1568;
  readonly SHARED_SECRET_BYTES: 32;
  readonly ENCAP_RANDOMNESS_BYTES: 32;
};
export declare const SIG: {
  readonly ALGORITHM: "ML-DSA-87";
  readonly PUBLIC_KEY_BYTES: 2592;
  readonly SECRET_KEY_SEED_BYTES: 32;
  readonly SECRET_KEY_EXPANDED_BYTES: 4896;
  readonly SECRET_KEY_BYTES: 4896;
  readonly SIGNATURE_BYTES: 4627;
  readonly MAX_CONTEXT_BYTES: 255;
};
export declare const AEAD: {
  readonly ALGORITHM: "AES-256-GCM";
  readonly KEY_BYTES: 32;
  readonly NONCE_BYTES: 12;
  readonly TAG_BYTES: 16;
};
export declare const HASH: {
  readonly ALGORITHM: "SHAKE256";
  readonly DEFAULT_OUTPUT_BYTES: 32;
};
export declare const PWHASH: {
  readonly ALGORITHM: "Argon2id";
  readonly SALT_BYTES: 16;
  readonly OUTPUT_BYTES: 32;
  readonly RECOMMENDED_PARAMS: {
    readonly memoryCostKib: 19456;
    readonly iterations: 2;
    readonly parallelism: 1;
  };
};

export type Argon2Params = {
  memoryCostKib: number;
  iterations: number;
  parallelism: number;
};

export type KemKeypair = { publicKey: Uint8Array; secretKey: Uint8Array };
export type KemEncapsulation = {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
};
export type SigKeypair = { publicKey: Uint8Array; secretKey: Uint8Array };
export type CryptoUsageRecord = {
  algorithm: string;
  suiteId: string;
  operation: string;
  crateVersion: string;
};

export declare function isPairwiseConsistencyFailure(err: unknown): boolean;
export declare function isSelfTestFailure(err: unknown): boolean;

export declare function kemGenerateKeypair(): KemKeypair;
export declare function kemKeypairFromSeed(seed: Uint8Array): KemKeypair;
export declare function kemExpandedSecretKey(secretKey: Uint8Array): Uint8Array;
export declare function kemEncapsulate(publicKey: Uint8Array): KemEncapsulation;
/** Hazmat — KATs only. Prefer kemEncapsulate. */
export declare function kemEncapsulateDeterministic(
  publicKey: Uint8Array,
  m: Uint8Array,
): KemEncapsulation;
export declare function kemDecapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array;

export declare function sigGenerateKeypair(): SigKeypair;
export declare function sigKeypairFromSeed(seed: Uint8Array): SigKeypair;
export declare function sigExpandedSecretKey(secretKey: Uint8Array): Uint8Array;
export declare function sigSign(
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array;
export declare function sigSignWithContext(
  secretKey: Uint8Array,
  message: Uint8Array,
  context: Uint8Array,
): Uint8Array;
export declare function sigVerify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean;
export declare function sigVerifyWithContext(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  context: Uint8Array,
): boolean;

export declare function kem768GenerateKeypair(): KemKeypair;
export declare function kem768KeypairFromSeed(seed: Uint8Array): KemKeypair;
export declare function kem768ExpandedSecretKey(secretKey: Uint8Array): Uint8Array;
export declare function kem768Encapsulate(publicKey: Uint8Array): KemEncapsulation;
/** Hazmat — KATs only. Prefer kem768Encapsulate. */
export declare function kem768EncapsulateDeterministic(
  publicKey: Uint8Array,
  m: Uint8Array,
): KemEncapsulation;
export declare function kem768Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array;

export declare function sig65GenerateKeypair(): SigKeypair;
export declare function sig65KeypairFromSeed(seed: Uint8Array): SigKeypair;
export declare function sig65ExpandedSecretKey(secretKey: Uint8Array): Uint8Array;
export declare function sig65Sign(
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array;
export declare function sig65SignWithContext(
  secretKey: Uint8Array,
  message: Uint8Array,
  context: Uint8Array,
): Uint8Array;
export declare function sig65Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean;
export declare function sig65VerifyWithContext(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  context: Uint8Array,
): boolean;

export declare function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array;
export declare function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array;

export declare function shake256(
  input: Uint8Array,
  outputLen: number,
): Uint8Array;
export declare function hashUtf8(value: string, outputLen: number): Uint8Array;

export declare function labeledKdf(
  label: string,
  ikm: Uint8Array,
  length: number,
): Uint8Array;
export declare function labeledKdf32(
  label: string,
  ikm: Uint8Array,
): Uint8Array;

/**
 * Argon2id password → 32-byte key. Deliberately slow / memory-hard.
 * Prefer PWHASH.RECOMMENDED_PARAMS unless you have measured otherwise.
 */
export declare function pwhashDeriveKey(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params,
): Uint8Array;
/** Cryptographically random 16-byte Argon2id salt. */
export declare function generateSalt(): Uint8Array;
/** Same values as PWHASH.RECOMMENDED_PARAMS (WASM mirror). */
export declare function RECOMMENDED_PARAMS(): Argon2Params;

/** CBOM attach point: usage from the last WASM primitive call, or undefined. */
export declare function getLastUsageRecord(): CryptoUsageRecord | undefined;

/** CAST self-tests; rejects with SelfTestFailureError (\`err.name\`). */
export declare function runSelfTests(): Promise<void>;

/**
 * Overwrite buffer bytes in place. WASM Drop zeroization does not apply to
 * secret material copied into JS Uint8Arrays — call this when finished.
 */
export declare function zeroize(buf: Uint8Array): void;
`;

function indexJs(targetName) {
  const header = `/**
 * @enclave-technologies/pqc-primitives — algorithm-only façade (${targetName}).
 *
 * Category 5 (ML-KEM-1024 / ML-DSA-87) and Category 3 (ML-KEM-768 / ML-DSA-65).
 *
 * Secret zeroization does NOT cross the WASM boundary. Call zeroize(buf) on
 * long-lived secret Uint8Arrays when finished.
 */
export {
  AEAD,
  ENCLAVE_PQ_SUITE_ID,
  HASH,
  KDF_LABEL_PREFIX,
  KEM,
  KEM768,
  PWHASH,
  SIG,
  SIG65,
  isPairwiseConsistencyFailure,
  isSelfTestFailure,
} from "./constants.js";
`;

  if (targetName === "nodejs") {
    // wasm-pack --target nodejs emits CommonJS (`exports.*`), which Node ESM
    // cannot named-import. Bridge via createRequire.
    return `${header}
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const wasm = require("./enclave_pqc_primitives_wasm.cjs");

export const aeadDecrypt = wasm.aeadDecrypt;
export const aeadEncrypt = wasm.aeadEncrypt;
export const getLastUsageRecord = wasm.getLastUsageRecord;
export const hashUtf8 = wasm.hashUtf8;
export const kemDecapsulate = wasm.kemDecapsulate;
export const kemEncapsulate = wasm.kemEncapsulate;
/** Hazmat — KATs only. Prefer kemEncapsulate in production. */
export const kemEncapsulateDeterministic = wasm.kemEncapsulateDeterministic;
export const kemExpandedSecretKey = wasm.kemExpandedSecretKey;
export const kemGenerateKeypair = wasm.kemGenerateKeypair;
export const kemKeypairFromSeed = wasm.kemKeypairFromSeed;
export const labeledKdf = wasm.labeledKdf;
export const labeledKdf32 = wasm.labeledKdf32;
export const pwhashDeriveKey = wasm.pwhashDeriveKey;
export const generateSalt = wasm.generateSalt;
export const RECOMMENDED_PARAMS = wasm.RECOMMENDED_PARAMS;
export const shake256 = wasm.shake256;
export const sigExpandedSecretKey = wasm.sigExpandedSecretKey;
export const sigGenerateKeypair = wasm.sigGenerateKeypair;
export const sigKeypairFromSeed = wasm.sigKeypairFromSeed;
export const sigSign = wasm.sigSign;
export const sigSignWithContext = wasm.sigSignWithContext;
export const sigVerify = wasm.sigVerify;
export const sigVerifyWithContext = wasm.sigVerifyWithContext;
export const kem768Decapsulate = wasm.kem768Decapsulate;
export const kem768Encapsulate = wasm.kem768Encapsulate;
export const kem768EncapsulateDeterministic = wasm.kem768EncapsulateDeterministic;
export const kem768ExpandedSecretKey = wasm.kem768ExpandedSecretKey;
export const kem768GenerateKeypair = wasm.kem768GenerateKeypair;
export const kem768KeypairFromSeed = wasm.kem768KeypairFromSeed;
export const sig65ExpandedSecretKey = wasm.sig65ExpandedSecretKey;
export const sig65GenerateKeypair = wasm.sig65GenerateKeypair;
export const sig65KeypairFromSeed = wasm.sig65KeypairFromSeed;
export const sig65Sign = wasm.sig65Sign;
export const sig65SignWithContext = wasm.sig65SignWithContext;
export const sig65Verify = wasm.sig65Verify;
export const sig65VerifyWithContext = wasm.sig65VerifyWithContext;
export const zeroize = wasm.zeroize;

/** Run CAST self-tests; throws SelfTestFailureError on failure. */
export async function runSelfTests() {
  wasm.runSelfTests();
}
`;
  }

  if (targetName === "web") {
    // wasm-pack --target web needs an async init before any export works.
    // Browsers / Expo Metro should serve the .wasm from a known URL (e.g.
    // /enclave_pqc_primitives_wasm_bg.wasm in Expo public/).
    return `${header}
import init, {
  aeadDecrypt,
  aeadEncrypt,
  generateSalt,
  getLastUsageRecord,
  hashUtf8,
  kemDecapsulate,
  kemEncapsulate,
  kemEncapsulateDeterministic,
  kemExpandedSecretKey,
  kemGenerateKeypair,
  kemKeypairFromSeed,
  kem768Decapsulate,
  kem768Encapsulate,
  kem768EncapsulateDeterministic,
  kem768ExpandedSecretKey,
  kem768GenerateKeypair,
  kem768KeypairFromSeed,
  labeledKdf,
  labeledKdf32,
  pwhashDeriveKey,
  RECOMMENDED_PARAMS,
  runSelfTests as runSelfTestsSync,
  shake256,
  sigExpandedSecretKey,
  sigGenerateKeypair,
  sigKeypairFromSeed,
  sigSign,
  sigSignWithContext,
  sigVerify,
  sigVerifyWithContext,
  sig65ExpandedSecretKey,
  sig65GenerateKeypair,
  sig65KeypairFromSeed,
  sig65Sign,
  sig65SignWithContext,
  sig65Verify,
  sig65VerifyWithContext,
  zeroize,
} from "./enclave_pqc_primitives_wasm.js";

export {
  aeadDecrypt,
  aeadEncrypt,
  generateSalt,
  getLastUsageRecord,
  hashUtf8,
  kemDecapsulate,
  kemEncapsulate,
  /** Hazmat — KATs only. Prefer kemEncapsulate in production. */
  kemEncapsulateDeterministic,
  kemExpandedSecretKey,
  kemGenerateKeypair,
  kemKeypairFromSeed,
  kem768Decapsulate,
  kem768Encapsulate,
  kem768EncapsulateDeterministic,
  kem768ExpandedSecretKey,
  kem768GenerateKeypair,
  kem768KeypairFromSeed,
  labeledKdf,
  labeledKdf32,
  pwhashDeriveKey,
  RECOMMENDED_PARAMS,
  shake256,
  sigExpandedSecretKey,
  sigGenerateKeypair,
  sigKeypairFromSeed,
  sigSign,
  sigSignWithContext,
  sigVerify,
  sigVerifyWithContext,
  sig65ExpandedSecretKey,
  sig65GenerateKeypair,
  sig65KeypairFromSeed,
  sig65Sign,
  sig65SignWithContext,
  sig65Verify,
  sig65VerifyWithContext,
  zeroize,
};

let readyPromise;

/**
 * Initialize the WASM module once.
 * @param {string | URL | Request | undefined} moduleOrPath
 */
export async function ensureWasm(moduleOrPath) {
  if (!readyPromise) {
    const path =
      moduleOrPath ??
      (typeof window !== "undefined"
        ? "/enclave_pqc_primitives_wasm_bg.wasm"
        : undefined);
    readyPromise = init(
      path !== undefined ? { module_or_path: path } : undefined,
    );
  }
  await readyPromise;
}

/** Run CAST self-tests; throws SelfTestFailureError on failure. */
export async function runSelfTests(moduleOrPath) {
  await ensureWasm(moduleOrPath);
  runSelfTestsSync();
}
`;
  }

  return `${header}
import {
  aeadDecrypt,
  aeadEncrypt,
  generateSalt,
  getLastUsageRecord,
  hashUtf8,
  kemDecapsulate,
  kemEncapsulate,
  kemEncapsulateDeterministic,
  kemExpandedSecretKey,
  kemGenerateKeypair,
  kemKeypairFromSeed,
  kem768Decapsulate,
  kem768Encapsulate,
  kem768EncapsulateDeterministic,
  kem768ExpandedSecretKey,
  kem768GenerateKeypair,
  kem768KeypairFromSeed,
  labeledKdf,
  labeledKdf32,
  pwhashDeriveKey,
  RECOMMENDED_PARAMS,
  runSelfTests as runSelfTestsSync,
  shake256,
  sigExpandedSecretKey,
  sigGenerateKeypair,
  sigKeypairFromSeed,
  sigSign,
  sigSignWithContext,
  sigVerify,
  sigVerifyWithContext,
  sig65ExpandedSecretKey,
  sig65GenerateKeypair,
  sig65KeypairFromSeed,
  sig65Sign,
  sig65SignWithContext,
  sig65Verify,
  sig65VerifyWithContext,
  zeroize,
} from "./enclave_pqc_primitives_wasm.js";

export {
  aeadDecrypt,
  aeadEncrypt,
  generateSalt,
  getLastUsageRecord,
  hashUtf8,
  kemDecapsulate,
  kemEncapsulate,
  /** Hazmat — KATs only. Prefer kemEncapsulate in production. */
  kemEncapsulateDeterministic,
  kemExpandedSecretKey,
  kemGenerateKeypair,
  kemKeypairFromSeed,
  kem768Decapsulate,
  kem768Encapsulate,
  kem768EncapsulateDeterministic,
  kem768ExpandedSecretKey,
  kem768GenerateKeypair,
  kem768KeypairFromSeed,
  labeledKdf,
  labeledKdf32,
  pwhashDeriveKey,
  RECOMMENDED_PARAMS,
  shake256,
  sigExpandedSecretKey,
  sigGenerateKeypair,
  sigKeypairFromSeed,
  sigSign,
  sigSignWithContext,
  sigVerify,
  sigVerifyWithContext,
  sig65ExpandedSecretKey,
  sig65GenerateKeypair,
  sig65KeypairFromSeed,
  sig65Sign,
  sig65SignWithContext,
  sig65Verify,
  sig65VerifyWithContext,
  zeroize,
};

/** Run CAST self-tests; throws SelfTestFailureError on failure. */
export async function runSelfTests() {
  runSelfTestsSync();
}
`;
}

ensureWasmPack();
run("rustup", ["target", "add", "wasm32-unknown-unknown"]);

rmSync(join(root, "dist"), { recursive: true, force: true });

for (const target of targets) {
  mkdirSync(target.out, { recursive: true });
  run("wasm-pack", [
    "build",
    wasmCrate,
    "--release",
    "--target",
    target.name,
    "--out-dir",
    target.out,
    "--out-name",
    "enclave_pqc_primitives_wasm",
  ]);
  for (const junk of ["package.json", ".gitignore", "README.md"]) {
    try {
      rmSync(join(target.out, junk));
    } catch {
      /* ignore */
    }
  }

  writeFileSync(join(target.out, "constants.js"), CONSTANTS_JS);
  writeFileSync(join(target.out, "index.js"), indexJs(target.name));
  writeFileSync(join(target.out, "index.d.ts"), INDEX_DTS);

  if (target.name === "nodejs") {
    // package.json has "type":"module"; wasm-pack nodejs glue is CommonJS.
    renameSync(
      join(target.out, "enclave_pqc_primitives_wasm.js"),
      join(target.out, "enclave_pqc_primitives_wasm.cjs"),
    );
  }

  if (target.name === "web") {
    // Metro / classic script tags cannot parse import.meta. Pin WASM to
    // the site-root path Expo serves from /public.
    const gluePath = join(target.out, "enclave_pqc_primitives_wasm.js");
    const glue = readFileSync(gluePath, "utf8");
    const patched = glue.replace(
      /module_or_path\s*=\s*new URL\([^)]*import\.meta\.url\);/,
      "module_or_path = '/enclave_pqc_primitives_wasm_bg.wasm';",
    );
    if (patched === glue) {
      throw new Error(
        "web wasm glue: expected import.meta URL for wasm path; pattern missing",
      );
    }
    writeFileSync(gluePath, patched);
  }
}

console.log("WASM bindings built → dist/{bundler,nodejs,web}");
