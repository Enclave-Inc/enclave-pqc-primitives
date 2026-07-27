import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const root = path.dirname(fileURLToPath(import.meta.url));
const nodeDist = path.join(root, "dist", "nodejs", "index.js");

export default defineConfig({
  resolve: {
    alias: {
      "@enclave-technologies/pqc-primitives": nodeDist,
    },
  },
  server: {
    fs: {
      allow: [root],
      // Override Vite's default deny of gitignored paths (dist/ is gitignored).
      deny: [".env", ".env.*", "*.{crt,pem}"],
    },
  },
  test: {
    include: ["tests/js/**/*.test.ts"],
    environment: "node",
  },
});
