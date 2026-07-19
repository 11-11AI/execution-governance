import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Resolve the workspace packages to their TypeScript source so `npm test` needs
// no build step. Examples and the published packages still use built dist.
const gateSrc = fileURLToPath(new URL("./packages/gate/src/index.ts", import.meta.url));
const mcpGateSrc = fileURLToPath(new URL("./packages/mcp-gate/src/index.ts", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@11ai/execution-governance": gateSrc,
      "@11ai/mcp-gate": mcpGateSrc,
    },
  },
  test: {
    include: ["packages/**/test/**/*.test.ts", "tests/**/*.test.ts"],
    environment: "node",
    testTimeout: 15000,
    reporters: "default",
  },
});
