import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/test/**/*.test.ts", "tests/**/*.test.ts"],
    environment: "node",
    testTimeout: 15000,
    reporters: "default",
  },
});
