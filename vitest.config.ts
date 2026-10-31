import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    globalSetup: ["test/globalSetup.ts"], // fresh integratex_test database per run
    fileParallelism: false, // DB-backed suites share one test database
    testTimeout: 30_000,
    env: { IX_LOG_LEVEL: "silent" },
  },
});
