import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      { test: { name: "unit", include: ["test/*.test.ts"] } },
      {
        test: {
          name: "integration",
          include: ["test/integration/*.test.ts"],
          testTimeout: 300_000,
          hookTimeout: 600_000,
          // one Anvil fork and one deployment shared by the whole run
          fileParallelism: false,
          sequence: { concurrent: false },
        },
      },
    ],
  },
});
