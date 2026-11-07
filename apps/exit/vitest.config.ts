import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@session-firewall/sdk": fileURLToPath(
        new URL("../../packages/sdk/src/index.ts", import.meta.url),
      ),
    },
  },
  test: { include: ["test/*.test.ts"] },
});
