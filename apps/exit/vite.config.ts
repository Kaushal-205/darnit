import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

/**
 * One self-contained file: every script and style is inlined into dist/exit.html, nothing is fetched
 * at runtime except the RPC and bundler URLs the user types in. scripts/finalize.ts then pins the
 * inlined script and style by hash in the Content-Security-Policy.
 */
export default defineConfig({
  base: "./",
  resolve: {
    alias: {
      // Use the SDK sources directly (no separate SDK build step).
      "@session-firewall/sdk": fileURLToPath(
        new URL("../../packages/sdk/src/index.ts", import.meta.url),
      ),
    },
  },
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    sourcemap: false,
    rollupOptions: { input: "exit.html" },
  },
  plugins: [viteSingleFile({ removeViteModuleLoader: true })],
});
