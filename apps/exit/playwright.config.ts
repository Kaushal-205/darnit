import { defineConfig } from "@playwright/test";

/**
 * Needs Foundry, network access for the Anvil fork, and a build (`pnpm build`).
 * Uses Playwright's Chromium, or an installed browser with E2E_CHANNEL=chrome.
 */
export default defineConfig({
  testDir: "e2e",
  timeout: 15 * 60_000,
  workers: 1,
  reporter: [["list"]],
  use: {
    headless: true,
    channel: process.env.E2E_CHANNEL || undefined,
  },
});
