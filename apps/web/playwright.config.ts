import { defineConfig } from "@playwright/test";

const PORT = Number(process.env.PORT ?? 4173);

export default defineConfig({
  testDir: "test/e2e",
  timeout: 300_000,
  expect: { timeout: 60_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  outputDir: "test-results",
  use: {
    baseURL: `http://localhost:${PORT}`,
    // Set PW_CHANNEL=chrome to use an installed Chrome instead of Playwright's Chromium.
    channel: process.env.PW_CHANNEL,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "pnpm exec tsx scripts/demo-web.ts",
    url: `http://localhost:${PORT}/runtime-config.json`,
    timeout: 600_000,
    reuseExistingServer: process.env.PW_REUSE === "1",
    stdout: "pipe",
    stderr: "pipe",
  },
});
