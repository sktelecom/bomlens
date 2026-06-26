import { defineConfig } from "@playwright/test";

// Boot smoke for the Electron desktop app. Launches the app on the runner's OS
// (Windows/macOS in CI) and asserts the first screen renders. No browser
// download is needed — Playwright drives the app's own Electron binary.
export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  reporter: "line",
});
