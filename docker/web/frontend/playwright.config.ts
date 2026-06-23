import { defineConfig, devices } from "@playwright/test";

// UI tests drive the built SPA (served by `vite preview`) and stub the backend
// API with page.route, so they are deterministic and need neither Docker nor a
// network. Focus: the --identify-vendored surfaces (Advanced toggle gating,
// result banner, vendored badge + match confidence, i18n, XSS escaping).
export default defineConfig({
  testDir: "./tests/ui",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:4173",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // Build then preview the static dist on a fixed port.
    command: "npm run build && npm run preview -- --port 4173 --strictPort",
    url: "http://localhost:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
