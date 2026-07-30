// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

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
  // Exact match. The baselines are produced in one pinned container
  // (playwright:v1.61.1-jammy) and compared in the same one, so rendering is
  // reproducible: measured on this suite, 17 of 33 baselines came back
  // bit-identical at a 0-pixel tolerance while the 16 that had genuinely
  // changed differed by 16-86 pixels.
  //
  // The old 100px allowance was meant to absorb cross-version antialiasing, but
  // every real change also fits under it: three merged UI edits left their
  // baselines stale and no check failed. A Playwright bump does need the
  // baselines regenerated (reseed_visual) — that is the honest signal, not
  // something to tolerate silently.
  expect: {
    toHaveScreenshot: { maxDiffPixels: 0 },
  },
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
