// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import path from "node:path";
import { defineConfig } from "vite";
// @ts-expect-error -- plain .mjs plugin, no type declarations to import
import { thirdPartyNotices } from "./scripts/vite-third-party-notices.mjs";

// BomLens local UI. Built to a static SPA (dist/) that docker/web/server.py
// serves. In dev, proxy the data API to a locally-running server.py (port 8080)
// so the SSE scan stream and result endpoints work without rebuilding.
//
// BASE_PATH exists for the published read-only demo, which is served from a
// sub-path (`/bomlens/demo/`) rather than a host root. server.py serves the app
// at `/`, so a normal build leaves this at the default.
// The SPDX 3.0.1 field mapping that drives the model questionnaire. A normal
// build fetches it from server.py (/spdx3-map), which serves the one source of
// truth, docker/lib/spdx3-ai-map.json. The demo has no server and its data
// folder is overwritten by every capture, so a demo build (VITE_DEMO_DATA_BASE
// set) bundles that same file; any other build resolves the alias to a null
// stub, so the Docker image build (whose context holds only web/frontend/) and
// the shipped bundle are unaffected.
const spdx3MapFile = process.env.VITE_DEMO_DATA_BASE
  ? path.resolve(__dirname, "../../lib/spdx3-ai-map.json")
  : path.resolve(__dirname, "./src/lib/spdx3-map-stub.json");

export default defineConfig({
  base: process.env.BASE_PATH || "/",
  // The notice plugin emits dist/third-party-licenses.txt from the bundled
  // module graph, so the shipped SPA always carries the terms of the packages
  // actually inside it.
  plugins: [react(), thirdPartyNotices()],
  resolve: {
    alias: [
      { find: /^@spdx3-map$/, replacement: spdx3MapFile },
      { find: "@", replacement: path.resolve(__dirname, "./src") },
    ],
  },
  // Unit tests (Vitest): data/display logic only — pure modules, no DOM.
  // Playwright owns interaction/visual/a11y coverage.
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Coverage is scoped to src/lib — the pure data/display modules Vitest
    // actually exercises. Components live behind the DOM and are covered by
    // Playwright, so including them here would just depress the number.
    // Thresholds guard against regressions; they sit just under the current
    // measured coverage rather than at an aspirational target.
    coverage: {
      provider: "v8",
      include: ["src/lib/**/*.ts"],
      // highlight-runtime is the loading half of the syntax highlighter: dynamic
      // grammar imports and a call into the library, which run in the browser
      // and are covered by the Playwright tests. Same reason the components are
      // out — measuring it here would only depress the number. Its seam with
      // the pure half (that every language the mapper names has a loader) is
      // unit tested; only the loading itself is excluded.
      exclude: ["src/lib/**/*.test.ts", "src/lib/highlight-runtime.ts"],
      reporter: ["text-summary", "json-summary"],
      // Re-baselined for Vitest 4: its v8 provider remaps coverage through the
      // AST rather than counting raw v8 ranges, so the same tests over the same
      // code measure lower — branches 82% -> 69.38%, functions 88% -> 81.79%.
      // Nothing stopped being tested. These sit just under the new measurement,
      // as the old ones sat just under the old.
      thresholds: {
        lines: 75,
        functions: 80,
        branches: 68,
        statements: 75,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/results": "http://localhost:8080",
      "/file": "http://localhost:8080",
      "/scan-stream": "http://localhost:8080",
    },
  },
});
