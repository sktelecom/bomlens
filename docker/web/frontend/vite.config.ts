/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import path from "node:path";
import { defineConfig } from "vite";

// sbom-tools local UI. Built to a static SPA (dist/) that docker/web/server.py
// serves. In dev, proxy the data API to a locally-running server.py (port 8080)
// so the SSE scan stream and result endpoints work without rebuilding.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
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
      exclude: ["src/lib/**/*.test.ts"],
      reporter: ["text-summary", "json-summary"],
      thresholds: {
        lines: 75,
        functions: 88,
        branches: 82,
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
