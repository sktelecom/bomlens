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
