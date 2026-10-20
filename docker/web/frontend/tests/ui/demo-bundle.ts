// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

import type { Page } from "@playwright/test";

// The read-only demo as a test target: the same SPA built with the demo data
// base set, served by `vite preview`, with its data requests answered from the
// capture committed in docs/demo/data. No server, Docker or network is
// involved and the normal `dist/` is left alone. Shared by the audit capture
// and the demo-mode checks so both read the demo the same way.

const FRONTEND = process.cwd(); // Playwright runs from docker/web/frontend
const REPO = resolve(FRONTEND, "..", "..", "..");
export const DEMO_DATA = join(REPO, "docs", "demo", "data");
export const DATA_BASE = "/demo-data";

const MIME: Record<string, string> = {
  ".json": "application/json",
  ".html": "text/html",
  ".txt": "text/plain",
  ".zip": "application/zip",
};

/** Answer the demo bundle's data requests, confined to docs/demo/data so a
 *  crafted path cannot read anything else. */
export async function serveDemoData(page: Page) {
  await page.route(`**${DATA_BASE}/**`, async (route) => {
    const rel = decodeURIComponent(new URL(route.request().url()).pathname.slice(DATA_BASE.length));
    const file = resolve(DEMO_DATA, "." + rel);
    const inside = relative(DEMO_DATA, file);
    if (inside.startsWith("..")) return route.fulfill({ status: 404, body: "not found" });
    let body: Buffer;
    try {
      body = readFileSync(file);
    } catch {
      return route.fulfill({ status: 404, body: "not found" });
    }
    return route.fulfill({ contentType: MIME[extname(file)] ?? "application/octet-stream", body });
  });
}

/** Build the demo bundle into `outDir`, serve it on `port`, and wait until it
 *  answers. Kill the returned process when done. */
export async function startDemoBundle(outDir: string, port: number): Promise<ChildProcess> {
  execFileSync("npx", ["vite", "build", "--outDir", outDir, "--emptyOutDir"], {
    cwd: FRONTEND,
    stdio: "ignore",
    env: { ...process.env, VITE_DEMO_DATA_BASE: DATA_BASE },
  });
  const preview = spawn(
    "npx",
    ["vite", "preview", "--outDir", outDir, "--port", String(port), "--strictPort"],
    { cwd: FRONTEND, stdio: "ignore" },
  );
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`http://localhost:${port}`)).ok) return preview;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  preview.kill();
  throw new Error("demo preview server did not start");
}
