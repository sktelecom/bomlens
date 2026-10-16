#!/usr/bin/env node
// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Accessibility check of the built documentation site: axe (WCAG 2.0/2.1/2.2 A
 * and AA) over a few representative pages in both languages and both colour
 * schemes. The pages are the ones whose look the shared design tokens decide
 * (home, a start page, a reference page), so a token change that breaks
 * contrast shows up here.
 *
 * Usage:
 *   node scripts/site-axe.mjs --dir ../../../site        serve a built site
 *   node scripts/site-axe.mjs --url https://host/base/    check a running site
 *
 * Needs `npm ci` and a Playwright Chromium. Exits 1 on any violation.
 */
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";

import AxeBuilder from "@axe-core/playwright";
import { chromium } from "@playwright/test";

const PAGES = [
  "",
  "start/first-scan/",
  "reference/ui/",
  "guides/by-input/",
  "ko/",
  "ko/start/first-scan/",
  "ko/reference/ui/",
];
const SCHEMES = ["light", "dark"];
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".ico": "image/x-icon",
};

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function serve(dir) {
  const root = resolve(dir);
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    let file = normalize(join(root, path));
    // Stay inside the site folder, whatever the request says.
    if (!file.startsWith(root)) {
      res.writeHead(403).end();
      return;
    }
    if (existsSync(file) && statSync(file).isDirectory()) file = join(file, "index.html");
    if (!existsSync(file)) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
    createReadStream(file).pipe(res);
  });
  return new Promise((ok) =>
    server.listen(0, "127.0.0.1", () => ok({ server, base: `http://127.0.0.1:${server.address().port}/` })),
  );
}

const dir = arg("--dir");
const url = arg("--url");
if (!dir && !url) {
  console.error("usage: site-axe.mjs --dir <built site> | --url <base url>");
  process.exit(2);
}

let server;
let base = url;
if (dir) {
  ({ server, base } = await serve(dir));
}
if (!base.endsWith("/")) base += "/";

const browser = await chromium.launch();
let failures = 0;
for (const scheme of SCHEMES) {
  const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  for (const path of PAGES) {
    await page.goto(base + path, { waitUntil: "load" });
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    for (const v of results.violations) {
      failures += 1;
      const nodes = v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ");
      console.log(`[${scheme}] /${path} ${v.id} (${v.impact}, ${v.nodes.length}): ${nodes}`);
    }
  }
  await ctx.close();
}
await browser.close();
server?.close();

console.log(`site-axe: ${PAGES.length * SCHEMES.length} page views, ${failures} violation(s)`);
process.exit(failures > 0 ? 1 : 0);
