#!/usr/bin/env node
// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// Verifies that a packaged app carries every file the start screens load. A file that exists
// in a development run (assets/ plus ../docker/shared) can still be missing from the package
// when the build config does not copy it, and the failure only shows on an installed app as an
// unstyled or blank window. Run after `electron-builder`:
//
//   node scripts/check-package.mjs [path/to/app.asar]
//
// With no argument it looks for app.asar under dist-electron (macOS .app or Windows
// win-unpacked). Exits 1 and names what is missing.
import asar from "@electron/asar";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const sharedTokens = path.resolve(appRoot, "..", "docker", "shared", "bomlens-tokens.css");

// Files the start screens load relative to themselves, plus the screens themselves.
export const REQUIRED = [
  "assets/status.html",
  "assets/docker-missing.html",
  "assets/steps.cjs",
  "assets/logo.svg",
  "assets/bomlens-tokens.css",
  "main.mjs",
  "preload.mjs",
];

function findAsar() {
  const out = path.join(appRoot, "dist-electron");
  const candidates = [];
  if (fs.existsSync(out)) {
    for (const dir of fs.readdirSync(out)) {
      candidates.push(path.join(out, dir, "resources", "app.asar"));
      const apps = path.join(out, dir);
      if (fs.existsSync(apps) && fs.statSync(apps).isDirectory()) {
        for (const entry of fs.readdirSync(apps)) {
          if (entry.endsWith(".app")) {
            candidates.push(path.join(apps, entry, "Contents", "Resources", "app.asar"));
          }
        }
      }
    }
  }
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null;
}

const target = process.argv[2] ? path.resolve(process.argv[2]) : findAsar();
if (!target || !fs.existsSync(target)) {
  console.error("check-package: no app.asar found. Build first (npm run dist -- --dir) or pass a path.");
  process.exit(1);
}

const packaged = new Set(asar.listPackage(target).map((entry) => entry.replace(/^[\\/]/, "").replaceAll("\\", "/")));
const missing = REQUIRED.filter((file) => !packaged.has(file));
if (missing.length > 0) {
  console.error(`check-package: ${target} is missing: ${missing.join(", ")}`);
  process.exit(1);
}

// The shipped tokens must be the repository's current file, not a stale copy.
const shipped = asar.extractFile(target, "assets/bomlens-tokens.css").toString("utf8");
if (shipped !== fs.readFileSync(sharedTokens, "utf8")) {
  console.error("check-package: packaged bomlens-tokens.css differs from docker/shared/bomlens-tokens.css");
  process.exit(1);
}
if (!shipped.includes("--background") || !shipped.includes(".dark")) {
  console.error("check-package: packaged bomlens-tokens.css has no light/dark tokens");
  process.exit(1);
}
console.log(`check-package: OK (${REQUIRED.length} files, tokens match) in ${path.relative(appRoot, target)}`);
