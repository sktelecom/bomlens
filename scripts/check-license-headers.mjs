// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// check-license-headers.mjs — every source file we wrote must state its license
// in machine-readable form.
//
// Why an SPDX tag and not just the Apache boilerplate: BomLens reads licenses
// for a living, and scancode-toolkit -- which BomLens itself invokes for its
// deep license mode -- takes `SPDX-License-Identifier` as the primary signal.
// A file without one is left to text matching or comes back undetermined, so a
// repository of untagged files is a repository our own tool cannot read
// precisely.
//
// Run with --fix to insert what is missing. Without it, the script only reports,
// which is how CI uses it.
//
// Out of scope: examples/. Those are sample projects a user copies into their
// own codebase, so stamping our copyright on them would be wrong.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const TAG = "SPDX-License-Identifier";
const COPYRIGHT = "Copyright 2026 SK Telecom Co., Ltd.";
const SPDX_ID = "Apache-2.0";

// Comment syntax per extension. .bat uses REM, which is why it cannot share the
// hash family; .css has no line comment, so it gets a wrapped block.
//
// .html is left out on purpose. Most tracked ones are reports the scanner
// generated; the hand-written ones (the SPA shell, the social-card render
// template) are markup whose first line has to be the doctype. So is .json --
// the format has no comments at all.
const COMMENT = {
  ".sh": "#", ".py": "#", ".jq": "#",
  ".ts": "//", ".tsx": "//", ".mjs": "//", ".js": "//",
  ".bat": "REM",
  ".css": "block",
};

// The shadcn/ui component patterns were copied into this repo and adapted, so
// these files carry code under two licenses and both notices have to stay.
// THIRD_PARTY_LICENSES.md records the same fact for readers.
const ADAPTED_FROM_SHADCN = new Set([
  "docker/web/frontend/src/components/ui/badge.tsx",
  "docker/web/frontend/src/components/ui/button.tsx",
  "docker/web/frontend/src/components/ui/card.tsx",
  "docker/web/frontend/src/components/ui/input.tsx",
  "docker/web/frontend/src/components/ui/label.tsx",
  "docker/web/frontend/src/components/ui/progress.tsx",
  "docker/web/frontend/src/components/ui/tabs.tsx",
]);
const SHADCN_NOTICE = "Adapted from shadcn/ui — Copyright (c) 2023 shadcn, MIT licensed.";
const SHADCN_SPDX_ID = "Apache-2.0 AND MIT";

function trackedSources() {
  const out = execFileSync("git", ["ls-files", "-z"], { cwd: REPO_ROOT, encoding: "utf8" });
  return out
    .split("\0")
    .filter(Boolean)
    .filter((f) => COMMENT[path.extname(f)])
    .filter((f) => !f.startsWith("examples/"))
    .filter((f) => !f.includes("node_modules/"))
    .sort();
}

/** Lines that must not be displaced: shebang, and cmd's echo-off preamble. */
function preambleLength(lines, ext) {
  if (lines[0]?.startsWith("#!")) return 1;
  if (ext === ".bat" && /^@echo\s+off/i.test(lines[0] || "")) return 1;
  return 0;
}

function headerFor(file, comment) {
  const spdx = ADAPTED_FROM_SHADCN.has(file) ? SHADCN_SPDX_ID : SPDX_ID;
  const body = [COPYRIGHT];
  if (ADAPTED_FROM_SHADCN.has(file)) body.push(SHADCN_NOTICE);
  body.push(`${TAG}: ${spdx}`);
  if (comment === "block") return ["/*", ...body.map((l) => ` * ${l}`), " */"];
  return body.map((l) => `${comment} ${l}`);
}

const fix = process.argv.includes("--fix");
const missing = [];
let inserted = 0;
let tagged = 0;

for (const file of trackedSources()) {
  const abs = path.join(REPO_ROOT, file);
  const text = fs.readFileSync(abs, "utf8");
  const lines = text.split("\n");
  const ext = path.extname(file);
  const comment = COMMENT[ext];
  // Only the top of the file counts. A tag buried in the body (a fixture, a
  // string, a doc comment further down) is not a file-level declaration.
  const top = lines.slice(0, 12);

  if (top.some((l) => l.includes(TAG))) {
    tagged += 1;
    continue;
  }

  if (!fix) {
    missing.push(file);
    continue;
  }

  const at = preambleLength(lines, ext);
  const copyrightAt = top.findIndex((l) => l.includes("Copyright") && l.includes("SK Telecom"));

  if (copyrightAt >= 0) {
    // The Apache boilerplate is already here and correct; the tag is all that
    // is missing, and it belongs with the copyright line.
    const spdx = ADAPTED_FROM_SHADCN.has(file) ? SHADCN_SPDX_ID : SPDX_ID;
    const line = comment === "block" ? ` * ${TAG}: ${spdx}` : `${comment} ${TAG}: ${spdx}`;
    lines.splice(copyrightAt + 1, 0, line);
  } else {
    const header = headerFor(file, comment);
    // Keep one blank line between the header and code that starts immediately.
    if (lines[at] !== undefined && lines[at].trim() !== "") header.push("");
    lines.splice(at, 0, ...header);
  }

  fs.writeFileSync(abs, lines.join("\n"));
  inserted += 1;
}

if (fix) {
  console.log(`[OK] ${inserted} file(s) stamped, ${tagged} already tagged.`);
  process.exit(0);
}

if (missing.length) {
  console.error(`[FAIL] ${missing.length} source file(s) carry no ${TAG}:`);
  for (const f of missing) console.error(`  ${f}`);
  console.error("");
  console.error("Fix: node scripts/check-license-headers.mjs --fix");
  process.exit(1);
}

console.log(`[OK] all ${tagged} tracked source files declare ${TAG}.`);
