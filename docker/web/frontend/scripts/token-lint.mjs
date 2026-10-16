#!/usr/bin/env node
// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Token lint — fails when a component hardcodes a colour instead of using a
 * design token (CSS var / Tailwind utility). This is the drift guard that keeps
 * the light/dark themes and the brand accent in one place (src/index.css).
 *
 * Flagged: hex literals (#abc / #aabbcc), literal rgb()/rgba()/hsl()/hsla()
 * calls, and Tailwind arbitrary colour values (bg-[#…], text-[rgb(…)]).
 *
 * Allowed: building a colour from a CSS variable at runtime, e.g.
 * `hsl(${getComputedStyle(...).getPropertyValue('--brand')})` — the first
 * character after `(` is `$`, not a digit, so the literal-call rule skips it.
 *
 * Also enforced: brand tokens appear only in the primary button variants (an
 * allow list), only the `-fg` shade of a role is a text colour, and font sizes
 * come from the role scale (no text-[Npx]).
 *
 * Scope: src/**\/*.{ts,tsx}. The token source itself (src/index.css) is not a
 * component and is never scanned. The rules live in token-lint-rules.mjs.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { lintLine } from "./token-lint-rules.mjs";

// TOKEN_LINT_SRC lets a test point the walker at a fixture folder.
const SRC =
  process.env.TOKEN_LINT_SRC ?? join(fileURLToPath(new URL(".", import.meta.url)), "..", "src");


function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    // The rule test feeds the rules deliberate violations, so it is not scanned.
    else if (/\.(ts|tsx)$/.test(entry) && entry !== "tokenLintRules.test.ts") out.push(p);
  }
  return out;
}

const violations = [];
for (const file of walk(SRC)) {
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    for (const name of lintLine(line, file)) {
      violations.push(`${file}:${i + 1}  [${name}]  ${line.trim()}`);
    }
  });
}

if (violations.length) {
  console.error("Token lint failed — hardcoded colours found:\n");
  console.error(violations.join("\n"));
  console.error(
    `\n${violations.length} violation(s). Use a design token (CSS var / Tailwind utility) instead.`,
  );
  process.exit(1);
}
console.log("Token lint passed — no hardcoded colours in components.");
