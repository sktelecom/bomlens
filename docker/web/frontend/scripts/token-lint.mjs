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
 * Scope: src/**\/*.{ts,tsx}. The token source itself (src/index.css) is not a
 * component and is never scanned.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = join(fileURLToPath(new URL(".", import.meta.url)), "..", "src");

/** Tailwind's built-in palette families. A token never names one of these. */
const PALETTE =
  "slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose";
/** Utilities that take a colour. `border` and `divide` also take widths, but a
 *  width is a bare number, not a palette family, so the family match is enough. */
const COLOUR_UTILS =
  "text|bg|border|ring|ring-offset|outline|decoration|divide|placeholder|caret|accent|fill|stroke|shadow|from|via|to";

const RULES = [
  { name: "hex colour", re: /#[0-9a-fA-F]{3,8}\b/ },
  { name: "literal rgb()/hsl()", re: /\b(?:rgba?|hsla?)\(\s*[\d.]/ },
  { name: "Tailwind arbitrary colour", re: /\[(?:#[0-9a-fA-F]|(?:rgba?|hsla?)\()/ },
  // A palette class is a colour decided in a component rather than in the token
  // file, which is the same drift as a hex literal and was invisible to the
  // three rules above. It is also how a light/dark pair goes out of sync: the
  // class carries one shade and its `dark:` twin carries another, maintained by
  // hand at each site. Turned on at zero violations, once every component had
  // moved onto tokens; a new one is therefore a regression, not a backlog item.
  { name: "Tailwind palette class", re: new RegExp(`\\b(?:${COLOUR_UTILS})-(?:${PALETTE})-\\d{2,3}\\b`) },
  // risk-* tokens come in pairs: the bare name (text-risk-high) is the
  // saturated colour meant for icons and badge backgrounds, and -fg is a
  // separate, darker/lighter variant chosen to meet WCAG AA text contrast on
  // the page background (badge.tsx already uses -fg for this). A bare token
  // reaching body text is how Overview.tsx's "more severe than before" text
  // failed contrast in light mode (3.56:1, needs 4.5:1) before switching to
  // -fg. This is a same-line heuristic, not real JSX parsing: an aria-hidden
  // icon is always flagged safe here because every icon site in this codebase
  // keeps its className and aria-hidden on one line; it does not see an
  // aria-hidden on a different line of a multi-line element, and it cannot
  // tell a genuine icon-only usage without aria-hidden from body text. Mark a
  // real false positive with `// token-lint-ignore` rather than reformatting
  // the JSX just to satisfy the lint.
  {
    name: "risk token on body text (use the -fg variant)",
    test: (line) =>
      /\btext-risk-(?:critical|high|medium|low|info)(?!-fg)\b/.test(line) && !/aria-hidden/.test(line),
  },
];

/** Lines we never flag (the runtime CSS-var helpers and lint-ignore markers). */
function isAllowed(line) {
  return /token-lint-ignore/.test(line);
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(ts|tsx)$/.test(entry)) out.push(p);
  }
  return out;
}

const violations = [];
for (const file of walk(SRC)) {
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    if (isAllowed(line)) return;
    for (const rule of RULES) {
      const hit = rule.re ? rule.re.test(line) : rule.test(line);
      if (hit) {
        violations.push(`${file}:${i + 1}  [${rule.name}]  ${line.trim()}`);
      }
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
