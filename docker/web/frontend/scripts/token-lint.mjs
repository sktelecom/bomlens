#!/usr/bin/env node
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

const RULES = [
  { name: "hex colour", re: /#[0-9a-fA-F]{3,8}\b/ },
  { name: "literal rgb()/hsl()", re: /\b(?:rgba?|hsla?)\(\s*[\d.]/ },
  { name: "Tailwind arbitrary colour", re: /\[(?:#[0-9a-fA-F]|(?:rgba?|hsla?)\()/ },
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
      if (rule.re.test(line)) {
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
