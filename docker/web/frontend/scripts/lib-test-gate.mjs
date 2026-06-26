#!/usr/bin/env node
/**
 * Lib test gate — fails when a src/lib module ships without a unit test.
 *
 * The lib layer holds the pure data/display logic the UI depends on (graph
 * parsing, the api client contract, result summaries). Nothing forced a new
 * module to arrive with a test, so untested logic could merge on developer
 * discipline alone. This gate makes the rule mechanical: every
 * `src/lib/<name>.ts` must have a sibling `src/lib/<name>.test.ts`, OR opt out
 * explicitly with a top-of-file annotation:
 *
 *     // @no-unit-test: <reason>
 *
 * Use the opt-out only for genuinely non-unit-testable modules (static data
 * tables, framework init). The reason is required so the choice is auditable.
 *
 * Scope: src/lib/*.ts, excluding *.test.ts and type-only *.d.ts.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const LIB = join(fileURLToPath(new URL(".", import.meta.url)), "..", "src", "lib");
const ANNOTATION = /^\s*\/\/\s*@no-unit-test:\s*\S/m;

const files = readdirSync(LIB).filter(
  (f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && !f.endsWith(".d.ts"),
);

const missing = [];
const optedOut = [];

for (const f of files) {
  const testFile = f.replace(/\.ts$/, ".test.ts");
  if (files.includes(testFile) || hasTest(testFile)) continue;
  const src = readFileSync(join(LIB, f), "utf8");
  if (ANNOTATION.test(src)) {
    optedOut.push(f);
  } else {
    missing.push(f);
  }
}

function hasTest(name) {
  try {
    readFileSync(join(LIB, name));
    return true;
  } catch {
    return false;
  }
}

if (optedOut.length > 0) {
  console.log(`lib-test-gate: ${optedOut.length} module(s) opted out via @no-unit-test:`);
  for (const f of optedOut) console.log(`  - ${f}`);
}

if (missing.length > 0) {
  console.error(`\nlib-test-gate: ${missing.length} src/lib module(s) have no unit test:`);
  for (const f of missing) console.error(`  - ${f}  (add ${f.replace(/\.ts$/, ".test.ts")}, or annotate // @no-unit-test: <reason>)`);
  process.exit(1);
}

console.log(`lib-test-gate: OK — every src/lib module has a unit test or a justified opt-out (${files.length} modules)`);
