// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// Run the axe color-contrast rule over generated HTML reports and print one
// count per report. It reuses @axe-core/playwright and playwright, which are
// already devDependencies of docker/web/frontend, so nothing new is installed.
//
// Usage: node axe-report-contrast.mjs <frontend-dir> <report.html>...
//   <frontend-dir>  docker/web/frontend after `npm ci` (modules resolve from it)
// Output: one line per file, "<count>\t<file>", then a JSON summary on the
// last line prefixed with "SUMMARY ". Exit 0 always; the caller applies limits.
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [frontendDir, ...files] = process.argv.slice(2);
if (!frontendDir || files.length === 0) {
  console.error('usage: axe-report-contrast.mjs <frontend-dir> <report.html>...');
  process.exit(2);
}

const req = createRequire(path.resolve(frontendDir, 'package.json'));
let chromium, AxeBuilder;
try {
  ({ chromium } = req('playwright'));
  AxeBuilder = req('@axe-core/playwright').default ?? req('@axe-core/playwright').AxeBuilder;
} catch (e) {
  console.error(`cannot load playwright/@axe-core/playwright from ${frontendDir}: ${e.message}`);
  console.error('fix: run `npm ci` in that directory first');
  process.exit(2);
}

const browser = await chromium.launch();
const summary = {};
try {
  for (const file of files) {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(pathToFileURL(path.resolve(file)).href);
    const res = await new AxeBuilder({ page }).withRules(['color-contrast']).analyze();
    const nodes = res.violations.reduce((n, v) => n + v.nodes.length, 0);
    summary[path.basename(file)] = nodes;
    console.log(`${nodes}\t${file}`);
    for (const v of res.violations) {
      for (const n of v.nodes.slice(0, 3)) {
        const d = (n.any[0] && n.any[0].message) || '';
        console.log(`  e.g. ${n.target.join(' ')}: ${d}`);
      }
    }
    await context.close();
  }
} finally {
  await browser.close();
}
console.log(`SUMMARY ${JSON.stringify(summary)}`);
