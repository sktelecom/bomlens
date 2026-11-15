// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// Checks the built site: every internal link and asset reference must point at a file
// that exists, and every #fragment at an element id on the target page. This replaces
// the link validation the previous site generator ran as part of its strict build.
//
// Usage: node scripts/check-links.mjs [dist-folder]   (default: dist)
// Exit code 1 when anything is broken.
import fs from 'node:fs';
import path from 'node:path';

const dist = path.resolve(process.argv[2] ?? 'dist');
const base = (process.env.DOCS_BASE || '/bomlens').replace(/\/$/, '');

const htmlFiles = fs
  .readdirSync(dist, { recursive: true, withFileTypes: true })
  .filter((e) => e.isFile() && e.name.endsWith('.html'))
  .map((e) => path.join(e.parentPath, e.name))
  // The demo is a separate single-page app with its own router.
  .filter((f) => !path.relative(dist, f).startsWith(`demo${path.sep}`) && !path.relative(dist, f).startsWith(`pagefind${path.sep}`));

const idCache = new Map();
function idsOf(file) {
  if (!idCache.has(file)) {
    const html = fs.readFileSync(file, 'utf8');
    idCache.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  }
  return idCache.get(file);
}

// A site path such as /bomlens/guides/ci-cd/ -> the file that serves it, or null.
function fileFor(sitePath) {
  if (!sitePath.startsWith(`${base}/`) && sitePath !== base) return undefined; // not ours
  const rel = decodeURIComponent(sitePath.slice(base.length)).replace(/^\//, '');
  const candidates = rel === '' || rel.endsWith('/') ? [path.join(dist, rel, 'index.html')] : [path.join(dist, rel), path.join(dist, rel, 'index.html')];
  return candidates.find((c) => fs.existsSync(c) && fs.statSync(c).isFile()) ?? null;
}

const problems = [];
let checked = 0;
for (const file of htmlFiles) {
  const html = fs.readFileSync(file, 'utf8');
  const pagePath = `${base}/${path.relative(dist, file).split(path.sep).join('/').replace(/index\.html$/, '')}`;
  for (const m of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
    const raw = m[1].replaceAll('&amp;', '&');
    if (!raw || /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(raw)) continue; // external, mailto:, data:
    const [target, fragment] = raw.split('#');
    const url = new URL(target || pagePath, `http://x${pagePath}`);
    const targetFile = target ? fileFor(url.pathname) : file;
    if (targetFile === undefined) continue; // outside this site
    checked++;
    if (targetFile === null) {
      problems.push(`${path.relative(dist, file)}: no such page or file: ${raw}`);
      continue;
    }
    if (fragment && targetFile.endsWith('.html') && !idsOf(targetFile).has(decodeURIComponent(fragment))) {
      problems.push(`${path.relative(dist, file)}: no element with id "${fragment}" in ${path.relative(dist, targetFile)} (link ${raw})`);
    }
  }
}

for (const p of [...new Set(problems)]) console.log(p);
console.log(`check-links: ${htmlFiles.length} pages, ${checked} internal references, ${new Set(problems).size} problem(s)`);
process.exit(problems.length > 0 ? 1 : 0);
