// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// Copies the Markdown sources under ../docs into src/content/docs so that
// Starlight can read them, without changing the sources. Two adjustments:
//   - Starlight requires a front matter `title`, so the first H1 is moved there.
//   - Files that are not part of the published site are skipped (same list as
//     exclude_docs in mkdocs.yml), and the demo bundle is exposed under public/.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const source = path.resolve(here, '../../docs');
const target = path.resolve(here, '../src/content/docs');
const demoTarget = path.resolve(here, '../public/demo');
const repoRoot = path.resolve(here, '../..');
const homeSource = path.resolve(here, '../home');

const skip = (rel) =>
  rel === 'korean-style-guide.md' ||
  // The home pages use MkDocs-only syntax; docs-site/home/ holds the Starlight versions.
  rel === 'index.md' ||
  rel === 'index.ko.md' ||
  rel === 'requirements.txt' ||
  rel.startsWith('images/src/') ||
  rel.startsWith('internal/') ||
  rel.startsWith('stylesheets/') ||
  rel.startsWith('javascripts/') ||
  rel.startsWith('demo/');

function withTitle(text) {
  const fm = text.match(/^---\n([\s\S]*?)\n---\n/);
  if (fm && /^title:/m.test(fm[1])) return text;
  const body = fm ? text.slice(fm[0].length) : text;
  const lines = body.split('\n');
  let inFence = false;
  let at = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^(```|~~~)/.test(lines[i])) inFence = !inFence;
    if (!inFence && /^# /.test(lines[i])) {
      at = i;
      break;
    }
  }
  if (at < 0) return text;
  const title = lines[at].slice(2).trim();
  lines.splice(at, 1);
  return `---\ntitle: ${JSON.stringify(title)}\n${fm ? fm[1] + '\n' : ''}---\n${lines.join('\n')}`;
}

fs.rmSync(target, { recursive: true, force: true });
let pages = 0;
for (const entry of fs.readdirSync(source, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile()) continue;
  const from = path.join(entry.parentPath, entry.name);
  const rel = path.relative(source, from);
  if (skip(rel.split(path.sep).join('/'))) continue;
  const to = path.join(target, rel);
  fs.mkdirSync(path.dirname(to), { recursive: true });
  if (rel.endsWith('.md')) {
    fs.writeFileSync(to, withTitle(fs.readFileSync(from, 'utf8')));
    pages++;
  } else {
    fs.copyFileSync(from, to);
  }
}

// Home pages written for Starlight (cards need components, so they are MDX).
for (const name of fs.readdirSync(homeSource)) {
  fs.copyFileSync(path.join(homeSource, name), path.join(target, name));
}

// Shared design tokens, the same file the web UI and the reports use. The token
// file puts dark values under `.dark`; Starlight marks its dark theme with
// data-theme="dark" on <html>, so the same block is attached to that selector.
const tokens = fs.readFileSync(path.join(repoRoot, 'docker/shared/bomlens-tokens.css'), 'utf8');
if (tokens.split('.dark {').length !== 2) throw new Error("expected exactly one '.dark {' block in bomlens-tokens.css");
fs.writeFileSync(
  path.resolve(here, '../src/styles/bomlens-tokens.css'),
  tokens.replace('.dark {', ".dark,\n:root[data-theme='dark'] {"),
);
fs.mkdirSync(path.resolve(here, '../public/images'), { recursive: true });
for (const card of ['og-card.png', 'og-card-ko.png']) {
  fs.copyFileSync(path.join(source, 'images', card), path.resolve(here, '../public/images', card));
}
fs.copyFileSync(path.join(source, 'images/logo-mark.svg'), path.resolve(here, '../public/favicon.svg'));

// The demo is a prebuilt single-page app (scripts/build-demo-bundle.sh) with its
// base path baked in as /bomlens/demo/, so it only works when the site is served at
// /bomlens/. It is therefore included only when DOCS_INCLUDE_DEMO=1 (the final
// switch-over), and goes to public/ because it is served as-is.
fs.rmSync(demoTarget, { recursive: true, force: true });
const demoSource = path.join(source, 'demo');
let withDemo = false;
if (process.env.DOCS_INCLUDE_DEMO === '1') {
  fs.cpSync(demoSource, demoTarget, { recursive: true });
  withDemo = true;
}

console.log(`prepare-content: ${pages} pages${withDemo ? ' + demo' : ''}`);
