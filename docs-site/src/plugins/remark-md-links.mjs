// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// The sources link to other files relative to their own location (`../guides/x.md`,
// `../samples/report.html`). This rewrites those links into site URLs:
//   - a .md link becomes the page URL, in the language of the target (`x.ko.md` -> /ko/x/);
//   - an .html link to a published static file (slide deck, sample report) becomes its
//     path under the site root.
import path from 'node:path';
import { visit } from 'unist-util-visit';

export default function remarkMdLinks({ base = '/' } = {}) {
  return (tree, file) => {
    const root = path.join(file.cwd, 'src/content/docs');
    const from = path.dirname(path.relative(root, file.path));
    visit(tree, ['link', 'definition'], (node) => {
      const url = node.url || '';
      const md = /^(?![a-z]+:|#|\/)([^#?]+\.md)(#.*)?$/i.exec(url);
      if (md) {
        let id = path.posix.normalize(path.posix.join(from, md[1])).replace(/\.md$/, '');
        const ko = id.endsWith('.ko');
        if (ko) id = id.slice(0, -3);
        id = id.replace(/(^|\/)index$/, '');
        node.url = base + (ko ? 'ko/' : '') + (id ? id + '/' : '') + (md[2] || '');
        return;
      }
      const html = /^(?![a-z]+:|#|\/)([^#?]+\.html)(#.*)?$/i.exec(url);
      if (html) {
        node.url = base + path.posix.normalize(path.posix.join(from, html[1])) + (html[2] || '');
      }
    });
  };
}
