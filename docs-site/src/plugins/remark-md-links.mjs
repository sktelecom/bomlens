// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
// Rewrite relative links to sibling Markdown files (MkDocs style) into site URLs.
import path from 'node:path';
import { visit } from 'unist-util-visit';
export default function remarkMdLinks({ base = '/' } = {}) {
  return (tree, file) => {
    const root = path.join(file.cwd, 'src/content/docs');
    const from = path.dirname(path.relative(root, file.path));
    visit(tree, ['link', 'definition'], (node) => {
      const m = /^(?![a-z]+:|#|\/)([^#?]+\.md)(#.*)?$/i.exec(node.url || '');
      if (!m) return;
      let id = path.posix.normalize(path.posix.join(from, m[1])).replace(/\.md$/, '');
      const ko = id.endsWith('.ko'); if (ko) id = id.slice(0, -3);
      id = id.replace(/(^|\/)index$/, '');
      node.url = base + (ko ? 'ko/' : '') + (id ? id + '/' : '') + (m[2] || '');
    });
  };
}
