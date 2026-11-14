// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { FileNode } from "./scancode";

/**
 * Keep the nodes whose name holds `q` (already trimmed and lower-cased), and the
 * folders on the way to them. A folder whose own name matches keeps all of its
 * children, so it can be opened; it is not opened for the reader (see
 * dirsWithMatchBelow).
 */
export function filterNodes(nodes: FileNode[], q: string): FileNode[] {
  if (!q) return nodes;
  const out: FileNode[] = [];
  for (const n of nodes) {
    const self = n.name.toLowerCase().includes(q);
    const kids = n.isDir ? filterNodes(n.children, q) : [];
    if (self || kids.length) out.push({ ...n, children: self && n.isDir ? n.children : kids });
  }
  return out;
}

/**
 * Paths of the folders that have a match somewhere below them. Only these open
 * while a filter is active: a folder matched by its own name stays closed, so a
 * short filter on a big tree does not build every row under it.
 */
export function dirsWithMatchBelow(nodes: FileNode[], q: string): Set<string> {
  const open = new Set<string>();
  if (!q) return open;
  const walk = (n: FileNode): boolean => {
    let below = false;
    for (const c of n.children) {
      const hit = c.name.toLowerCase().includes(q);
      const deeper = walk(c);
      if (hit || deeper) below = true;
    }
    if (below) open.add(n.path);
    return below;
  };
  nodes.forEach(walk);
  return open;
}

/** The folder paths above `path`: "a/b/c" gives "a" and "a/b". */
export function ancestorDirs(path: string | null): Set<string> {
  const out = new Set<string>();
  if (!path) return out;
  const parts = path.split("/");
  for (let i = 1; i < parts.length; i++) out.add(parts.slice(0, i).join("/"));
  return out;
}
