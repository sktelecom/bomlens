// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronDown, ChevronRight, Package } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/lib/api";
import type { TreeNode } from "@/lib/sbomGraph";

const VULN_TONE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

/** One visible row of the tree, with the structure a screen reader needs. */
interface Row {
  node: TreeNode;
  /** 1-based, for aria-level. */
  level: number;
  /** Position among its siblings, 1-based (aria-posinset). */
  pos: number;
  /** How many siblings it has (aria-setsize). */
  size: number;
  /** Index path, unique even when the same package appears under two parents. */
  path: string;
  hasChildren: boolean;
  expanded: boolean;
}

/**
 * Flatten the visible part of the tree.
 *
 * A flat list with aria-level / aria-posinset / aria-setsize is one of the two
 * shapes ARIA allows for a tree, and it is the one that makes roving focus
 * tractable: "the next row" is the next array entry, whatever its depth.
 */
function flatten(
  nodes: TreeNode[],
  open: Set<string>,
  level = 1,
  prefix = "",
): Row[] {
  const rows: Row[] = [];
  nodes.forEach((node, i) => {
    const path = prefix ? `${prefix}.${i}` : String(i);
    const hasChildren = node.children.length > 0;
    const expanded = hasChildren && open.has(path);
    rows.push({
      node,
      level,
      pos: i + 1,
      size: nodes.length,
      path,
      hasChildren,
      expanded,
    });
    if (expanded) rows.push(...flatten(node.children, open, level + 1, path));
  });
  return rows;
}

/**
 * Collapsible package hierarchy built from CycloneDX `dependencies[]`. Direct
 * dependencies (depth 0) sit at the top; expanding a row reveals its transitive
 * dependencies. When the SBOM has no dependency graph the caller passes a flat
 * list (every node at depth 0, no children) and we render it as a plain list.
 *
 * The graph view tells keyboard users to come here, so this has to be navigable:
 * one tab stop for the whole tree, arrow keys to move within it, and each row
 * carrying its own name, depth and expanded state. Before that it offered a row
 * of identical "Expand" buttons and no structure at all, which made the advice
 * on the graph view false.
 */
export function DependencyTree({
  tree,
  hasDependencies,
}: {
  tree: TreeNode[];
  hasDependencies: boolean;
}) {
  const { t } = useTranslation();
  // Direct dependencies start expanded, as they did when each row owned its own
  // state. Paths, not ids: the same package can sit under two parents.
  const [open, setOpen] = useState<Set<string>>(
    () => new Set(tree.map((_, i) => String(i))),
  );
  const [focused, setFocused] = useState(0);
  // Set while a key handler moves focus, so the effect below only pulls focus
  // when this component asked for it — never stealing it on an unrelated render.
  const moving = useRef(false);
  const rowRefs = useRef<(HTMLLIElement | null)[]>([]);

  const rows = useMemo(() => flatten(tree, open), [tree, open]);

  // Rows come and go as branches open and close; keep the focused index inside
  // the list rather than leaving the tree with no tab stop at all.
  const active = Math.min(focused, Math.max(rows.length - 1, 0));

  useEffect(() => {
    if (!moving.current) return;
    moving.current = false;
    rowRefs.current[active]?.focus();
  }, [active, rows.length]);

  const toggle = useCallback((path: string, want?: boolean) => {
    setOpen((prev) => {
      const next = new Set(prev);
      const isOpen = next.has(path);
      const target = want ?? !isOpen;
      if (target) next.add(path);
      else next.delete(path);
      return next;
    });
  }, []);

  const move = useCallback((to: number) => {
    moving.current = true;
    setFocused(to);
  }, []);

  const onKeyDown = (e: React.KeyboardEvent, i: number) => {
    const row = rows[i];
    if (!row) return;
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        if (i < rows.length - 1) move(i + 1);
        break;
      case "ArrowUp":
        e.preventDefault();
        if (i > 0) move(i - 1);
        break;
      case "ArrowRight":
        e.preventDefault();
        // Closed: open it. Already open: step into the first child, which is
        // the next row by construction.
        if (row.hasChildren && !row.expanded) toggle(row.path, true);
        else if (row.expanded && i < rows.length - 1) move(i + 1);
        break;
      case "ArrowLeft":
        e.preventDefault();
        if (row.expanded) {
          toggle(row.path, false);
        } else {
          // Walk back to the nearest row one level up — the parent.
          for (let j = i - 1; j >= 0; j -= 1) {
            if (rows[j].level < row.level) {
              move(j);
              break;
            }
          }
        }
        break;
      case "Home":
        e.preventDefault();
        move(0);
        break;
      case "End":
        e.preventDefault();
        move(rows.length - 1);
        break;
      case "Enter":
      case " ":
        if (row.hasChildren) {
          e.preventDefault();
          toggle(row.path);
        }
        break;
      default:
        break;
    }
  };

  if (tree.length === 0) {
    return <p className="text-sm text-muted-foreground">{t("deps.empty")}</p>;
  }

  return (
    <div className="space-y-2">
      {!hasDependencies && (
        <p className="text-xs text-muted-foreground">{t("deps.flatFallback")}</p>
      )}
      <div className="max-h-[44rem] resize-y overflow-auto rounded-md border p-1">
        <ul role="tree" aria-label={t("deps.treeLabel")}>
          {rows.map((row, i) => {
            const { node } = row;
            const label = node.version ? `${node.name} ${node.version}` : node.name;
            return (
              <li
                key={row.path}
                role="treeitem"
                aria-level={row.level}
                aria-posinset={row.pos}
                aria-setsize={row.size}
                aria-expanded={row.hasChildren ? row.expanded : undefined}
                // One tab stop for the tree; the arrow keys move within it.
                tabIndex={i === active ? 0 : -1}
                ref={(el) => {
                  rowRefs.current[i] = el;
                }}
                onFocus={() => setFocused(i)}
                onKeyDown={(e) => onKeyDown(e, i)}
                className="rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div
                  className="flex items-center gap-2 rounded-sm px-1.5 py-1 hover:bg-accent/50"
                  style={{ paddingLeft: `${(row.level - 1) * 16 + 6}px` }}
                >
                  {row.hasChildren ? (
                    <button
                      type="button"
                      onClick={() => toggle(row.path)}
                      className="flex h-4 w-4 shrink-0 items-center justify-center text-muted-foreground hover:text-foreground"
                      // The row owns the expanded state for assistive tech; this
                      // is the pointer affordance, kept out of the tab order so
                      // the tree stays one stop. Its name carries the package,
                      // because a dozen buttons all called "Expand" name nothing.
                      tabIndex={-1}
                      aria-hidden
                      title={t(row.expanded ? "deps.collapseNamed" : "deps.expandNamed", {
                        name: label,
                      })}
                    >
                      {row.expanded ? (
                        <ChevronDown className="h-3.5 w-3.5" />
                      ) : (
                        <ChevronRight className="h-3.5 w-3.5" />
                      )}
                    </button>
                  ) : (
                    <span className="inline-block h-4 w-4 shrink-0" />
                  )}

                  <Package className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="font-mono text-xs">
                    {node.name}
                    {node.version ? (
                      <span className="text-muted-foreground"> {node.version}</span>
                    ) : null}
                  </span>

                  {node.vuln && (
                    <Badge tone={VULN_TONE[node.vuln]} className="ml-1" title={t("deps.hasVuln")}>
                      {t(`severity.${node.vuln}`)}
                    </Badge>
                  )}
                  {row.level === 1 && (
                    <Badge tone="info" className="ml-1">
                      {t("deps.direct")}
                    </Badge>
                  )}
                  {node.cycle && (
                    <Badge variant="muted" className="ml-1">
                      {t("deps.cycle")}
                    </Badge>
                  )}
                  {node.licenses.slice(0, 2).map((l) => (
                    <Badge key={l} variant="muted">
                      {l}
                    </Badge>
                  ))}
                  {node.licenses.length > 2 && (
                    <Badge variant="muted">+{node.licenses.length - 2}</Badge>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
