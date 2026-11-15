// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { FileIcon, FileSymlinkFileIcon, FilterIcon, XIcon } from "@primer/octicons-react";
import { Label, TextInput, TreeView } from "@primer/react";
import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { FileNode } from "@/lib/scancode";
import { ancestorDirs, dirsWithMatchBelow, filterNodes } from "@/lib/sourceTreeFilter";

import "./source-tree.css";

/** Top-level folders open at the start only when there are few of them. */
const TOP_OPEN_MAX = 8;

/** How long typing waits before the tree is filtered: a big tree rebuilds per change. */
const FILTER_DELAY_MS = 150;

function Licenses({ licenses }: { licenses: string[] }) {
  if (licenses.length === 0) return null;
  return (
    <span className="bl-src-licenses">
      {licenses.slice(0, 2).map((l) => (
        <Label key={l} variant="secondary" title={l}>
          {l}
        </Label>
      ))}
      {licenses.length > 2 && (
        <Label variant="secondary" title={licenses.slice(2).join(", ")}>
          +{licenses.length - 2}
        </Label>
      )}
    </span>
  );
}

/**
 * Source file tree rendered from the scan's file inventory: ScanCode output
 * (`_scancode.json`, which also carries per-file licenses) or the
 * structure-only `_files.json`. A Primer TreeView, so the arrow keys, Home,
 * End and type-ahead work; folders open and close, files are selectable, and
 * SourceTreePanel shows the selected one's captured text.
 */
export function SourceFileTree({
  nodes,
  selected = null,
  onSelect,
}: {
  nodes: FileNode[];
  /** Path of the file whose content is on screen. */
  selected?: string | null;
  onSelect?: (path: string) => void;
}) {
  const { t } = useTranslation();
  const [filter, setFilter] = useState("");
  const [q, setQ] = useState("");
  const scroller = useRef<HTMLDivElement>(null);
  // Folders the reader opened or closed with no filter active, kept across a
  // filter so clearing it brings the tree back as it was left.
  const userOpen = useRef(new Map<string, boolean>());

  useEffect(() => {
    const id = setTimeout(() => setQ(filter.trim().toLowerCase()), FILTER_DELAY_MS);
    return () => clearTimeout(id);
  }, [filter]);

  const shown = useMemo(() => filterNodes(nodes, q), [nodes, q]);
  const matchOpen = useMemo(() => dirsWithMatchBelow(nodes, q), [nodes, q]);
  const selectedDirs = useMemo(() => ancestorDirs(selected), [selected]);
  const openTop = nodes.filter((n) => n.isDir).length <= TOP_OPEN_MAX;

  // After a filter changes the rows, bring the open file back into view.
  useEffect(() => {
    scroller.current
      ?.querySelector('[aria-current="true"]')
      ?.scrollIntoView({ block: "nearest" });
  }, [q]);

  const expandedAtStart = (n: FileNode, depth: number): boolean => {
    if (q) return matchOpen.has(n.path);
    if (selectedDirs.has(n.path)) return true;
    return userOpen.current.get(n.path) ?? (depth === 0 && openTop);
  };

  const render = (list: FileNode[], depth: number): ReactNode =>
    list.map((n) => (
      <TreeView.Item
        key={n.path}
        id={`src-${encodeURIComponent(n.path)}`}
        aria-label={n.licenses.length ? `${n.name}, ${n.licenses.join(", ")}` : n.name}
        defaultExpanded={n.isDir ? expandedAtStart(n, depth) : undefined}
        onExpandedChange={
          n.isDir
            ? (open) => {
                if (!q) userOpen.current.set(n.path, open);
              }
            : undefined
        }
        current={!n.isDir && selected === n.path}
        onSelect={n.isDir ? undefined : () => onSelect?.(n.path)}
      >
        <TreeView.LeadingVisual>
          {n.isDir ? (
            <TreeView.DirectoryIcon />
          ) : n.isLink ? (
            <FileSymlinkFileIcon />
          ) : (
            <FileIcon />
          )}
        </TreeView.LeadingVisual>
        <span className="bl-mono">{n.name}</span>
        <Licenses licenses={n.licenses} />
        {n.isDir && n.children.length > 0 && (
          <TreeView.SubTree>{render(n.children, depth + 1)}</TreeView.SubTree>
        )}
      </TreeView.Item>
    ));

  if (nodes.length === 0) {
    return <p className="bl-muted bl-src-none">{t("sourceTree.empty")}</p>;
  }

  return (
    <>
      <div className="bl-src-filter">
        <TextInput
          block
          size="small"
          leadingVisual={FilterIcon}
          trailingAction={
            filter ? (
              <TextInput.Action
                icon={XIcon}
                aria-label={t("sourceTree.filterClear")}
                onClick={() => setFilter("")}
              />
            ) : undefined
          }
          aria-label={t("sourceTree.filter")}
          placeholder={t("sourceTree.filter")}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      <div className="bl-src-scroll" ref={scroller}>
        {shown.length === 0 ? (
          <p className="bl-muted bl-small bl-src-none" role="status">
            {t("sourceTree.filterNone")}
          </p>
        ) : (
          // Keyed by the filter so each search starts with its matches open.
          <TreeView key={q} aria-label={t("sourceTree.treeLabel")} truncate={false}>
            {render(shown, 0)}
          </TreeView>
        )}
      </div>
    </>
  );
}
