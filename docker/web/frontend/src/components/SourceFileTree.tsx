// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  ChevronDown,
  ChevronRight,
  File,
  FileSymlink,
  Folder,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import type { FileNode } from "@/lib/scancode";
import { cn } from "@/lib/utils";

/**
 * Source file tree rendered from the scan's file inventory — ScanCode output
 * (`_scancode.json`, which also carries per-file licenses) or the
 * structure-only `_files.json`. Directories collapse/expand; files are
 * selectable, and SourceTreePanel shows the selected one's captured text.
 */
function FileRow({
  node,
  depth,
  selected,
  onSelect,
}: {
  node: FileNode;
  depth: number;
  selected: string | null;
  onSelect: (path: string) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(depth === 0);

  const indent = { paddingLeft: `${depth * 16 + 6}px` };
  const isSelected = !node.isDir && selected === node.path;

  const label = (
    <>
      {node.isDir ? (
        <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      ) : node.isLink ? (
        <FileSymlink className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      ) : (
        <File className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      )}
      <span className="truncate font-mono text-xs">{node.name}</span>

      {node.licenses.slice(0, 2).map((l) => (
        <Badge key={l} variant="muted">
          {l}
        </Badge>
      ))}
      {node.licenses.length > 2 && (
        <Badge variant="muted">+{node.licenses.length - 2}</Badge>
      )}
    </>
  );

  return (
    <li>
      {node.isDir ? (
        <div
          className="flex items-center gap-2 rounded-sm px-1.5 py-1 hover:bg-accent/50"
          style={indent}
        >
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="flex h-4 w-4 shrink-0 items-center justify-center text-muted-foreground hover:text-foreground"
            aria-expanded={open}
            aria-label={open ? t("deps.collapse") : t("deps.expand")}
          >
            {open ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
          </button>
          {label}
        </div>
      ) : (
        // Files are buttons: the whole row selects, so a keyboard reader tabs
        // through the files themselves instead of hunting for a hit area.
        <button
          type="button"
          onClick={() => onSelect(node.path)}
          aria-current={isSelected ? "true" : undefined}
          className={cn(
            "flex w-full items-center gap-2 rounded-sm px-1.5 py-1 text-left hover:bg-accent/50",
            isSelected && "bg-accent text-accent-foreground",
          )}
          style={indent}
        >
          <span className="inline-block h-4 w-4 shrink-0" />
          {label}
        </button>
      )}

      {node.isDir && open && node.children.length > 0 && (
        <ul>
          {node.children.map((c) => (
            <FileRow
              key={c.path}
              node={c}
              depth={depth + 1}
              selected={selected}
              onSelect={onSelect}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

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

  if (nodes.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">{t("sourceTree.empty")}</p>
    );
  }

  return (
    <div className="max-h-[44rem] min-h-[16rem] resize-y overflow-auto rounded-md border p-1">
      <ul>
        {nodes.map((n) => (
          <FileRow
            key={n.path}
            node={n}
            depth={0}
            selected={selected}
            onSelect={onSelect ?? (() => {})}
          />
        ))}
      </ul>
    </div>
  );
}
