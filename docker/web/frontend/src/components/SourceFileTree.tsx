import { ChevronDown, ChevronRight, File, Folder } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import type { FileNode } from "@/lib/scancode";

/**
 * Source file tree rendered from ScanCode output (`_scancode.json`), shown only
 * when --deep-license produced one. Directories collapse/expand; each file
 * shows its detected SPDX license(s).
 */
function FileRow({ node, depth }: { node: FileNode; depth: number }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(depth === 0);

  return (
    <li>
      <div
        className="flex items-center gap-2 rounded-sm px-1.5 py-1 hover:bg-accent/50"
        style={{ paddingLeft: `${depth * 16 + 6}px` }}
      >
        {node.isDir ? (
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
        ) : (
          <span className="inline-block h-4 w-4 shrink-0" />
        )}

        {node.isDir ? (
          <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
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
      </div>

      {node.isDir && open && node.children.length > 0 && (
        <ul>
          {node.children.map((c) => (
            <FileRow key={c.path} node={c} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function SourceFileTree({ nodes }: { nodes: FileNode[] }) {
  const { t } = useTranslation();

  if (nodes.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">{t("sourceTree.empty")}</p>
    );
  }

  return (
    <div className="max-h-[28rem] overflow-auto rounded-md border p-1">
      <ul>
        {nodes.map((n) => (
          <FileRow key={n.path} node={n} depth={0} />
        ))}
      </ul>
    </div>
  );
}
