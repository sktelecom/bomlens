import { ChevronDown, ChevronRight, Package } from "lucide-react";
import { useState } from "react";
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

/**
 * Collapsible package hierarchy built from CycloneDX `dependencies[]`. Direct
 * dependencies (depth 0) sit at the top; expanding a row reveals its transitive
 * dependencies. When the SBOM has no dependency graph the caller passes a flat
 * list (every node at depth 0, no children) and we render it as a plain list.
 */
function TreeRow({ node }: { node: TreeNode }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(node.depth === 0);
  const hasChildren = node.children.length > 0;

  return (
    <li>
      <div
        className="flex items-center gap-2 rounded-sm px-1.5 py-1 hover:bg-accent/50"
        style={{ paddingLeft: `${node.depth * 16 + 6}px` }}
      >
        {hasChildren ? (
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

        <Package className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
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
        {node.depth === 0 && (
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

      {hasChildren && open && (
        <ul>
          {node.children.map((c, i) => (
            <TreeRow key={`${c.id}-${i}`} node={c} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function DependencyTree({
  tree,
  hasDependencies,
}: {
  tree: TreeNode[];
  hasDependencies: boolean;
}) {
  const { t } = useTranslation();

  if (tree.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">{t("deps.empty")}</p>
    );
  }

  return (
    <div className="space-y-2">
      {!hasDependencies && (
        <p className="text-xs text-muted-foreground">{t("deps.flatFallback")}</p>
      )}
      <div className="max-h-[28rem] overflow-auto rounded-md border p-1">
        <ul>
          {tree.map((n, i) => (
            <TreeRow key={`${n.id}-${i}`} node={n} />
          ))}
        </ul>
      </div>
    </div>
  );
}
