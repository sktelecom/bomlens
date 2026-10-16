// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { GitFork, ListTree } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { SELECTED_SOLID } from "@/components/ui/selectable";
import { ErrorState, LoadingState } from "@/components/ui/state";
import type { ComponentItem } from "@/lib/api";
import { severityFor, vulnSeverityIndex } from "@/lib/dependencies";
import { defaultDependencyView, type DependencyView } from "@/lib/graphView";
import { dependenciesFromQuery } from "@/lib/section-query";
import { loadSbom, parseSbomGraph, type SbomGraph } from "@/lib/sbomGraph";
import type { RouteQuery } from "@/lib/route";
import { cn } from "@/lib/utils";

import { DependencyGraph } from "./DependencyGraph";
import { DependencyTree } from "./DependencyTree";

/**
 * Fetches the raw `_bom.json` (lazily, when its tab opens), parses the
 * dependency graph client-side, and toggles between the node-link graph and
 * the package hierarchy tree. Components carrying a Risk join (Phase 2a) mark
 * their nodes as vulnerable.
 */
export function DependenciesPanel({
  scanId,
  sbomFile,
  components = [],
  query,
}: {
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  sbomFile: string;
  components?: ComponentItem[];
  /** Carries a "View in Dependencies" jump from another section (package name
   *  + version, from a Vulnerabilities/Components row). Read once per value:
   *  this panel does not write its own state back into the URL. */
  query?: RouteQuery;
}) {
  const { t } = useTranslation();
  const [graph, setGraph] = useState<SbomGraph | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const focus = dependenciesFromQuery(query);
  // The reader's own pick, once made. Until then the view follows the size of
  // the graph (see defaultDependencyView), which is only known after the SBOM
  // has loaded. A jump always means "show me the tree", even if Graph was left
  // open from a previous visit: the graph has no equivalent jump-and-expand.
  const [picked, setPicked] = useState<DependencyView | null>(focus ? "tree" : null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    if (focus) setPicked("tree");
    // Only react to the focus target itself changing, not every re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus?.name, focus?.version]);

  const vulnIndex = useMemo(() => vulnSeverityIndex(components), [components]);

  useEffect(() => {
    let active = true;
    setState("loading");
    void loadSbom(scanId, sbomFile)
      .then((sbom) => {
        if (!active) return;
        setGraph(parseSbomGraph(sbom, (n, v) => severityFor(vulnIndex, n, v)));
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });
    return () => {
      active = false;
    };
  }, [scanId, sbomFile, reloadKey, vulnIndex]);

  if (state === "loading") {
    return <LoadingState>{t("deps.loading")}</LoadingState>;
  }
  if (state === "error" || !graph) {
    return (
      <ErrorState
        onRetry={() => setReloadKey((k) => k + 1)}
        retryLabel={t("retry")}
      >
        {t("deps.loadError")}
      </ErrorState>
    );
  }

  const view: DependencyView = picked ?? defaultDependencyView(graph.nodes.length, false);
  // The tree opened because the graph would be a tangle, not because anyone
  // asked for it: say so, so the missing graph is not mistaken for a fault.
  const autoTree = picked === null && view === "tree" && graph.edges.length > 0;

  return (
    <div className="space-y-3">
      <div className="inline-flex rounded-md border p-0.5">
        <Button
          type="button"
          size="sm"
          variant="ghost"
          data-testid="deps-view-graph"
          aria-pressed={view === "graph"}
          className={cn(view === "graph" && SELECTED_SOLID)}
          onClick={() => setPicked("graph")}
        >
          <GitFork className="h-4 w-4" />
          {t("deps.viewGraph")}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          data-testid="deps-view-tree"
          aria-pressed={view === "tree"}
          className={cn(view === "tree" && SELECTED_SOLID)}
          onClick={() => setPicked("tree")}
        >
          <ListTree className="h-4 w-4" />
          {t("deps.viewTree")}
        </Button>
      </div>

      {autoTree && (
        <p className="text-body-sm text-muted-foreground" data-testid="deps-auto-tree-note">
          {t("deps.autoTreeNote", { count: graph.nodes.length })}
        </p>
      )}

      {view === "graph" ? (
        <DependencyGraph nodes={graph.nodes} edges={graph.edges} />
      ) : (
        <DependencyTree tree={graph.tree} hasDependencies={graph.hasDependencies} focusTarget={focus} />
      )}
    </div>
  );
}
