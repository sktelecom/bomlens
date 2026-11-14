// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import type { ComponentItem } from "@/lib/api";
import { severityFor, vulnSeverityIndex } from "@/lib/dependencies";
import { defaultDependencyView, type DependencyView } from "@/lib/graphView";
import type { RouteQuery } from "@/lib/route";
import { loadSbom, parseSbomGraph, type SbomGraph } from "@/lib/sbomGraph";
import { dependenciesFromQuery } from "@/lib/section-query";

import { DependencyGraph } from "./DependencyGraph";
import { DependencyTree } from "./DependencyTree";
import { DepError, DepLoading } from "./dependencies/states";
import { ViewSwitch } from "./dependencies/ViewSwitch";
import "./dependencies/dependencies.css";

/**
 * Fetches the raw `_bom.json` (when the section opens), parses the dependency
 * graph client-side, and switches between the node-link graph and the package
 * hierarchy tree. Components carrying a Risk join mark their nodes as
 * vulnerable.
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
   *  and version, from a Vulnerabilities or Components row). Read once per
   *  value: this panel does not write its own state back into the URL. */
  query?: RouteQuery;
}) {
  const { t } = useTranslation();
  const [graph, setGraph] = useState<SbomGraph | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const focus = dependenciesFromQuery(query);
  // The reader's own pick, once made. Until then the view follows the size of
  // the graph (see defaultDependencyView), known only after the SBOM has
  // loaded. A jump always means "show me the tree", even if Graph was left open
  // from a previous visit: the graph has no equivalent jump-and-expand.
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
    return <DepLoading text={t("deps.loading")} />;
  }
  if (state === "error" || !graph) {
    return <DepError text={t("deps.loadError")} onRetry={() => setReloadKey((k) => k + 1)} />;
  }

  const view: DependencyView = picked ?? defaultDependencyView(graph.nodes.length, false);
  // The tree opened because the graph would be a tangle, not because anyone
  // asked for it: say so, so the missing graph is not mistaken for a fault.
  const autoTree = picked === null && view === "tree" && graph.edges.length > 0;
  const viewSwitch = <ViewSwitch view={view} onPick={setPicked} />;

  return (
    <div className="bl-dep-screen">
      {view === "graph" ? (
        <DependencyGraph
          nodes={graph.nodes}
          edges={graph.edges}
          fileBase={sbomFile.replace(/_bom\.json$/, "")}
          viewSwitch={viewSwitch}
        />
      ) : (
        <DependencyTree
          tree={graph.tree}
          hasDependencies={graph.hasDependencies}
          focusTarget={focus}
          viewSwitch={viewSwitch}
          count={graph.componentCount}
          direct={graph.hasDependencies ? graph.nodes.filter((n) => n.direct && !n.root).length : undefined}
          transitive={graph.hasDependencies ? graph.nodes.filter((n) => !n.direct && !n.root).length : undefined}
          note={
            autoTree ? (
              <span className="bl-muted bl-small" data-testid="deps-auto-tree-note">
                {t("deps.autoTreeNote", { count: graph.nodes.length })}
              </span>
            ) : null
          }
        />
      )}
    </div>
  );
}
