import { GitFork, ListTree, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { loadSbom, parseSbomGraph, type SbomGraph } from "@/lib/sbomGraph";

import { DependencyGraph } from "./DependencyGraph";
import { DependencyTree } from "./DependencyTree";

type View = "graph" | "tree";

/**
 * Fetches the raw `_bom.json` (lazily, when its tab opens), parses the
 * dependency graph client-side, and toggles between the node-link graph and
 * the package hierarchy tree.
 */
export function DependenciesPanel({ sbomFile }: { sbomFile: string }) {
  const { t } = useTranslation();
  const [graph, setGraph] = useState<SbomGraph | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [view, setView] = useState<View>("graph");

  useEffect(() => {
    let active = true;
    setState("loading");
    void loadSbom(sbomFile)
      .then((sbom) => {
        if (!active) return;
        setGraph(parseSbomGraph(sbom));
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });
    return () => {
      active = false;
    };
  }, [sbomFile]);

  if (state === "loading") {
    return (
      <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        {t("deps.loading")}
      </div>
    );
  }
  if (state === "error" || !graph) {
    return <p className="py-8 text-sm text-muted-foreground">{t("deps.loadError")}</p>;
  }

  return (
    <div className="space-y-3">
      <div className="inline-flex rounded-md border p-0.5">
        <Button
          type="button"
          size="sm"
          variant={view === "graph" ? "secondary" : "ghost"}
          onClick={() => setView("graph")}
        >
          <GitFork className="h-4 w-4" />
          {t("deps.viewGraph")}
        </Button>
        <Button
          type="button"
          size="sm"
          variant={view === "tree" ? "secondary" : "ghost"}
          onClick={() => setView("tree")}
        >
          <ListTree className="h-4 w-4" />
          {t("deps.viewTree")}
        </Button>
      </div>

      {view === "graph" ? (
        <DependencyGraph nodes={graph.nodes} edges={graph.edges} />
      ) : (
        <DependencyTree tree={graph.tree} hasDependencies={graph.hasDependencies} />
      )}
    </div>
  );
}
