import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { GraphEdge, GraphNode } from "@/lib/sbomGraph";

/**
 * Node-link dependency graph rendered with Cytoscape.js (+ dagre hierarchical
 * layout). Cytoscape is loaded with a dynamic import so it stays out of the
 * initial bundle — the canvas only matters once a user opens this tab.
 *
 * Large graphs are slow to lay out and unreadable, so above NODE_CAP we skip
 * the canvas and point the user at the tree view instead.
 */
const NODE_CAP = 1500;

let dagreRegistered = false;

export function DependencyGraph({
  nodes,
  edges,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
}) {
  const { t } = useTranslation();
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState(false);
  const tooLarge = nodes.length > NODE_CAP;

  useEffect(() => {
    if (tooLarge || nodes.length === 0) return;
    let destroyed = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let cy: any;

    void (async () => {
      try {
        const [{ default: cytoscape }, { default: dagre }] = await Promise.all([
          import("cytoscape"),
          import("cytoscape-dagre"),
        ]);
        if (!dagreRegistered) {
          cytoscape.use(dagre);
          dagreRegistered = true;
        }
        if (destroyed || !containerRef.current) return;

        // dagre layout options aren't in cytoscape's base LayoutOptions type.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const config: any = {
          container: containerRef.current,
          elements: [
            ...nodes.map((n) => ({
              data: { id: n.id, label: n.label, direct: n.direct ? "1" : "0" },
            })),
            ...edges.map((e) => ({
              data: { id: `${e.source}->${e.target}`, source: e.source, target: e.target },
            })),
          ],
          style: [
            {
              selector: "node",
              style: {
                label: "data(label)",
                "font-size": "9px",
                "background-color": "#94a3b8",
                color: "#1e293b",
                "text-valign": "center",
                "text-halign": "right",
                "text-margin-x": 4,
                width: 10,
                height: 10,
              },
            },
            {
              selector: 'node[direct = "1"]',
              style: { "background-color": "#ea002c", width: 14, height: 14 },
            },
            {
              selector: "edge",
              style: {
                width: 1,
                "line-color": "#cbd5e1",
                "target-arrow-color": "#cbd5e1",
                "target-arrow-shape": "triangle",
                "arrow-scale": 0.7,
                "curve-style": "bezier",
              },
            },
          ],
          layout: { name: "dagre", rankDir: "LR", nodeSep: 16, rankSep: 60 },
          wheelSensitivity: 0.2,
        };
        cy = cytoscape(config);
      } catch {
        if (!destroyed) setError(true);
      }
    })();

    return () => {
      destroyed = true;
      if (cy) cy.destroy();
    };
  }, [nodes, edges, tooLarge]);

  if (nodes.length === 0) {
    return <p className="text-sm text-muted-foreground">{t("deps.empty")}</p>;
  }
  if (tooLarge) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("deps.tooLarge", { count: nodes.length, cap: NODE_CAP })}
      </p>
    );
  }
  if (error) {
    return <p className="text-sm text-muted-foreground">{t("deps.graphError")}</p>;
  }

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">{t("deps.graphLegend")}</p>
      <div
        ref={containerRef}
        className="h-[28rem] w-full rounded-md border bg-card"
      />
    </div>
  );
}
