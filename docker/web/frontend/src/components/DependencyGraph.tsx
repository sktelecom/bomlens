import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import type { GraphEdge, GraphNode } from "@/lib/sbomGraph";

/**
 * Node-link dependency graph rendered with Cytoscape.js (+ dagre hierarchical
 * layout). Cytoscape is loaded with a dynamic import so it stays out of the
 * initial bundle — the canvas only matters once a user opens this tab.
 *
 * Interactions: click a node to see its details, type to highlight matching
 * packages (others dim). Canvas colors are read from the CSS design tokens at
 * mount so the graph follows light/dark (the canvas can't use Tailwind
 * classes); the direct-dependency accent keeps the SK red brand mark.
 *
 * Large graphs are slow to lay out and unreadable, so above NODE_CAP we skip
 * the canvas and point the user at the tree view instead.
 */
const NODE_CAP = 1500;
const DIRECT_COLOR = "#ea002c"; // SK red — direct dependencies (legend)

let dagreRegistered = false;

/** Resolve themed canvas colors from the CSS custom properties.
 *
 * Tokens store HSL channels space-separated ("240 4% 46%"); Cytoscape's color
 * parser only handles the legacy comma form, so convert before handing it over.
 */
function themeColors() {
  const css = getComputedStyle(document.documentElement);
  const hsl = (name: string) => {
    const channels = css.getPropertyValue(name).trim().replace(/\s+/g, ", ");
    return `hsl(${channels})`;
  };
  return {
    node: hsl("--muted-foreground"),
    text: hsl("--foreground"),
    edge: hsl("--border"),
  };
}

export function DependencyGraph({
  nodes,
  edges,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
}) {
  const { t } = useTranslation();
  const containerRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cyRef = useRef<any>(null);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const tooLarge = nodes.length > NODE_CAP;

  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

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

        const c = themeColors();
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
                "font-size": "10px",
                "background-color": c.node,
                color: c.text,
                "text-valign": "center",
                "text-halign": "right",
                "text-margin-x": 6,
                "min-zoomed-font-size": 7,
                width: 10,
                height: 10,
              },
            },
            {
              selector: 'node[direct = "1"]',
              style: { "background-color": DIRECT_COLOR, width: 14, height: 14 },
            },
            {
              selector: "node.match",
              style: { "border-width": 2, "border-color": c.text },
            },
            {
              selector: "node:selected",
              style: { "border-width": 2, "border-color": c.text },
            },
            { selector: ".dim", style: { opacity: 0.2 } },
            {
              selector: "edge",
              style: {
                width: 1,
                "line-color": c.edge,
                "target-arrow-color": c.edge,
                "target-arrow-shape": "triangle",
                "arrow-scale": 0.7,
                "curve-style": "bezier",
              },
            },
          ],
          layout: { name: "dagre", rankDir: "LR", nodeSep: 28, rankSep: 160, fit: true, padding: 24 },
          // Cap zoom so small graphs (a few nodes) don't blow up to fill the
          // canvas — that's what made labels huge and overlap.
          minZoom: 0.2,
          maxZoom: 1.4,
          wheelSensitivity: 0.2,
        };
        cy = cytoscape(config);
        cyRef.current = cy;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cy.on("tap", "node", (evt: any) => {
          setSelected(nodeById.get(evt.target.id()) ?? null);
        });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cy.on("tap", (evt: any) => {
          if (evt.target === cy) setSelected(null);
        });
      } catch {
        if (!destroyed) setError(true);
      }
    })();

    return () => {
      destroyed = true;
      cyRef.current = null;
      if (cy) cy.destroy();
    };
  }, [nodes, edges, tooLarge, nodeById]);

  // Highlight nodes matching the query; dim the rest (and all edges).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const q = query.trim().toLowerCase();
    cy.batch(() => {
      if (!q) {
        cy.elements().removeClass("dim match");
        return;
      }
      cy.nodes().forEach((n: { data: (k: string) => string; toggleClass: (c: string, on: boolean) => void }) => {
        const hit = (n.data("label") || "").toLowerCase().includes(q);
        n.toggleClass("match", hit);
        n.toggleClass("dim", !hit);
      });
      cy.edges().addClass("dim");
    });
  }, [query, nodes]);

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
      <div className="relative max-w-xs">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("deps.search")}
          className="h-8 pl-8"
        />
      </div>
      <p className="text-xs text-muted-foreground">
        {t("deps.graphLegend")} {t("deps.clickHint")}
      </p>
      <div
        ref={containerRef}
        className="h-[28rem] w-full rounded-md border bg-card"
      />
      {selected && (
        <div className="space-y-2 rounded-md border bg-muted/30 p-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="font-mono font-medium">{selected.label}</span>
            {selected.direct && <Badge tone="critical">{t("deps.direct")}</Badge>}
          </div>
          {selected.type && (
            <div>
              <span className="text-muted-foreground">{t("result.colType")}: </span>
              {selected.type}
            </div>
          )}
          {selected.licenses.length > 0 && (
            <div className="flex flex-wrap items-center gap-1">
              <span className="text-muted-foreground">{t("result.colLicense")}:</span>
              {selected.licenses.map((l, i) => (
                <Badge key={i} variant="muted">
                  {l}
                </Badge>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
