import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { SEVERITY_ORDER, type Severity } from "@/lib/api";
import type { GraphEdge, GraphNode } from "@/lib/sbomGraph";

const VULN_TONE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

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
  // Risk tokens are stored as hex, so read them raw (Cytoscape accepts hex).
  const raw = (name: string) => css.getPropertyValue(name).trim();
  return {
    node: hsl("--muted-foreground"),
    text: hsl("--foreground"),
    edge: hsl("--border"),
    // Card surface — used as a translucent plate behind node labels.
    bg: hsl("--card"),
    // Direct-dependency accent — SK red brand token (legend mark).
    direct: hsl("--brand"),
    risk: {
      CRITICAL: raw("--risk-critical"),
      HIGH: raw("--risk-high"),
      MEDIUM: raw("--risk-medium"),
      LOW: raw("--risk-low"),
      UNKNOWN: raw("--risk-info"),
    } as Record<Severity, string>,
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

  // Latest query, readable from the long-lived Cytoscape event handlers without
  // rebinding them — so hover highlighting can stand down while a search owns
  // the dim/match classes.
  const queryRef = useRef("");
  useEffect(() => {
    queryRef.current = query;
  }, [query]);

  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  useEffect(() => {
    // No edges = no dependency relationships (e.g. a firmware SBOM): a node-only
    // graph is just overlapping dots, so we show a note instead (see render).
    if (tooLarge || nodes.length === 0 || edges.length === 0) return;
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
              data: {
                id: n.id,
                label: n.label,
                direct: n.direct ? "1" : "0",
                vuln: n.vuln ?? "",
              },
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
                // A translucent card-coloured plate behind each label keeps it
                // legible where labels and edges overlap on a dense graph.
                "text-background-color": c.bg,
                "text-background-opacity": 0.85,
                "text-background-padding": 2,
                "text-background-shape": "roundrectangle",
                width: 10,
                height: 10,
              },
            },
            {
              selector: 'node[direct = "1"]',
              style: { "background-color": c.direct, width: 14, height: 14 },
            },
            // Vulnerable nodes get a severity-coloured ring.
            ...SEVERITY_ORDER.map((sev) => ({
              selector: `node[vuln = "${sev}"]`,
              style: { "border-width": 3, "border-color": c.risk[sev] },
            })),
            {
              selector: "node.match",
              style: { "border-width": 2, "border-color": c.text },
            },
            {
              selector: "node:selected",
              style: { "border-width": 2, "border-color": c.text },
            },
            { selector: ".dim", style: { opacity: 0.2 } },
            // Hover trace: the focused node gets a brand ring while the edges of
            // its neighbourhood thicken and recolour to the foreground, so the
            // package's links read clearly against the dimmed rest.
            {
              selector: "node.focus",
              style: { "border-width": 3, "border-color": c.direct },
            },
            {
              selector: "edge.trace",
              style: {
                width: 2,
                "line-color": c.text,
                "target-arrow-color": c.text,
                "z-index": 10,
              },
            },
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
          layout: { name: "dagre", rankDir: "LR", nodeSep: 36, rankSep: 160, fit: true, padding: 24 },
          // Cap zoom so small graphs (a few nodes) don't blow up to fill the
          // canvas — that's what made labels huge and overlap.
          minZoom: 0.2,
          maxZoom: 1.4,
          wheelSensitivity: 0.2,
        };
        cy = cytoscape(config);
        cyRef.current = cy;
        // First view: a big graph fits to unreadable dots, so when fit zoomed
        // far out, snap to zoom 1 (labels legible) and anchor the top-left —
        // the user pans/scrolls from there. Small graphs keep their fit.
        // dagre runs synchronously inside cytoscape(config), so layoutstop
        // has already fired before any listener can attach — snap now, and
        // keep the listener for any later async re-layout.
        const snapLegible = () => {
          if (cy.zoom() < 0.9) {
            cy.zoom(1);
            const bb = cy.elements().boundingBox();
            cy.pan({ x: 24 - bb.x1, y: 24 - bb.y1 });
          }
        };
        snapLegible();
        cy.one("layoutstop", snapLegible);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cy.on("tap", "node", (evt: any) => {
          setSelected(nodeById.get(evt.target.id()) ?? null);
        });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cy.on("tap", (evt: any) => {
          if (evt.target === cy) setSelected(null);
        });
        // Hover to trace a package: highlight its neighbourhood (node, its edges
        // and adjacent packages), dim the rest. Skipped while a search query
        // owns the dim/match classes so the two never fight.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cy.on("mouseover", "node", (evt: any) => {
          if (queryRef.current.trim()) return;
          const node = evt.target;
          const nb = node.closedNeighborhood();
          cy.elements().difference(nb).addClass("dim");
          nb.edges().addClass("trace");
          node.addClass("focus");
        });
        cy.on("mouseout", "node", () => {
          if (queryRef.current.trim()) return;
          cy.elements().removeClass("dim trace focus");
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

  // No nodes, or nodes but no edges (no dependency relationships, e.g. a
  // firmware SBOM): a node-only graph is unreadable overlapping dots, so show
  // the "no relationships" note and let the user use Components / Tree instead.
  if (nodes.length === 0 || edges.length === 0) {
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
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-brand" aria-hidden />
          {t("deps.direct")}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-muted-foreground" aria-hidden />
          {t("deps.legendTransitive")}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span
            className="h-2.5 w-2.5 shrink-0 rounded-full border-2 border-risk-high bg-muted-foreground"
            aria-hidden
          />
          {t("deps.legendVuln")}
        </span>
        <span className="text-muted-foreground/80">
          {t("deps.arrowHint")} {t("deps.interactHint")} {t("deps.keyboardHint")}
        </span>
      </div>
      <div
        ref={containerRef}
        role="img"
        aria-label={t("deps.graphAria")}
        className="h-[28rem] w-full rounded-md border bg-card"
      />
      {selected && (
        <div className="space-y-2 rounded-md border bg-muted/30 p-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="font-mono font-medium">{selected.label}</span>
            {selected.vuln && (
              <Badge tone={VULN_TONE[selected.vuln]} title={t("deps.hasVuln")}>
                {t(`severity.${selected.vuln}`)}
              </Badge>
            )}
            {selected.direct && <Badge tone="info">{t("deps.direct")}</Badge>}
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
