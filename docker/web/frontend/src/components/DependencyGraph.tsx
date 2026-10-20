// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Download,
  Keyboard,
  Maximize2,
  MousePointer2,
  MoveRight,
  Search,
  Workflow,
  ZoomIn,
  ZoomOut,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorState } from "@/components/ui/state";
import { SEVERITY_ORDER, type Severity } from "@/lib/api";
import { cssLengthToPx } from "@/lib/graphView";
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
 * classes). The direct-dependency accent is the foreground colour: the brand
 * red is not a data colour, and a red dot reads as "problem" next to the
 * severity rings (token-lint rejects brand tokens in this file).
 *
 * Large graphs are slow to lay out and unreadable, so above NODE_CAP we skip
 * the canvas and point the user at the tree view instead.
 */
const NODE_CAP = 1500;

/** Cytoscape shape per severity, mirroring `SEVERITY_SHAPE` in ui/marker.tsx.
 *  UNKNOWN keeps the circle, but is drawn hollow with a dashed ring (see the
 *  style list), the counterpart of the dash marker: "not graded" is not a grade,
 *  and a plain grey ring was only a colour difference from a low-severity ring. */
const NODE_SHAPE: Partial<Record<Severity, string>> = {
  CRITICAL: "diamond",
  HIGH: "triangle",
  MEDIUM: "ellipse",
  LOW: "rectangle",
};

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
  // Risk tokens are NOT hex: they store RGB channels space-separated
  // ("234 88 12"), because the Tailwind utilities compose them as
  // `rgb(var(--risk-high) / <alpha-value>)`. Handing the bare channels to
  // Cytoscape left it unable to parse a colour, so every severity ring fell back
  // to black — invisible against the dark canvas, and out of step with the
  // legend, which renders the same severities through the utility classes.
  const rgb = (name: string) => {
    const channels = css.getPropertyValue(name).trim().replace(/\s+/g, ", ");
    return `rgb(${channels})`;
  };
  // Label size follows the --font-size-label token (12px), never a literal.
  const labelPx = cssLengthToPx(
    css.getPropertyValue("--font-size-label"),
    parseFloat(css.fontSize) || 16,
  );
  return {
    labelPx: labelPx ?? 12,
    node: hsl("--muted-foreground"),
    text: hsl("--foreground"),
    edge: hsl("--border"),
    // Card surface — used as a translucent plate behind node labels.
    bg: hsl("--card"),
    // Direct-dependency accent: the foreground colour (legend mark).
    direct: hsl("--foreground"),
    risk: {
      CRITICAL: rgb("--risk-critical"),
      HIGH: rgb("--risk-high"),
      MEDIUM: rgb("--risk-medium"),
      LOW: rgb("--risk-low"),
      UNKNOWN: rgb("--risk-info"),
    } as Record<Severity, string>,
  };
}

/** One legend entry: a mark and a short label in a pill. `quiet` entries are
 *  how-to hints rather than node kinds, so they drop the border. */
function LegendChip({
  label,
  quiet,
  children,
}: {
  label: string;
  quiet?: boolean;
  children: React.ReactNode;
}) {
  return (
    <li
      className={
        quiet
          ? "inline-flex items-center gap-1.5 px-1.5 py-0.5 text-label text-muted-foreground"
          : "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-label text-foreground"
      }
    >
      {children}
      {label}
    </li>
  );
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
  // Mirrored out of cytoscape so the control row can publish it; the canvas
  // itself tells the DOM nothing.
  const [zoomLevel, setZoomLevel] = useState(1);
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
        // Published so a test can pin the label size the canvas was given.
        containerRef.current.dataset.labelPx = String(c.labelPx);
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
                root: n.root ? "1" : "0",
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
                "font-size": `${c.labelPx}px`,
                "background-color": c.node,
                color: c.text,
                "text-valign": "center",
                "text-halign": "right",
                "text-margin-x": 6,
                // Below 8 rendered px a label is noise, so it is left out until the
                // reader zooms in; the node itself stays.
                "min-zoomed-font-size": 8,
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
            // The scanned component itself: same accent as a direct dependency
            // but hollow, so it reads as the thing the arrows start from rather
            // than as one more package in the list.
            {
              selector: 'node[root = "1"]',
              style: {
                "background-color": c.bg,
                "border-width": 3,
                "border-color": c.direct,
                width: 16,
                height: 16,
              },
            },
            {
              selector: 'node[direct = "1"]',
              style: { "background-color": c.direct, width: 14, height: 14 },
            },
            // Vulnerable nodes get a severity-coloured ring and, for the four
            // graded severities, the same shape as the severity badge (diamond,
            // triangle, circle, square), so the grade does not rest on hue.
            ...SEVERITY_ORDER.map((sev) => ({
              selector: `node[vuln = "${sev}"]`,
              style: {
                "border-width": 3,
                "border-color": c.risk[sev],
                ...(NODE_SHAPE[sev] ? { shape: NODE_SHAPE[sev] } : {}),
              },
            })),
            {
              selector: 'node[vuln = "UNKNOWN"]',
              style: { "border-style": "dashed", "background-color": c.bg },
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
            // Hover trace: the focused node gets a foreground ring while the edges of
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
          // nodeSep is the gap between stacked nodes. The graph is as tall as its
          // widest rank, and a tall graph fits to a tiny zoom, so keep the stack
          // tight: with 12px labels, about 22px per node is enough to read.
          layout: { name: "dagre", rankDir: "LR", nodeSep: 10, rankSep: 160, fit: true, padding: 24 },
          // Cap zoom so small graphs (a few nodes) don't blow up to fill the
          // canvas — that's what made labels huge and overlap. The floor is low
          // so a fit is never clamped to a view that crops the graph.
          minZoom: 0.02,
          maxZoom: 1.4,
          wheelSensitivity: 0.2,
        };
        cy = cytoscape(config);
        cyRef.current = cy;
        // First view: the layout's own fit, which shows the whole graph inside
        // the pane. A big graph used to be snapped to zoom 1 and anchored at the
        // top-left right after this, which cut nodes off, so there is
        // deliberately no "legible zoom" override here: labels stay hidden until
        // the reader zooms, and a graph large enough to need that opens as the
        // tree. The layout runs synchronously inside cytoscape(config); publish
        // the level it landed on.
        setZoomLevel(cy.zoom());
        // Every zoom lands here — the buttons, the wheel, the initial fit — so
        // the published level is the graph's own, not a guess at what it became.
        cy.on("zoom", () => setZoomLevel(cy.zoom()));

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
    return (
      <EmptyState icon={Workflow} hint={t("deps.emptyHint")}>
        {t("deps.empty")}
      </EmptyState>
    );
  }
  if (tooLarge) {
    return (
      <EmptyState icon={Workflow}>
        {t("deps.tooLarge", { count: nodes.length, cap: NODE_CAP })}
      </EmptyState>
    );
  }
  if (error) {
    return <ErrorState>{t("deps.graphError")}</ErrorState>;
  }

  const zoomBy = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    // Zoom about the middle of the viewport rather than the graph's origin, so
    // what the reader is looking at stays where it is.
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    setZoomLevel(cy.zoom());
  };

  const fitToView = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.fit(undefined, 24);
    setZoomLevel(cy.zoom());
  };

  const savePng = () => {
    const cy = cyRef.current;
    if (!cy) return;
    // Rendered on the card colour rather than transparent: a transparent PNG
    // pasted into a light document loses every pale node.
    const uri = cy.png({ full: true, scale: 2, bg: getComputedStyle(document.body).backgroundColor });
    const a = document.createElement("a");
    a.href = uri;
    a.download = "dependency-graph.png";
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

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
      <ul
        aria-label={t("deps.legend")}
        data-testid="deps-legend"
        className="flex flex-wrap items-center gap-1.5"
      >
        <LegendChip label={t("deps.legendRoot")}>
          <span className="h-2.5 w-2.5 shrink-0 rounded-full border-2 border-foreground bg-card" aria-hidden />
        </LegendChip>
        <LegendChip label={t("deps.direct")}>
          <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-foreground" aria-hidden />
        </LegendChip>
        <LegendChip label={t("deps.legendTransitive")}>
          <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-muted-foreground" aria-hidden />
        </LegendChip>
        <LegendChip label={t("deps.legendVuln")}>
          <span
            className="h-2.5 w-2.5 shrink-0 rounded-full border-2 border-risk-high bg-muted-foreground"
            aria-hidden
          />
        </LegendChip>
        <LegendChip label={t("deps.legendArrow")} quiet>
          <MoveRight className="h-3.5 w-3.5 shrink-0" aria-hidden />
        </LegendChip>
        <LegendChip label={t("deps.legendHover")} quiet>
          <MousePointer2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
        </LegendChip>
        <LegendChip label={t("deps.legendKeyboard")} quiet>
          <Keyboard className="h-3.5 w-3.5 shrink-0" aria-hidden />
        </LegendChip>
      </ul>
      <div className="flex flex-wrap items-center gap-1.5">
        <Button type="button" variant="outline" size="sm" onClick={() => zoomBy(1.25)}>
          <ZoomIn className="mr-1.5 h-3.5 w-3.5" aria-hidden />
          {t("deps.zoomIn")}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => zoomBy(0.8)}>
          <ZoomOut className="mr-1.5 h-3.5 w-3.5" aria-hidden />
          {t("deps.zoomOut")}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={fitToView}>
          <Maximize2 className="mr-1.5 h-3.5 w-3.5" aria-hidden />
          {t("deps.fit")}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={savePng}>
          <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden />
          {t("deps.savePng")}
        </Button>
      </div>
      <div
        ref={containerRef}
        role="img"
        aria-label={t("deps.graphAria")}
        // The graph is a canvas, so its zoom is invisible to the DOM and a test
        // could otherwise only assert that a button exists. Publishing the level
        // makes "the button actually zoomed" observable.
        data-zoom={zoomLevel.toFixed(2)}
        className="h-[32rem] w-full rounded-md border bg-card"
      />
      {selected && (
        <div className="space-y-2 rounded-md border bg-muted/30 p-3 text-label">
          <div className="flex items-center gap-2">
            <span className="font-mono font-medium">{selected.label}</span>
            {selected.vuln && (
              <Badge tone={VULN_TONE[selected.vuln]} mark title={t("deps.hasVuln")}>
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
