// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  ArrowRightIcon,
  DownloadIcon,
  PackageIcon,
  ScreenFullIcon,
  SearchIcon,
  WorkflowIcon,
  XIcon,
  ZoomInIcon,
  ZoomOutIcon,
} from "@primer/octicons-react";
import { Button, IconButton, Label, TextInput } from "@primer/react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { SeverityLabel } from "@/components/primer";
import { SEVERITY_ORDER, type Severity } from "@/lib/api";
import { cssLengthToPx } from "@/lib/graphView";
import type { GraphEdge, GraphNode } from "@/lib/sbomGraph";

import { LicenseLabels } from "./dependencies/LicenseLabels";
import { DepEmpty, DepError } from "./dependencies/states";
import "./dependencies/dependencies.css";

/**
 * Node-link dependency graph rendered with Cytoscape.js (+ dagre hierarchical
 * layout). Cytoscape is loaded with a dynamic import so it stays out of the
 * initial bundle: the canvas only matters once a reader opens this view.
 *
 * Interactions: click a node to see its details, type to highlight matching
 * packages (others dim), hover to trace a package's neighbourhood. Canvas
 * colours are read from the Primer variables at mount so the graph follows
 * light and dark (a canvas cannot use CSS classes). The direct-dependency
 * accent is the foreground colour, never the accent: a coloured dot next to the
 * severity rings would read as a finding.
 *
 * Large graphs are slow to lay out and unreadable, so above NODE_CAP the canvas
 * is skipped and the reader is pointed at the tree instead.
 */
const NODE_CAP = 1500;

/** Cytoscape shape per severity, mirroring the severity marker shapes. UNKNOWN
 *  keeps the circle but is drawn hollow with a dashed ring (see the style
 *  list): "not graded" is not a grade. */
const NODE_SHAPE: Partial<Record<Severity, string>> = {
  CRITICAL: "diamond",
  HIGH: "triangle",
  MEDIUM: "ellipse",
  LOW: "rectangle",
};

let dagreRegistered = false;

/** Resolve the canvas colours from the Primer variables in effect on `el`. */
function themeColors(el: Element) {
  const css = getComputedStyle(el);
  const v = (name: string) => css.getPropertyValue(name).trim();
  // Label size follows the body-small text token (12px), never a literal.
  const labelPx = cssLengthToPx(v("--text-body-size-small"), parseFloat(getComputedStyle(document.documentElement).fontSize) || 16);
  return {
    labelPx: labelPx ?? 12,
    font: v("--fontStack-monospace") || "monospace",
    node: v("--fgColor-muted"),
    text: v("--fgColor-default"),
    edge: v("--borderColor-default"),
    bg: v("--bgColor-default"),
    direct: v("--fgColor-default"),
    risk: {
      CRITICAL: v("--fgColor-danger"),
      HIGH: v("--fgColor-severe"),
      MEDIUM: v("--fgColor-attention"),
      LOW: v("--display-gray-fgColor") || v("--fgColor-muted"),
      UNKNOWN: v("--fgColor-muted"),
    } as Record<Severity, string>,
  };
}

export function DependencyGraph({
  nodes,
  edges,
  fileBase,
  viewSwitch,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** The scan's file name stem, so the saved PNG names its scan. */
  fileBase: string;
  viewSwitch?: ReactNode;
}) {
  const { t } = useTranslation();
  const containerRef = useRef<HTMLDivElement>(null);
  // Mirrored out of cytoscape so the canvas's zoom is observable from the DOM.
  const [zoomLevel, setZoomLevel] = useState(1);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cyRef = useRef<any>(null);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  // Bumped when a canvas is created, so a search typed while it loaded is applied.
  const [drawn, setDrawn] = useState(0);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const tooLarge = nodes.length > NODE_CAP;

  // Latest query, readable from the long-lived Cytoscape handlers without
  // rebinding them, so hover tracing stands down while a search owns the
  // dim and match classes.
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
    // No edges means no dependency relationships (a firmware SBOM): a
    // node-only graph is overlapping dots, so a note is shown instead.
    if (tooLarge || nodes.length === 0 || edges.length === 0) return;
    let destroyed = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let cy: any;

    void (async () => {
      try {
        const [{ default: cytoscape }, { default: dagre }] = await Promise.all([import("cytoscape"), import("cytoscape-dagre")]);
        if (!dagreRegistered) {
          cytoscape.use(dagre);
          dagreRegistered = true;
        }
        if (destroyed || !containerRef.current) return;

        const c = themeColors(containerRef.current);
        // Published so a test can pin the label size the canvas was given.
        containerRef.current.dataset.labelPx = String(c.labelPx);
        // dagre layout options are not in cytoscape's base LayoutOptions type.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const config: any = {
          container: containerRef.current,
          elements: [
            ...nodes.map((n) => ({
              data: {
                id: n.id,
                label: n.label,
                // The name alone, for the few nodes that carry a label.
                short: n.name || n.label,
                show: n.root || n.direct || n.vuln ? "1" : "0",
                direct: n.direct ? "1" : "0",
                root: n.root ? "1" : "0",
                vuln: n.vuln ?? "",
              },
            })),
            ...edges.map((e) => ({ data: { id: `${e.source}->${e.target}`, source: e.source, target: e.target } })),
          ],
          style: [
            {
              selector: "node",
              style: {
                // Only the scanned component, direct and vulnerable packages and
                // the node being looked at carry a name: a label on all of them
                // overlaps into noise.
                label: "",
                "font-size": `${c.labelPx}px`,
                "font-family": c.font,
                "background-color": c.node,
                color: c.text,
                "text-valign": "center",
                "text-halign": "right",
                "text-margin-x": 6,
                // Below 8 rendered px a label is noise, so it is left out until
                // the reader zooms in; the node itself stays.
                "min-zoomed-font-size": 6,
                // A translucent plate behind each label keeps it legible where
                // labels and edges overlap on a dense graph.
                "text-background-color": c.bg,
                "text-background-opacity": 0.85,
                "text-background-padding": 2,
                "text-background-shape": "roundrectangle",
                width: 10,
                height: 10,
              },
            },
            // The scanned component itself: the direct accent but hollow, so it
            // reads as the thing the arrows start from.
            {
              selector: 'node[root = "1"]',
              style: { "background-color": c.bg, "border-width": 3, "border-color": c.direct, width: 16, height: 16 },
            },
            { selector: 'node[direct = "1"]', style: { "background-color": c.direct, width: 14, height: 14 } },
            // Vulnerable nodes get a severity-coloured ring and, for the four
            // graded severities, the severity badge's shape, so the grade does
            // not rest on hue.
            ...SEVERITY_ORDER.map((sev) => ({
              selector: `node[vuln = "${sev}"]`,
              style: { "border-width": 3, "border-color": c.risk[sev], ...(NODE_SHAPE[sev] ? { shape: NODE_SHAPE[sev] } : {}) },
            })),
            { selector: 'node[vuln = "UNKNOWN"]', style: { "border-style": "dashed", "background-color": c.bg } },
            { selector: "node.match", style: { "border-width": 2, "border-color": c.text } },
            { selector: "node:selected", style: { "border-width": 2, "border-color": c.text } },
            { selector: ".dim", style: { opacity: 0.2 } },
            // Hover trace: the focused node gets a foreground ring while the
            // edges of its neighbourhood thicken and take the foreground colour.
            { selector: "node.focus", style: { "border-width": 3, "border-color": c.direct } },
            { selector: "edge.trace", style: { width: 2, "line-color": c.text, "target-arrow-color": c.text, "z-index": 10 } },
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
          // nodeSep is the gap between stacked nodes. The graph is as tall as
          // its widest rank, and a tall graph fits to a tiny zoom, so the stack
          // stays tight: with 12px labels, about 22px per node is enough.
          layout: { name: "dagre", rankDir: "LR", nodeSep: 10, rankSep: 160, fit: true, padding: 12 },
          // Cap zoom so a small graph does not blow up to fill the canvas. The
          // floor is low so a fit is never clamped to a cropped view.
          minZoom: 0.02,
          maxZoom: 1.4,
          wheelSensitivity: 0.2,
        };
        cy = cytoscape(config);
        cyRef.current = cy;
        // First view: the layout's own fit, the whole graph inside the pane.
        // The layout ran synchronously inside cytoscape(config); publish the
        // level it landed on.
        setZoomLevel(cy.zoom());
        setDrawn((n) => n + 1);
        // Every zoom lands here (buttons, wheel, the initial fit).
        cy.on("zoom", () => setZoomLevel(cy.zoom()));
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cy.on("tap", "node", (evt: any) => setSelected(nodeById.get(evt.target.id()) ?? null));
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cy.on("tap", (evt: any) => {
          if (evt.target === cy) setSelected(null);
        });
        // Hover to trace a package: highlight its neighbourhood, dim the rest.
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
  }, [nodes, edges, tooLarge, nodeById, attempt]);

  // Highlight nodes matching the query; dim the rest (and all edges).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const q = query.trim().toLowerCase();
    cy.batch(() => {
      if (!q) {
        cy.elements().removeClass("dim match");
        delete containerRef.current?.dataset.matches;
        return;
      }
      let matches = 0;
      cy.nodes().forEach((n: { data: (k: string) => string; toggleClass: (c: string, on: boolean) => void }) => {
        const hitNode = (n.data("label") || "").toLowerCase().includes(q);
        if (hitNode) matches += 1;
        n.toggleClass("match", hitNode);
        n.toggleClass("dim", !hitNode);
      });
      cy.edges().addClass("dim");
      // Published so a test can see how many nodes the search lit up.
      if (containerRef.current) containerRef.current.dataset.matches = String(matches);
    });
  }, [query, nodes, drawn]);

  const bar = viewSwitch ? <div className="bl-dep-bar">{viewSwitch}</div> : null;

  // No nodes, or nodes but no edges: the "no relationships" note; the reader
  // uses Components or the tree instead.
  if (nodes.length === 0 || edges.length === 0) {
    return (
      <div className="bl-stack-8">
        {bar}
        <DepEmpty icon={WorkflowIcon} title={t("deps.empty")} hint={t("deps.emptyHint")} testId="deps-empty" />
      </div>
    );
  }
  if (tooLarge) {
    return (
      <div className="bl-stack-8">
        {bar}
        <DepEmpty icon={WorkflowIcon} title={t("deps.tooLarge", { count: nodes.length, cap: NODE_CAP })} testId="deps-too-large" />
      </div>
    );
  }
  if (error) {
    return (
      <div className="bl-stack-8">
        {bar}
        <DepError text={t("deps.graphError")} onRetry={() => {
            // Clear the error in the same update, so the canvas container is
            // mounted before the effect runs again.
            setError(false);
            setAttempt((n) => n + 1);
          }} />
      </div>
    );
  }

  const zoomBy = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    // Zoom about the middle of the viewport, so what the reader looks at stays.
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    setZoomLevel(cy.zoom());
  };
  const fitToView = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.fit(undefined, 12);
    setZoomLevel(cy.zoom());
  };
  const savePng = () => {
    const cy = cyRef.current;
    if (!cy) return;
    // Rendered on the page colour rather than transparent: a transparent PNG
    // pasted into a light document loses every pale node.
    const uri = cy.png({ full: true, scale: 2, bg: getComputedStyle(document.body).backgroundColor });
    const a = document.createElement("a");
    a.href = uri;
    a.download = `${fileBase}_dependency-graph.png`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  return (
    <div className="bl-stack-8">
      <div className="bl-dep-bar">
        {viewSwitch}
        <TextInput
          className="bl-dep-search"
          leadingVisual={SearchIcon}
          aria-label={t("deps.search")}
          placeholder={t("deps.search")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <span className="bl-dep-btns">
          <Button size="small" leadingVisual={ZoomInIcon} onClick={() => zoomBy(1.25)}>
            {t("deps.zoomIn")}
          </Button>
          <Button size="small" leadingVisual={ZoomOutIcon} onClick={() => zoomBy(0.8)}>
            {t("deps.zoomOut")}
          </Button>
          <Button size="small" leadingVisual={ScreenFullIcon} onClick={fitToView}>
            {t("deps.fit")}
          </Button>
          <Button size="small" leadingVisual={DownloadIcon} onClick={savePng}>
            {t("deps.savePng")}
          </Button>
        </span>
      </div>
      <ul aria-label={t("deps.legend")} data-testid="deps-legend" className="bl-dep-legend">
        <li>
          <span className="bl-dep-dot bl-dep-dot-root" aria-hidden />
          {t("deps.legendRoot")}
        </li>
        <li>
          <span className="bl-dep-dot bl-dep-dot-direct" aria-hidden />
          {t("deps.direct")}
        </li>
        <li>
          <span className="bl-dep-dot bl-dep-dot-transitive" aria-hidden />
          {t("deps.legendTransitive")}
        </li>
        {/* A vulnerable package keeps its dot and gets a ring in the grade's
            shape and colour: the same Marker the severity Labels use. */}
        <li className="bl-dep-legend-lead">{t("deps.legendVuln")}</li>
        {SEVERITY_ORDER.filter((sev) => sev !== "UNKNOWN").map((sev) => (
          <li key={sev}>
            <SeverityLabel severity={sev} quiet size="small" />
          </li>
        ))}
      </ul>
      <div
        ref={containerRef}
        role="img"
        aria-label={t("deps.graphAria")}
        // The canvas tells the DOM nothing, so its zoom is published here to
        // make "the button actually zoomed" observable.
        data-zoom={zoomLevel.toFixed(2)}
        className="bl-box bl-dep-canvas"
      />
      {/* How to read and use the canvas, one line under it so the legend keeps to node kinds. */}
      <p className="bl-dep-hints bl-flat" data-testid="deps-hints">
        <span>
          <ArrowRightIcon size={12} aria-hidden />
          {t("deps.legendArrow")}
        </span>
        <span>{t("deps.legendHover")}</span>
        <span>{t("deps.legendKeyboard")}</span>
      </p>
      {selected && (
        <section className="bl-box" aria-label={selected.label} data-testid="deps-detail">
          <div className="bl-box-head bl-wrap">
            <PackageIcon size={16} aria-hidden />
            <h2 className="bl-mono bl-dep-detail-title bl-flat">{selected.label}</h2>
            {selected.vuln && (
              <span title={t("deps.hasVuln")}>
                <SeverityLabel severity={selected.vuln} />
              </span>
            )}
            {selected.direct && <Label variant="secondary">{t("deps.direct")}</Label>}
            <span className="bl-grow" />
            <IconButton size="small" variant="invisible" icon={XIcon} aria-label={t("viewer.close")} onClick={() => setSelected(null)} />
          </div>
          {(selected.type || selected.licenses.length > 0) && (
            <div className="bl-box-body">
              <dl className="bl-dep-kv">
                {selected.type && (
                  <>
                    <dt>{t("result.colType")}</dt>
                    <dd>{selected.type}</dd>
                  </>
                )}
                {selected.licenses.length > 0 && (
                  <>
                    <dt>{t("result.colLicense")}</dt>
                    <dd>
                      <LicenseLabels licenses={selected.licenses} all />
                    </dd>
                  </>
                )}
              </dl>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
