// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { GitBranchIcon, PackageIcon, SearchIcon } from "@primer/octicons-react";
import { CounterLabel, Label, TextInput, TreeView } from "@primer/react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { SeverityLabel, severityLabelKey } from "@/components/primer";
import { formatNumber } from "@/lib/format";
import { licenseOperands, shownLicenseLabels } from "@/lib/licenseOperands";
import { findFirstMatch, findPathToRef, type TreeNode } from "@/lib/sbomGraph";

import { LicenseLabels } from "./dependencies/LicenseLabels";
import { DepEmpty } from "./dependencies/states";
import "./dependencies/dependencies.css";

/** The DOM id of a tree row, from its index path ("0.2.1" becomes "dep-0-2-1"). */
const rowId = (path: string) => `dep-${path.replace(/\./g, "-")}`;

/**
 * Collapsible package hierarchy built from CycloneDX `dependencies[]`. Direct
 * dependencies sit at the top and start open; expanding a row reveals its
 * transitive dependencies. When the SBOM has no dependency graph the caller
 * passes a flat list (every node at depth 0, no children).
 *
 * The rows are a Primer TreeView, which carries the tree semantics the graph
 * view sends keyboard users here for: one tab stop, arrow keys, Home and End,
 * Enter and Space, and a name, level and expanded state on every row.
 */
export function DependencyTree({
  tree,
  hasDependencies,
  focusTarget,
  viewSwitch,
  count,
  direct,
  transitive,
  note,
}: {
  tree: TreeNode[];
  hasDependencies: boolean;
  /** Jump here on mount and whenever it changes: every ancestor branch opens
   *  and the matched row gets keyboard focus, scrolled into view. Set from a
   *  "View in Dependencies" link, carried in the URL so the jump survives a
   *  reload or a shared link. */
  focusTarget?: { name: string; version?: string } | null;
  viewSwitch?: ReactNode;
  /** Packages in the SBOM (the same number as Components in the page meta). */
  count?: number;
  /** Direct and transitive packages, when the SBOM records relationships. */
  direct?: number;
  transitive?: number;
  note?: ReactNode;
}) {
  const { t, i18n } = useTranslation();
  // Paths, not ids: the same package can sit under two parents.
  const [open, setOpen] = useState<Set<string>>(() => new Set(tree.map((_, i) => String(i))));
  const [term, setTerm] = useState("");
  const [hit, setHit] = useState<string | null>(null);
  const [noMatch, setNoMatch] = useState(false);

  // Expand to a match and bring it into view. `focus` moves the keyboard there
  // too: a jump from another section does, typing in the search box does not
  // (the cursor stays in the box; Enter moves it).
  const jump = useCallback((found: ReturnType<typeof findFirstMatch>, focus: boolean) => {
    if (!found) {
      setHit(null);
      setNoMatch(true);
      return;
    }
    setNoMatch(false);
    setOpen((prev) => new Set([...prev, ...found.ancestors]));
    setHit(found.target);
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        const el = document.getElementById(rowId(found.target));
        if (!el) return;
        el.scrollIntoView({ block: "center" });
        if (focus) el.focus({ preventScroll: true });
      }),
    );
  }, []);

  useEffect(() => {
    if (focusTarget) jump(findPathToRef(tree, focusTarget), true);
    // Only re-run when the target itself changes, not on every `tree` identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusTarget?.name, focusTarget?.version]);

  const onSearch = (v: string) => {
    setTerm(v);
    const needle = v.trim().toLowerCase();
    if (!needle) {
      setNoMatch(false);
      setHit(null);
      return;
    }
    jump(findFirstMatch(tree, (n) => n.name.toLowerCase().includes(needle)), false);
  };

  if (tree.length === 0) {
    return (
      <div className="bl-stack">
        {viewSwitch && <div className="bl-dep-bar">{viewSwitch}</div>}
        <DepEmpty icon={GitBranchIcon} title={t("deps.empty")} testId="deps-empty" />
      </div>
    );
  }

  // The description adds only what the name does not hold: "Direct", which a
  // top-level row does not show, and the licences folded into "+N".
  const describe = (node: TreeNode, level: number) =>
    [level === 1 ? t("deps.direct") : null, ...licenseOperands(node.licenses).slice(2)]
      .filter(Boolean)
      .join(", ");

  const render = (nodes: TreeNode[], prefix: string, level: number): ReactNode =>
    nodes.map((node, i) => {
      const path = prefix ? `${prefix}.${i}` : String(i);
      const hasChildren = node.children.length > 0 && !node.cycle;
      const expanded = open.has(path);
      // The name holds the row's visible words in order (name, version, cycle,
      // severity, the licence labels as shown), so it contains what is on screen.
      const label = [
        node.name,
        node.version,
        node.cycle ? t("deps.cycle") : null,
        node.vuln ? t(severityLabelKey(node.vuln)) : null,
        ...shownLicenseLabels(node.licenses),
      ]
        .filter(Boolean)
        .join(" ");
      return (
        <TreeView.Item
          key={path}
          id={rowId(path)}
          aria-label={label}
          expanded={hasChildren ? expanded : null}
          current={hit === path}
          onExpandedChange={(e) =>
            setOpen((prev) => {
              const next = new Set(prev);
              if (e) next.add(path);
              else next.delete(path);
              return next;
            })
          }
        >
          <TreeView.LeadingVisual>
            <PackageIcon />
          </TreeView.LeadingVisual>
          <span className="bl-dep-name bl-mono">
            {node.name}
            {node.version && <span className="bl-muted"> {node.version}</span>}
            {node.cycle && (
              <Label variant="secondary" className="bl-dep-label bl-dep-cycle">
                {/* A word break from the version; it starts the line, so it takes no room. */}{" "}
                {t("deps.cycle")}
              </Label>
            )}
          </span>
          {/* Ends the label's line, so it takes no room; it keeps the label and
              the trailing words apart in the text. */}{" "}
          {/* The visible trailing part is aria-hidden in Primer, so what it shows
              is also given as the row's description (its `label`): a direct
              dependency has no visible label (it sits at the top level), so the
              word is there for assistive technology, with the folded licences. */}
          <TreeView.TrailingVisual label={describe(node, level)}>
            <span className="bl-dep-trail">
              {node.vuln && (
                <span title={t("deps.hasVuln")}>
                  <SeverityLabel severity={node.vuln} />
                </span>
              )}
              {node.vuln && node.licenses.length > 0 && " "}
              <LicenseLabels licenses={node.licenses} />
            </span>
          </TreeView.TrailingVisual>
          {/* A collapsed branch still gets a (cheap, truthy) child: with none, Primer
              reads the item as a leaf and drops its expanded state, so it could
              not be opened again. */}
          {hasChildren && <TreeView.SubTree>{expanded ? render(node.children, path, level + 1) : <></>}</TreeView.SubTree>}
        </TreeView.Item>
      );
    });

  return (
    <div className="bl-stack-8">
      <div className="bl-dep-bar">
        {viewSwitch}
        <TextInput
          className="bl-dep-search"
          leadingVisual={SearchIcon}
          aria-label={t("deps.search")}
          placeholder={t("deps.search")}
          value={term}
          onChange={(e) => onSearch(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && hit) {
              e.preventDefault();
              document.getElementById(rowId(hit))?.focus();
            }
          }}
        />
      </div>
      {/* Always mounted, so a screen reader announces the text when it changes. */}
      <span className="bl-muted bl-small bl-dep-status" role="status" data-testid="deps-search-status">
        {noMatch ? t("deps.searchNoMatch") : hit && term ? t("deps.searchHint") : ""}
      </span>
      {note}
      {!hasDependencies && (
        <p className="bl-muted bl-flat" data-testid="deps-flat-note">
          {t("deps.flatFallback")}
        </p>
      )}
      <section className="bl-box" aria-labelledby="dep-tree-title">
        <div className="bl-box-head">
          <h2 id="dep-tree-title">{t("deps.packages")}</h2>
          {count !== undefined && <CounterLabel>{formatNumber(count, i18n.language)}</CounterLabel>}
          {direct !== undefined && transitive !== undefined && (
            <span className="bl-muted bl-small" data-testid="deps-split">
              {t("nav.depsSaid", { direct: formatNumber(direct, i18n.language), transitive: formatNumber(transitive, i18n.language) })}
            </span>
          )}
        </div>
        <div className="bl-dep-tree">
          <TreeView aria-label={t("deps.treeLabel")} truncate={false}>
            {render(tree, "", 1)}
          </TreeView>
        </div>
      </section>
    </div>
  );
}
