// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The Vulnerabilities table's preset views and its layout, as they travel in
 * the URL.
 *
 * A preset is a named subset ("what can I fix now"), not a filter the reader
 * builds, so a link can say "show me this" in one word. It sits next to the
 * severity chip and the search box in the query, and narrows with them (all
 * three must match). The layout is the flat list or the package grouping.
 *
 * Both are left out of the query at their default, like every other piece of
 * table state, and an unknown value reads as the default.
 */
import type { VulnItem } from "./api";
import type { RouteQuery } from "./route";

export type VulnView =
  | "all"
  | "fixable"
  | "unfixed"
  | "exploited"
  | "critical-high"
  | "fixable-severe";
export type VulnLayout = "list" | "package";

/** In the order the chips show. */
export const VULN_VIEWS: readonly VulnView[] = ["all", "fixable", "unfixed", "exploited", "critical-high"];
/** Every view a link can name. `fixable-severe` (Critical or High with a fixed
 *  version) is opened from the Overview's first checks, so it matches that
 *  count exactly; its chip shows only while it is the active view. */
export const LINKABLE_VULN_VIEWS: readonly VulnView[] = [...VULN_VIEWS, "fixable-severe"];
export const DEFAULT_VULN_VIEW: VulnView = "all";
export const DEFAULT_VULN_LAYOUT: VulnLayout = "list";

const PRESETS: Record<VulnView, (v: VulnItem) => boolean> = {
  all: () => true,
  // A fixed version is published. The installed one is still affected until
  // the reader upgrades, which is why the label says "available".
  fixable: (v) => Boolean(v.fixed),
  // No fixed version is published yet: the reader can only mitigate or wait.
  unfixed: (v) => !v.fixed,
  exploited: (v) => Boolean(v.kev),
  "critical-high": (v) => v.severity === "CRITICAL" || v.severity === "HIGH",
  "fixable-severe": (v) => (v.severity === "CRITICAL" || v.severity === "HIGH") && Boolean(v.fixed),
};

export function applyVulnView(items: VulnItem[], view: VulnView): VulnItem[] {
  return view === "all" ? items : items.filter(PRESETS[view]);
}

/** How many rows each preset would show, for the chip labels. */
export function viewCounts(items: VulnItem[]): Record<VulnView, number> {
  const out = {} as Record<VulnView, number>;
  for (const view of LINKABLE_VULN_VIEWS) out[view] = items.filter(PRESETS[view]).length;
  return out;
}

export function vulnViewToQuery(view: VulnView, layout: VulnLayout): RouteQuery {
  const q: Record<string, string> = {};
  if (view !== DEFAULT_VULN_VIEW) q.view = view;
  if (layout !== DEFAULT_VULN_LAYOUT) q.group = layout;
  return q;
}

export function vulnViewFromQuery(query: RouteQuery | undefined): {
  view: VulnView;
  layout: VulnLayout;
} {
  const q = query ?? {};
  return {
    view: LINKABLE_VULN_VIEWS.find((v) => v === q.view) ?? DEFAULT_VULN_VIEW,
    layout: q.group === "package" ? "package" : DEFAULT_VULN_LAYOUT,
  };
}
