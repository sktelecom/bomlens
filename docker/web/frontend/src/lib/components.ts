// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Pure filter/sort logic for the Components table. Kept out of the component so
 * the decision-first behaviour (risk ordering, "has vulns"/"direct only"/"needs
 * review" filters) is unit tested independently of rendering.
 */
import type { ComponentItem, Severity } from "./api";
import { licenseNeedsDecision } from "./licenses";

export interface ComponentFilters {
  query: string;
  type: string;
  license: string;
  /** Only components with at least one vulnerability. */
  hasVulns: boolean;
  /** Only direct dependencies of the root. */
  directOnly: boolean;
  /** Only components flagged for review (vendored / copied-in open source). */
  needsReview: boolean;
  /** Only components past their upstream end-of-life (eol === "true"). */
  eolOnly: boolean;
  /** Only components behind the latest patch in their cycle (outdated === "true").
   *  Distinct from eolOnly: an outdated component is still supported. */
  outdatedOnly: boolean;
  /** Only components whose licence a person still has to decide: none declared,
   *  or a name that is not an identifier we can place. */
  licenseUnclear: boolean;
}

export const EMPTY_FILTERS: ComponentFilters = {
  query: "",
  type: "",
  license: "",
  hasVulns: false,
  directOnly: false,
  needsReview: false,
  eolOnly: false,
  outdatedOnly: false,
  licenseUnclear: false,
};

export type ComponentSortKey = "name" | "version" | "type" | "scope" | "risk";
export type SortDir = "asc" | "desc";

const SEV_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  UNKNOWN: 1,
};

/** Sortable risk weight: worst severity, 0 when the component has no vulns. */
export function riskRank(c: ComponentItem): number {
  return c.maxSeverity ? SEV_RANK[c.maxSeverity] : 0;
}

/** Direct (2) ranks above transitive (1) above unknown/absent (0). */
function scopeRank(c: ComponentItem): number {
  if (c.scope === "direct") return 2;
  if (c.scope === "transitive") return 1;
  return 0;
}

function nameOf(c: ComponentItem): string {
  return `${c.group} ${c.name}`.trim();
}

/** Whether a component passes every active filter. */
export function matchesFilters(c: ComponentItem, f: ComponentFilters): boolean {
  const needle = f.query.trim().toLowerCase();
  if (
    needle &&
    !`${c.name} ${c.group} ${c.version} ${c.type} ${c.licenses.join(" ")}`
      .toLowerCase()
      .includes(needle)
  ) {
    return false;
  }
  if (f.type && c.type !== f.type) return false;
  if (f.license && !c.licenses.includes(f.license)) return false;
  if (f.hasVulns && !(c.vulnCount && c.vulnCount > 0)) return false;
  if (f.directOnly && c.scope !== "direct") return false;
  if (f.needsReview && !c.vendored) return false;
  if (f.eolOnly && c.eol !== "true") return false;
  if (f.outdatedOnly && c.outdated !== "true") return false;
  if (f.licenseUnclear && !licenseNeedsDecision(c.licenses)) return false;
  return true;
}

/** True when any filter would actually narrow the set (drives reset affordances). */
export function hasActiveFilters(f: ComponentFilters): boolean {
  return Boolean(
    f.query ||
      f.type ||
      f.license ||
      f.hasVulns ||
      f.directOnly ||
      f.needsReview ||
      f.eolOnly ||
      f.outdatedOnly ||
      f.licenseUnclear,
  );
}

function localeCompare(a: string, b: string): number {
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
}

/** Compare two components by the active sort key/direction (stable tiebreaks). */
export function compareComponents(
  a: ComponentItem,
  b: ComponentItem,
  key: ComponentSortKey,
  dir: SortDir,
): number {
  const factor = dir === "asc" ? 1 : -1;

  // Tiebreaks always sort by name ascending (stable, direction-independent).
  if (key === "risk") {
    const d = riskRank(a) - riskRank(b);
    if (d !== 0) return factor * d;
    const c = (a.vulnCount ?? 0) - (b.vulnCount ?? 0);
    if (c !== 0) return factor * c;
    return localeCompare(nameOf(a), nameOf(b));
  }

  if (key === "scope") {
    const d = scopeRank(a) - scopeRank(b);
    if (d !== 0) return factor * d;
    return localeCompare(nameOf(a), nameOf(b));
  }

  const av = key === "name" ? nameOf(a) : a[key] || "";
  const bv = key === "name" ? nameOf(b) : b[key] || "";
  return factor * localeCompare(av, bv);
}

/** Apply filters then sort. Operates on the full set (rendering caps separately). */
export function selectComponents(
  items: ComponentItem[],
  filters: ComponentFilters,
  sort: { key: ComponentSortKey; dir: SortDir } | null,
): ComponentItem[] {
  const rows = items.filter((c) => matchesFilters(c, filters));
  if (!sort) return rows;
  return [...rows].sort((a, b) => compareComponents(a, b, sort.key, sort.dir));
}

/**
 * How many license badges a row shows before the rest collapse into a "+n".
 * A row with a dozen licenses used to wrap its badges over three lines, which
 * made the row taller than its neighbours and cost the table its rhythm. The
 * expanded row still lists every license, so nothing is hidden from the reader.
 */
export const LICENSE_BADGE_LIMIT = 2;

export interface LicenseBadges {
  /** The licenses to render as badges, in the order given. */
  shown: string[];
  /** How many were left out; 0 when they all fit. */
  hidden: number;
}

/** Split a row's licenses into the badges it shows and the count it folds away. */
export function licenseBadges(
  licenses: string[],
  limit: number = LICENSE_BADGE_LIMIT,
): LicenseBadges {
  // A limit below 1 would fold everything away and leave the cell reading "+n"
  // with nothing to anchor it, so keep at least one badge visible.
  const cap = Math.max(1, limit);
  if (licenses.length <= cap) return { shown: licenses, hidden: 0 };
  return { shown: licenses.slice(0, cap), hidden: licenses.length - cap };
}
