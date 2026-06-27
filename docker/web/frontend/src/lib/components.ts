/**
 * Pure filter/sort logic for the Components table. Kept out of the component so
 * the decision-first behaviour (risk ordering, "has vulns"/"direct only"/"needs
 * review" filters) is unit tested independently of rendering.
 */
import type { ComponentItem, Severity } from "./api";

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
}

export const EMPTY_FILTERS: ComponentFilters = {
  query: "",
  type: "",
  license: "",
  hasVulns: false,
  directOnly: false,
  needsReview: false,
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
  return true;
}

/** True when any filter would actually narrow the set (drives reset affordances). */
export function hasActiveFilters(f: ComponentFilters): boolean {
  return Boolean(
    f.query || f.type || f.license || f.hasVulns || f.directOnly || f.needsReview,
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

export interface TypeGroup {
  /** CycloneDX component type (library/application/framework/…). */
  type: string;
  count: number;
}

/**
 * Component-type distribution, busiest type first. Mirrors licenseGroups: a
 * plain count per CycloneDX `type`, skipping components with no declared type.
 * Low signal for single-ecosystem SBOMs (often all "library") but informative
 * where the type split is real (e.g. Maven's library vs framework), so callers
 * gate on `length >= 2` before showing it.
 */
export function typeGroups(components: ComponentItem[]): TypeGroup[] {
  const counts = new Map<string, number>();
  for (const c of components) {
    if (!c.type) continue;
    counts.set(c.type, (counts.get(c.type) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
}
