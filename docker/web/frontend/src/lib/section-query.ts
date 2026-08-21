// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Translation between a result section's filter/sort state and the URL query
 * that carries it (see `route.ts` for where that query sits in the hash).
 *
 * Pure and total in both directions: state → query → state returns the state
 * it started from, and an unknown or malformed query yields defaults rather
 * than throwing. A hand-edited or truncated link is a normal input here, not
 * an error — the view it names may no longer exist in the scan at all.
 *
 * State at its default is left out of the query entirely, so an unfiltered
 * section has a bare hash and only a view the user actually narrowed carries
 * one.
 */
import {
  EMPTY_FILTERS,
  type ComponentFilters,
  type ComponentSortKey,
  type SortDir,
} from "./components";
import { LICENSE_TIER_ORDER, type LicenseRiskTier } from "./licenses";
import type { RouteQuery } from "./route";
import type { VulnSortKey } from "./vulns";

export type ComponentSort = { key: ComponentSortKey; dir: SortDir } | null;
export type VulnSort = { key: VulnSortKey; dir: SortDir };

/** The Vulnerabilities table opens worst-first; that ordering needs no query. */
export const DEFAULT_VULN_SORT: VulnSort = { key: "severity", dir: "desc" };

const COMPONENT_SORT_KEYS: ComponentSortKey[] = ["name", "version", "type", "scope", "risk"];
const VULN_SORT_KEYS: VulnSortKey[] = ["severity", "cvss", "epss", "nvdSeverity"];

/** Boolean filters travel as `1`; absent means off. */
const COMPONENT_FLAGS = {
  vulns: "hasVulns",
  direct: "directOnly",
  review: "needsReview",
  eol: "eolOnly",
  outdated: "outdatedOnly",
} as const satisfies Record<string, keyof ComponentFilters>;

function dirOf(v: string | undefined, fallback: SortDir): SortDir {
  return v === "asc" || v === "desc" ? v : fallback;
}

export function componentsToQuery(filters: ComponentFilters, sort: ComponentSort): RouteQuery {
  const q: Record<string, string> = {};
  if (filters.query) q.q = filters.query;
  if (filters.type) q.type = filters.type;
  if (filters.license) q.license = filters.license;
  for (const [key, field] of Object.entries(COMPONENT_FLAGS)) {
    if (filters[field]) q[key] = "1";
  }
  if (sort) {
    q.sort = sort.key;
    q.dir = sort.dir;
  }
  return q;
}

export function componentsFromQuery(query: RouteQuery | undefined): {
  filters: ComponentFilters;
  sort: ComponentSort;
} {
  const q = query ?? {};
  const filters: ComponentFilters = {
    ...EMPTY_FILTERS,
    query: q.q ?? "",
    type: q.type ?? "",
    license: q.license ?? "",
  };
  for (const [key, field] of Object.entries(COMPONENT_FLAGS)) {
    filters[field] = q[key] === "1";
  }
  const key = COMPONENT_SORT_KEYS.find((k) => k === q.sort);
  return { filters, sort: key ? { key, dir: dirOf(q.dir, "asc") } : null };
}

export function vulnsToQuery(term: string, severity: string, sort: VulnSort): RouteQuery {
  const q: Record<string, string> = {};
  if (term) q.q = term;
  if (severity) q.severity = severity;
  if (sort.key !== DEFAULT_VULN_SORT.key || sort.dir !== DEFAULT_VULN_SORT.dir) {
    q.sort = sort.key;
    q.dir = sort.dir;
  }
  return q;
}

export function vulnsFromQuery(query: RouteQuery | undefined): {
  term: string;
  severity: string;
  sort: VulnSort;
} {
  const q = query ?? {};
  const key = VULN_SORT_KEYS.find((k) => k === q.sort);
  return {
    term: q.q ?? "",
    severity: q.severity ?? "",
    sort: key ? { key, dir: dirOf(q.dir, "desc") } : DEFAULT_VULN_SORT,
  };
}

export function licensesToQuery(tier: LicenseRiskTier | ""): RouteQuery {
  return tier ? { tier } : {};
}

export function licensesFromQuery(query: RouteQuery | undefined): {
  tier: LicenseRiskTier | "";
} {
  const found = LICENSE_TIER_ORDER.find((x) => x === query?.tier);
  return { tier: found ?? "" };
}
