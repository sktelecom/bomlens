// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The Vulnerabilities table's two optional columns, EPSS and the NVD rating,
 * and when each is on. A column with no value anywhere is never offered. The
 * reader's choice in the View menu wins; without one, a column is on as soon
 * as any row has a value (a narrow window scrolls the table sideways instead of
 * dropping a column). A sort in the URL that names a column turns it on too
 * (see the table).
 */
import type { VulnItem } from "./api";
import type { ViewStore } from "./tableView";
import { defaultStore } from "./tableView";

export type VulnColumnId = "epss" | "nvd";
export type VulnColumnPref = Partial<Record<VulnColumnId, boolean>>;

/** localStorage key, namespaced like the components table's. */
export const VULN_COLUMNS_KEY = "sbom.vulns.columns";

export interface VulnColumnFacts {
  /** Rows with an EPSS score. */
  epssRows: number;
  /** Rows with an NVD rating. */
  nvdRows: number;
  rows: number;
}

export function columnFacts(items: readonly VulnItem[]): VulnColumnFacts {
  let epssRows = 0;
  let nvdRows = 0;
  for (const v of items) {
    if (typeof v.epss === "number") epssRows += 1;
    if (v.nvdSeverity) nvdRows += 1;
  }
  return { epssRows, nvdRows, rows: items.length };
}

export function columnOn(id: VulnColumnId, f: VulnColumnFacts, pref: VulnColumnPref): boolean {
  const rows = id === "epss" ? f.epssRows : f.nvdRows;
  return rows > 0 && (pref[id] ?? true);
}

export function parseColumnPref(raw: string | null): VulnColumnPref {
  try {
    const o = raw ? JSON.parse(raw) : null;
    if (!o || typeof o !== "object") return {};
    const out: VulnColumnPref = {};
    if (typeof o.epss === "boolean") out.epss = o.epss;
    if (typeof o.nvd === "boolean") out.nvd = o.nvd;
    return out;
  } catch {
    return {};
  }
}

export function readColumnPref(store: ViewStore | null = defaultStore()): VulnColumnPref {
  try {
    return parseColumnPref(store?.getItem(VULN_COLUMNS_KEY) ?? null);
  } catch {
    return {};
  }
}

export function writeColumnPref(pref: VulnColumnPref, store: ViewStore | null = defaultStore()): void {
  try {
    store?.setItem(VULN_COLUMNS_KEY, JSON.stringify(pref));
  } catch {
    // Storage full or blocked: the choice lasts for this visit only.
  }
}
