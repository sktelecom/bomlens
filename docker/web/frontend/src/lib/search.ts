// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Cross-section quick search over a finished scan: find a component (by name or
 * purl) or a vulnerability (by CVE id, package or title) from anywhere, without
 * first navigating to the right section. Pure and unit tested; the UI (TopBar
 * GlobalSearch) renders the results and routes the pick into the section.
 */
import type { ComponentItem, DoneEvent, VulnItem } from "./api";

export interface ScanSearchResults {
  components: ComponentItem[];
  vulns: VulnItem[];
  /** How many matched before the cap, so the UI can offer "show all". */
  componentTotal: number;
  vulnTotal: number;
}

/** Case-insensitive substring search, each kind capped (default 6). */
export function searchScan(
  result: DoneEvent,
  query: string,
  cap = 6,
): ScanSearchResults {
  const q = query.trim().toLowerCase();
  if (!q) return { components: [], vulns: [], componentTotal: 0, vulnTotal: 0 };

  const allComponents = (result.sbom?.componentList ?? []).filter(
    (c) => c.name.toLowerCase().includes(q) || (c.purl ?? "").toLowerCase().includes(q),
  );

  const allVulns = (result.security?.vulnerabilities ?? []).filter(
    (v) =>
      v.id.toLowerCase().includes(q) ||
      v.pkg.toLowerCase().includes(q) ||
      (v.title ?? "").toLowerCase().includes(q),
  );

  return {
    components: allComponents.slice(0, cap),
    vulns: allVulns.slice(0, cap),
    componentTotal: allComponents.length,
    vulnTotal: allVulns.length,
  };
}
