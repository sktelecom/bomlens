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
}

/** Case-insensitive substring search, each kind capped (default 6). */
export function searchScan(
  result: DoneEvent,
  query: string,
  cap = 6,
): ScanSearchResults {
  const q = query.trim().toLowerCase();
  if (!q) return { components: [], vulns: [] };

  const components = (result.sbom?.componentList ?? [])
    .filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        (c.purl ?? "").toLowerCase().includes(q),
    )
    .slice(0, cap);

  const vulns = (result.security?.vulnerabilities ?? [])
    .filter(
      (v) =>
        v.id.toLowerCase().includes(q) ||
        v.pkg.toLowerCase().includes(q) ||
        (v.title ?? "").toLowerCase().includes(q),
    )
    .slice(0, cap);

  return { components, vulns };
}
