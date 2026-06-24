/**
 * Sorting for the Vulnerabilities table: by severity then CVSS, or by CVSS
 * then severity. Pure and unit tested so "most severe / highest-scored first"
 * is verifiable independently of the table.
 */
import { SEVERITY_ORDER, type VulnItem } from "./api";

export type VulnSortKey = "severity" | "cvss";
export type SortDir = "asc" | "desc";

/** Higher = more severe (CRITICAL highest). Unknown/absent severities sort last. */
function severityValue(v: VulnItem): number {
  const i = SEVERITY_ORDER.indexOf(v.severity);
  return i === -1 ? 0 : SEVERITY_ORDER.length - i;
}

/** CVSS as a comparable number; missing scores sort below any real score. */
function cvssValue(v: VulnItem): number {
  return typeof v.cvss === "number" ? v.cvss : -1;
}

/**
 * Compare two vulnerabilities by the active key/direction. The non-primary
 * metric is always a "highest first" tiebreak (direction-independent), then the
 * CVE id, so order is stable and intuitive within a severity band.
 */
export function compareVulns(
  a: VulnItem,
  b: VulnItem,
  key: VulnSortKey,
  dir: SortDir,
): number {
  const factor = dir === "asc" ? 1 : -1;

  const primary = key === "cvss" ? cvssValue(a) - cvssValue(b) : severityValue(a) - severityValue(b);
  if (primary !== 0) return factor * primary;

  const secondary =
    key === "cvss" ? severityValue(a) - severityValue(b) : cvssValue(a) - cvssValue(b);
  if (secondary !== 0) return -secondary; // higher first, regardless of direction

  return a.id.localeCompare(b.id);
}

/** Sort a copy by severity→CVSS (default) or the given key/direction. */
export function sortVulns(
  items: VulnItem[],
  sort: { key: VulnSortKey; dir: SortDir } = { key: "severity", dir: "desc" },
): VulnItem[] {
  return [...items].sort((a, b) => compareVulns(a, b, sort.key, sort.dir));
}
