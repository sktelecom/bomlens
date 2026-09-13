// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Sorting for the Vulnerabilities table: by severity then CVSS, or by CVSS
 * then severity. Pure and unit tested so "most severe / highest-scored first"
 * is verifiable independently of the table.
 */
import { SEVERITY_ORDER, type Severity, type VulnItem } from "./api";

export type VulnSortKey = "severity" | "cvss" | "epss" | "nvdSeverity";
export type SortDir = "asc" | "desc";

/** Higher = more severe (CRITICAL highest). Unknown/absent severities sort last. */
function severityRank(s: Severity | undefined): number {
  const i = s ? SEVERITY_ORDER.indexOf(s) : -1;
  return i === -1 ? 0 : SEVERITY_ORDER.length - i;
}

function severityValue(v: VulnItem): number {
  return severityRank(v.severity);
}

/** CVSS as a comparable number; missing scores sort below any real score. */
function cvssValue(v: VulnItem): number {
  return typeof v.cvss === "number" ? v.cvss : -1;
}

/** EPSS as a comparable number; missing scores sort below any real score. */
function epssValue(v: VulnItem): number {
  return typeof v.epss === "number" ? v.epss : -1;
}

/** Same scale as severityValue, but on NVD's own rating; absent sorts last. */
function nvdSeverityValue(v: VulnItem): number {
  if (!v.nvdSeverity) return -1;
  const i = SEVERITY_ORDER.indexOf(v.nvdSeverity);
  return i === -1 ? -1 : SEVERITY_ORDER.length - i;
}

function primaryValue(v: VulnItem, key: VulnSortKey): number {
  if (key === "cvss") return cvssValue(v);
  if (key === "epss") return epssValue(v);
  if (key === "nvdSeverity") return nvdSeverityValue(v);
  return severityValue(v);
}

/**
 * Compare two vulnerabilities by the active key/direction. The tiebreak is
 * always severity (highest first, direction-independent) then the CVE id, so
 * order is stable and intuitive within a band.
 */
export function compareVulns(
  a: VulnItem,
  b: VulnItem,
  key: VulnSortKey,
  dir: SortDir,
): number {
  const factor = dir === "asc" ? 1 : -1;

  const primary = primaryValue(a, key) - primaryValue(b, key);
  if (primary !== 0) return factor * primary;

  if (key !== "severity") {
    const sev = severityValue(a) - severityValue(b);
    if (sev !== 0) return -sev; // most severe first, regardless of direction
  } else {
    const cvss = cvssValue(a) - cvssValue(b);
    if (cvss !== 0) return -cvss;
  }

  return a.id.localeCompare(b.id);
}

/** Sort a copy by severity→CVSS (default) or the given key/direction. */
export function sortVulns(
  items: VulnItem[],
  sort: { key: VulnSortKey; dir: SortDir } = { key: "severity", dir: "desc" },
): VulnItem[] {
  return [...items].sort((a, b) => compareVulns(a, b, sort.key, sort.dir));
}

/** Two or more CVEs on the same installed package that share the same fixed
 *  version: one upgrade resolves all of them. */
export interface UpgradeGroup {
  pkg: string;
  installed: string;
  fixed: string;
  vulnIds: string[];
  /** Worst severity among the grouped CVEs (for sorting/highlighting). */
  maxSeverity: Severity;
}

/**
 * Group vulnerabilities that a single upgrade would resolve together.
 *
 * The key is package + installed version + fixed version, not package name
 * alone: the same name can resolve to two different installed versions in
 * one SBOM (a dependency conflict, qs@6.15.3 and qs@6.16.0 coexisting is a
 * real, measured case), and grouping by name only would silently merge CVEs
 * against unrelated installs. A CVE with no fixed version is not groupable
 * (there is nothing to upgrade to) and is dropped from every group; a group
 * of exactly one CVE is not a "bundle" and is dropped too: the summary
 * exists to answer "what fixes more than one thing at once".
 *
 * Sorted worst-severity-first, then by how many CVEs the upgrade resolves
 * (most first): the reader is choosing where to spend one upgrade, so the
 * biggest, most severe win should lead.
 */
export function groupByUpgrade(vulns: VulnItem[]): UpgradeGroup[] {
  const byKey = new Map<string, VulnItem[]>();
  for (const v of vulns) {
    if (!v.fixed) continue;
    const key = `${v.pkg}::${v.installed}::${v.fixed}`;
    const list = byKey.get(key);
    if (list) list.push(v);
    else byKey.set(key, [v]);
  }

  const groups: UpgradeGroup[] = [];
  for (const [key, list] of byKey) {
    if (list.length < 2) continue;
    const [pkg, installed, fixed] = key.split("::");
    let worst = list[0];
    for (const v of list) {
      if (severityValue(v) > severityValue(worst)) worst = v;
    }
    groups.push({ pkg, installed, fixed, vulnIds: list.map((v) => v.id), maxSeverity: worst.severity });
  }

  return groups.sort((a, b) => {
    const sev = severityRank(b.maxSeverity) - severityRank(a.maxSeverity);
    if (sev !== 0) return sev;
    return b.vulnIds.length - a.vulnIds.length;
  });
}
