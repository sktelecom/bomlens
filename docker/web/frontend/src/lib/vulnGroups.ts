// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Package-level view of the Vulnerabilities table.
 *
 * Two questions the flat list cannot answer at a glance: "how bad is this one
 * package" and "which single upgrade clears the most". Both come from grouping
 * the rows by installed package and walking its fix versions in order.
 *
 * Fix versions are cumulative. Upgrading to 2.8.0 also passes 2.6.0, so every
 * CVE fixed at or before 2.8.0 is resolved by it. A package whose CVEs are
 * fixed at 2.6.0 (two of them) and 2.8.0 (two more, plus three fixed in
 * between) therefore reads "upgrade to 2.8.0 to resolve 7, or to 2.6.0 for 2".
 * Previously each fixed version was its own line, so the same package appeared
 * several times with counts that did not add up to what one upgrade does.
 */
import { SEVERITY_ORDER, type Severity, type VulnItem } from "./api";
import { compareVersions } from "./versionCompare";

/** One upgrade target of a package and what reaching it resolves. */
export interface FixStep {
  fixed: string;
  /** CVEs resolved by upgrading to this version, counting those fixed earlier. */
  count: number;
}

export interface PackageGroup {
  /** purl (or name) plus installed version: the same identity the upgrade
   *  grouping used, so two installs of one name never merge. */
  key: string;
  pkg: string;
  installed: string;
  vulns: VulnItem[];
  maxSeverity: Severity;
  /** At least one row is on CISA's actively exploited list. */
  kev: boolean;
  /** Upgrade targets, lowest first. Empty when no row has a fixed version. */
  steps: FixStep[];
  /** Rows with no fixed version: nothing to upgrade to yet. */
  unfixed: number;
}

function severityRank(s: Severity | undefined): number {
  const i = s ? SEVERITY_ORDER.indexOf(s) : -1;
  return i === -1 ? 0 : SEVERITY_ORDER.length - i;
}

/**
 * The version to upgrade to for one row. Trivy lists several fixed versions for
 * a package maintained on more than one branch ("1.2.9, 1.3.4"); the one that
 * matters is the nearest above the installed version. When none is above it
 * (or the installed version is unknown) the first listed one stands.
 */
export function effectiveFixed(v: Pick<VulnItem, "fixed" | "installed">): string {
  const listed = (v.fixed || "")
    .split(/[,;]/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (listed.length <= 1) return listed[0] ?? "";
  if (!v.installed) return listed[0];
  const above = listed
    .filter((c) => compareVersions(c, v.installed) > 0)
    .sort(compareVersions);
  return above[0] ?? listed[0];
}

/**
 * Group rows by installed package, in the order the packages first appear, so
 * a caller that sorts the rows first gets the groups in the same order.
 */
export function groupByPackage(vulns: VulnItem[]): PackageGroup[] {
  const byKey = new Map<string, VulnItem[]>();
  for (const v of vulns) {
    const key = `${v.purl || v.pkg}::${v.installed}`;
    const list = byKey.get(key);
    if (list) list.push(v);
    else byKey.set(key, [v]);
  }

  const groups: PackageGroup[] = [];
  for (const [key, list] of byKey) {
    const fixedBy = new Map<string, number>();
    let unfixed = 0;
    for (const v of list) {
      const f = effectiveFixed(v);
      if (!f) unfixed += 1;
      else fixedBy.set(f, (fixedBy.get(f) ?? 0) + 1);
    }
    const ordered = [...fixedBy.keys()].sort(compareVersions);
    let running = 0;
    const steps = ordered.map((fixed) => {
      running += fixedBy.get(fixed) ?? 0;
      return { fixed, count: running };
    });
    let worst = list[0];
    for (const v of list) if (severityRank(v.severity) > severityRank(worst.severity)) worst = v;
    groups.push({
      key,
      pkg: list[0].pkg,
      installed: list[0].installed,
      vulns: list,
      maxSeverity: worst.severity,
      kev: list.some((v) => v.kev),
      steps,
      unfixed,
    });
  }
  return groups;
}

/**
 * The packages worth calling out as "one upgrade, several CVEs": those whose
 * top upgrade target resolves two or more. Worst severity first, then the
 * biggest win.
 */
export function upgradeBundles(groups: PackageGroup[]): PackageGroup[] {
  return groups
    .filter((g) => g.steps.length > 0 && g.steps[g.steps.length - 1].count >= 2)
    .sort((a, b) => {
      const sev = severityRank(b.maxSeverity) - severityRank(a.maxSeverity);
      if (sev !== 0) return sev;
      return b.steps[b.steps.length - 1].count - a.steps[a.steps.length - 1].count;
    });
}

/** The target the summary leads with, and the lower ones it shows beside it
 *  (nearest first, at most `limit`). */
export function bundleSteps(
  g: PackageGroup,
  limit = 2,
): { top: FixStep; lower: FixStep[] } {
  const top = g.steps[g.steps.length - 1];
  const lower = g.steps.slice(0, -1).slice(-limit);
  return { top, lower };
}
