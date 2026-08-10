// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Split and summarize conformance checks: the format and submission checks this
 * pipeline writes itself, and the baselines that arrive from a registry — the
 * 2026 SBOM minimum elements ("cisa-") and the G7 AI minimum elements ("g7-").
 * Per-cluster grouping, coverage tallies, and the ordering the panel reads.
 * Pure and unit tested — every count comes from the check statuses and sources,
 * none is invented.
 */
import type { AiProfile, ConformanceCheck } from "./api";

export function isG7(check: ConformanceCheck): boolean {
  return check.id.startsWith("g7-");
}

/** The 2026 SBOM minimum elements. Measured on every SBOM, all advisory. */
export function isCisa(check: ConformanceCheck): boolean {
  return check.id.startsWith("cisa-");
}

/** Does this check come from a registry rather than from the scripts themselves?
 *  Registry checks carry a cluster and a data source, which is what lets a row
 *  show which group it belongs to and how it was satisfied. */
export function isRegistryCheck(check: ConformanceCheck): boolean {
  return isG7(check) || isCisa(check);
}

/** Cluster order for the 2026 minimum elements (mirrors cisa-registry.json). */
export const CISA_CLUSTER_ORDER = [
  "cisa-metadata",
  "cisa-component",
  "cisa-practices",
] as const;

/** Canonical cluster order for the G7 sub-groups (mirrors g7-registry.json). */
export const G7_CLUSTER_ORDER = [
  "metadata",
  "slp",
  "models",
  "dp",
  "infrastructure",
  "sp",
  "kpi",
] as const;

export type G7Cluster = (typeof G7_CLUSTER_ORDER)[number];

/** The cluster a check belongs to; base format checks (empty cluster) are "base". */
export function clusterOf(check: ConformanceCheck): string {
  return check.cluster && check.cluster.length > 0 ? check.cluster : "base";
}

export interface SplitChecks {
  /** Format and submission checks — the ones that decide pass or fail. */
  base: ConformanceCheck[];
  /** 2026 SBOM minimum elements. Advisory; measured on every SBOM. */
  cisa: ConformanceCheck[];
  /** G7 AI minimum elements. Advisory; only when the SBOM carries a model. */
  g7: ConformanceCheck[];
}

/** Partition checks by which baseline they come from. Splitting only `g7-` off
 *  left the CISA elements in with the format checks, where they read as more of
 *  the same list while answering an entirely different question. */
export function splitChecks(checks: ConformanceCheck[]): SplitChecks {
  return {
    base: checks.filter((c) => !isRegistryCheck(c)),
    cisa: checks.filter(isCisa),
    g7: checks.filter(isG7),
  };
}

/** Sort order for a list a reader scans for work: what failed, then what is
 *  short, then what a person has to look at, then what is already met. Stable
 *  within each band, so the registry's own order survives inside a status. */
const STATUS_RANK: Record<string, number> = { fail: 0, warn: 1, pass: 3 };

export function sortByAttention(checks: ConformanceCheck[]): ConformanceCheck[] {
  return checks
    .map((c, i) => ({ c, i }))
    .sort((a, b) => {
      const rank = (c: ConformanceCheck) =>
        isNotApplicable(c) ? 3 : c.source === "na" ? 2 : (STATUS_RANK[c.status] ?? 1);
      const ra = rank(a.c);
      const rb = rank(b.c);
      return ra === rb ? a.i - b.i : ra - rb;
    })
    .map((x) => x.c);
}

/** Collapse repeated names in a missing list and say how many times each
 *  appeared. A firmware SBOM lists several components under one name, and the
 *  list used to repeat that name with nothing to tell the entries apart. */
export function dedupeMissing(missing: string[]): { name: string; count: number }[] {
  const seen = new Map<string, number>();
  for (const m of missing) seen.set(m, (seen.get(m) ?? 0) + 1);
  return [...seen].map(([name, count]) => ({ name, count }));
}

/** How many offenders the detail line says there are, when the list itself was
 *  capped. "14/31 component(s)" means 17 are missing; showing 50 of them without
 *  saying so reads as the whole story. Returns 0 when the detail carries no
 *  count or nothing was dropped. */
export function missingOverflow(check: ConformanceCheck): number {
  const m = /^(\d+)\/(\d+)\b/.exec(check.detail ?? "");
  if (!m) return 0;
  const total = Number(m[2]) - Number(m[1]);
  return Math.max(0, total - (check.missing?.length ?? 0));
}

export interface G7Group {
  cluster: string;
  checks: ConformanceCheck[];
}

/**
 * Group registry checks by cluster in the registry's own order. Clusters with no
 * checks are dropped; any unexpected cluster value is appended (in insertion
 * order) so nothing is silently lost.
 */
export function groupByCluster(
  checks: ConformanceCheck[],
  order: readonly string[],
): G7Group[] {
  const byCluster = new Map<string, ConformanceCheck[]>();
  for (const c of checks) {
    const key = clusterOf(c);
    const arr = byCluster.get(key);
    if (arr) arr.push(c);
    else byCluster.set(key, [c]);
  }
  const groups: G7Group[] = [];
  for (const cl of order) {
    const found = byCluster.get(cl);
    if (found && found.length > 0) {
      groups.push({ cluster: cl, checks: found });
      byCluster.delete(cl);
    }
  }
  for (const [cluster, group] of byCluster) groups.push({ cluster, checks: group });
  return groups;
}

export function groupG7ByCluster(g7: ConformanceCheck[]): G7Group[] {
  return groupByCluster(g7, G7_CLUSTER_ORDER);
}

/** A check the document gives nothing to judge: what it measures is absent here
 *  (no packages, no files, no parts to relate). Distinct from a review item,
 *  which has something to judge and no automated source for it. Neither counts as
 *  met; neither belongs in a coverage denominator, because counting one as a pass
 *  would rank a document that declares less above one that declares more and is
 *  measured on it. */
export function isNotApplicable(c: { naKind?: string }): boolean {
  return c.naKind === "not-applicable";
}

export interface G7Tally {
  /** Checks whose element is present (status pass). */
  present: number;
  /** Not-present advisory checks (status warn) that have an automated source. */
  advisory: number;
  /** Checks with no automated source (source "na") — need human review. */
  review: number;
  /** Total G7 checks (computed, never hardcoded). */
  total: number;
  /** Checks with nothing in this document to judge — outside the coverage base. */
  notApplicable: number;
  /** Checks with an automated source (total minus review and n/a) — the base. */
  autoTotal: number;
  /** Mandatory failures among G7 (G7 is advisory, so normally 0). */
  failed: number;
}

/** Coverage of one advisory baseline. Named for G7 because that is where it
 *  started; the shape is the same for any registry, so the 2026 elements use it
 *  too rather than growing a second set of numbers with the same meaning. */
export function registryTally(checks: ConformanceCheck[]): G7Tally {
  return g7Tally(checks);
}

/** The one line a reader needs before anything else: what actually blocks this
 *  SBOM, what is merely short, and what a person still has to look at. The
 *  verdict belongs to the mandatory checks alone — an advisory baseline can be
 *  entirely unmet without changing it. */
export interface VerdictTally {
  mandatoryFailed: number;
  mandatoryTotal: number;
  mandatoryPassed: number;
  advisoryGap: number;
  review: number;
  notApplicable: number;
}

export function verdictTally(checks: ConformanceCheck[]): VerdictTally {
  const mandatory = checks.filter((c) => c.required && !isNotApplicable(c));
  return {
    mandatoryFailed: mandatory.filter((c) => c.status === "fail").length,
    mandatoryTotal: mandatory.length,
    mandatoryPassed: mandatory.filter((c) => c.status === "pass").length,
    advisoryGap: checks.filter(
      (c) =>
        !c.required &&
        c.status !== "pass" &&
        c.source !== "na" &&
        !isNotApplicable(c),
    ).length,
    review: checks.filter((c) => c.source === "na" && !isNotApplicable(c))
      .length,
    notApplicable: checks.filter(isNotApplicable).length,
  };
}

export function g7Tally(g7: ConformanceCheck[]): G7Tally {
  const notApplicable = g7.filter(isNotApplicable).length;
  const review = g7.filter(
    (c) => c.source === "na" && !isNotApplicable(c),
  ).length;
  return {
    present: g7.filter((c) => c.status === "pass").length,
    advisory: g7.filter(
      (c) => c.status === "warn" && c.source !== "na" && !isNotApplicable(c),
    ).length,
    review,
    notApplicable,
    total: g7.length,
    autoTotal: g7.length - review - notApplicable,
    failed: g7.filter((c) => c.status === "fail").length,
  };
}

/** Base-check tally for the format conformance panel. */
export function baseTally(base: ConformanceCheck[]) {
  const applicable = base.filter((c) => !isNotApplicable(c));
  return {
    passed: applicable.filter((c) => c.status === "pass").length,
    total: applicable.length,
    failed: applicable.filter((c) => c.required && c.status === "fail").length,
    warnings: applicable.filter((c) => c.status === "warn").length,
    notApplicable: base.length - applicable.length,
  };
}

// ── Regulatory crosswalk ────────────────────────────────────────────────────

/** A framework carrying the four coverage counts (both crosswalk shapes have
 *  these; the detailed view adds `source` + `elements[]`, the card view doesn't). */
interface CoverageCounts {
  total: number;
  present: number;
  gap: number;
  review: number;
  /** Failing requirements, as the report states them. Optional so a report
   *  generated before this field existed still sums, reading as zero. */
  failed?: number;
}

export interface CrosswalkTotals {
  total: number;
  present: number;
  gap: number;
  review: number;
  /** Requirements the SBOM fails outright, as the report states them. */
  failed: number;
}

/** How a crosswalk element counts toward its framework coverage. Mirrors the
 *  backend framework tally (validate-sbom.sh): source "na" is a human-review
 *  item, a passing element is present, anything else is a documentation gap. */
export type CrosswalkCoverage = "present" | "gap" | "review";

export function elementCoverage(el: {
  status: string;
  source: string;
}): CrosswalkCoverage {
  if (el.source === "na") return "review";
  if (el.status === "pass") return "present";
  return "gap";
}

/**
 * Sum the coverage counts across crosswalk frameworks. Works for both the
 * detailed (`conformance.regulatoryCrosswalk`) and the card
 * (`aiProfile.regulatoryCrosswalk`) framework shapes — only the shared counts are
 * read. Every number comes from the frameworks; nothing is invented.
 */
export function crosswalkTotals(frameworks: CoverageCounts[]): CrosswalkTotals {
  return frameworks.reduce<CrosswalkTotals>(
    (acc, f) => ({
      total: acc.total + f.total,
      present: acc.present + f.present,
      gap: acc.gap + f.gap,
      review: acc.review + f.review,
      // Read, not derived. The remainder happens to be the failure count, and
      // calling it "advisory" showed the most serious category under the mildest
      // name there is. The report states it now.
      failed: acc.failed + (f.failed ?? 0),
    }),
    { total: 0, present: 0, gap: 0, review: 0, failed: 0 },
  );
}

// ── AI compliance profile card ──────────────────────────────────────────────

/** Derived, card-ready values for the AI compliance summary card. Pure so the
 *  card component stays presentational (and the derivation is unit tested). */
export interface ProfileCardModel {
  result: string;
  g7Present: number;
  g7Auto: number;
  g7Gap: number;
  g7Review: number;
  licenseTotal: number;
  licenseBehavioral: number;
  licenseNonCommercial: number;
  /** How many regulatory frameworks the crosswalk covers. */
  frameworkCount: number;
  /** Aggregate coverage across all crosswalk frameworks. */
  crosswalk: CrosswalkTotals;
}

export function profileCard(profile: AiProfile): ProfileCardModel {
  return {
    result: profile.conformanceResult,
    g7Present: profile.g7.present,
    g7Auto: profile.g7.auto,
    g7Gap: profile.g7.gap,
    g7Review: profile.g7.review,
    licenseTotal: profile.licenseReview.total,
    licenseBehavioral: profile.licenseReview.behavioral,
    licenseNonCommercial: profile.licenseReview.nonCommercial,
    frameworkCount: profile.regulatoryCrosswalk.frameworks.length,
    crosswalk: crosswalkTotals(profile.regulatoryCrosswalk.frameworks),
  };
}
