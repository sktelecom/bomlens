/**
 * Split and summarize conformance checks for the G7 section: base format checks
 * vs the G7 AI minimum-element checks (ids prefixed "g7-"), the per-cluster
 * grouping (`cluster` field), and the coverage tallies. Pure and unit tested —
 * no invented numbers, every count comes from the check statuses/sources.
 */
import type { ConformanceCheck } from "./api";

export function isG7(check: ConformanceCheck): boolean {
  return check.id.startsWith("g7-");
}

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
  base: ConformanceCheck[];
  g7: ConformanceCheck[];
}

/** Partition checks into base format checks and G7 AI checks (rail order). */
export function splitChecks(checks: ConformanceCheck[]): SplitChecks {
  return {
    base: checks.filter((c) => !isG7(c)),
    g7: checks.filter(isG7),
  };
}

export interface G7Group {
  cluster: string;
  checks: ConformanceCheck[];
}

/**
 * Group the G7 checks by cluster in the canonical registry order. Clusters with
 * no checks are dropped; any unexpected cluster value is appended (in insertion
 * order) so nothing is silently lost.
 */
export function groupG7ByCluster(g7: ConformanceCheck[]): G7Group[] {
  const byCluster = new Map<string, ConformanceCheck[]>();
  for (const c of g7) {
    const key = clusterOf(c);
    const arr = byCluster.get(key);
    if (arr) arr.push(c);
    else byCluster.set(key, [c]);
  }
  const groups: G7Group[] = [];
  for (const cl of G7_CLUSTER_ORDER) {
    const checks = byCluster.get(cl);
    if (checks && checks.length > 0) {
      groups.push({ cluster: cl, checks });
      byCluster.delete(cl);
    }
  }
  for (const [cluster, checks] of byCluster) groups.push({ cluster, checks });
  return groups;
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
  /** Checks with an automated source (total minus review) — the coverage base. */
  autoTotal: number;
  /** Mandatory failures among G7 (G7 is advisory, so normally 0). */
  failed: number;
}

export function g7Tally(g7: ConformanceCheck[]): G7Tally {
  const review = g7.filter((c) => c.source === "na").length;
  return {
    present: g7.filter((c) => c.status === "pass").length,
    advisory: g7.filter((c) => c.status === "warn" && c.source !== "na").length,
    review,
    total: g7.length,
    autoTotal: g7.length - review,
    failed: g7.filter((c) => c.status === "fail").length,
  };
}

/** Base-check tally for the format conformance panel. */
export function baseTally(base: ConformanceCheck[]) {
  return {
    passed: base.filter((c) => c.status === "pass").length,
    total: base.length,
    failed: base.filter((c) => c.required && c.status === "fail").length,
    warnings: base.filter((c) => c.status === "warn").length,
  };
}
