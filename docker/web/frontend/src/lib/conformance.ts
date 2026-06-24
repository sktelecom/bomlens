/**
 * Split and summarize conformance checks for the G7 section: base format checks
 * vs the G7 AI minimum-element checks (ids prefixed "g7-"), and the
 * "N/6 present · M advisory" tallies. Pure and unit tested — no invented
 * numbers, every count comes from the check statuses.
 */
import type { ConformanceCheck } from "./api";

export function isG7(check: ConformanceCheck): boolean {
  return check.id.startsWith("g7-");
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

export interface G7Tally {
  /** Checks whose element is present (status pass). */
  present: number;
  /** Total G7 checks (6 for an AIBOM, but computed, not hardcoded). */
  total: number;
  /** Not-present advisory checks (status warn). */
  advisory: number;
  /** Mandatory failures among G7 (G7 is advisory, so normally 0). */
  failed: number;
}

export function g7Tally(g7: ConformanceCheck[]): G7Tally {
  return {
    present: g7.filter((c) => c.status === "pass").length,
    total: g7.length,
    advisory: g7.filter((c) => c.status === "warn").length,
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
