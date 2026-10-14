// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Components no vulnerability check could reach (the security summary's
 * `uncheckedCount` / `uncheckedComponents`): no version, or neither a purl nor
 * a CPE a check used. Zero findings says nothing about them, so a result with
 * these must not read as clean.
 */
import type { SecuritySummary, UncheckedComponent, UncheckedReason } from "./api";

export const UNCHECKED_REASONS: UncheckedReason[] = ["no-version", "no-identifier", "unknown"];

export interface UncheckedSummary {
  /** Components not checked; may exceed `rows.length` (the server caps rows). */
  count: number;
  rows: UncheckedComponent[];
  /** Rows per reason, only reasons that occur, in UNCHECKED_REASONS order. */
  byReason: { reason: UncheckedReason; count: number }[];
  /** True when the list holds fewer rows than `count`. */
  truncated: boolean;
}

function normReason(r: unknown): UncheckedReason {
  return r === "no-version" || r === "no-identifier" ? r : "unknown";
}

/** The unchecked components of a security summary, or null when there are none. */
export function uncheckedSummary(security: SecuritySummary | null | undefined): UncheckedSummary | null {
  if (!security) return null;
  const rows = (Array.isArray(security.uncheckedComponents) ? security.uncheckedComponents : [])
    .filter((c) => c && typeof c.name === "string" && c.name)
    .map((c) => ({ ...c, version: typeof c.version === "string" ? c.version : "", reason: normReason(c.reason) }));
  const declared = typeof security.uncheckedCount === "number" ? security.uncheckedCount : 0;
  const count = Math.max(declared, rows.length);
  if (count <= 0) return null;
  const byReason = UNCHECKED_REASONS.map((reason) => ({
    reason,
    count: rows.filter((r) => r.reason === reason).length,
  })).filter((b) => b.count > 0);
  return { count, rows, byReason, truncated: rows.length < count };
}

/** i18n key for a reason code. */
export function uncheckedReasonKey(reason: UncheckedReason): string {
  return reason === "no-version"
    ? "result.uncheckedReason.noVersion"
    : reason === "no-identifier"
      ? "result.uncheckedReason.noIdentifier"
      : "result.uncheckedReason.unknown";
}
