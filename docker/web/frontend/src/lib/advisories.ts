// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Advisories with no CVE (the security summary's `advisoryCount` /
 * `advisories`): findings the vulnerability database filed under a
 * distribution advisory number (DLA-..., SUSE-SU-...) and for
 * which it names no CVE. They are listed apart from the findings and are not
 * part of the severity counts.
 */
import type { AdvisoryItem, SecuritySummary, Severity } from "./api";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export interface AdvisorySummary {
  /** Advisories listed; may exceed `rows.length` (the server caps rows). */
  count: number;
  rows: AdvisoryItem[];
  /** True when the list holds fewer rows than `count`. */
  truncated: boolean;
}

function normSeverity(s: unknown): Severity {
  return SEVERITIES.includes(s as Severity) ? (s as Severity) : "UNKNOWN";
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/** The advisories with no CVE of a security summary, or null when there are none. */
export function advisorySummary(security: SecuritySummary | null | undefined): AdvisorySummary | null {
  if (!security) return null;
  const rows = (Array.isArray(security.advisories) ? security.advisories : [])
    .filter((a) => a && typeof a.id === "string" && a.id)
    .map((a) => ({
      ...a,
      pkg: str(a.pkg),
      installed: str(a.installed),
      title: str(a.title),
      target: str(a.target),
      severity: normSeverity(a.severity),
    }));
  const declared = typeof security.advisoryCount === "number" ? security.advisoryCount : 0;
  const count = Math.max(declared, rows.length);
  if (count <= 0) return null;
  return { count, rows, truncated: rows.length < count };
}

/** Advisory numbers filed for a CVE, other than the CVE id itself. */
export function vulnAliases(v: { id: string; aliases?: unknown }): string[] {
  if (!Array.isArray(v.aliases)) return [];
  const out: string[] = [];
  for (const a of v.aliases) {
    if (typeof a === "string" && a && a !== v.id && !out.includes(a)) out.push(a);
  }
  return out;
}
