// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Go reachability (--reachability, govulncheck). The security summary lists
 * the findings judged not reachable in `notReachable` with their count in
 * `notReachableCount`, apart from the counted `vulnerabilities`, the same way
 * the generated security report does.
 */
import type { SecuritySummary, SourceType, VulnItem } from "./api";

export interface NotReachableSummary {
  /** Findings judged not reachable; may exceed `rows.length` (the server caps rows). */
  count: number;
  rows: VulnItem[];
  /** True when the list holds fewer rows than `count`. */
  truncated: boolean;
}

/** The not-reachable findings of a security summary, or null when there are none. */
export function notReachableSummary(
  security: SecuritySummary | null | undefined,
): NotReachableSummary | null {
  if (!security) return null;
  const rows = (Array.isArray(security.notReachable) ? security.notReachable : []).filter(
    (v) => v && typeof v.id === "string" && v.id,
  );
  const declared = typeof security.notReachableCount === "number" ? security.notReachableCount : 0;
  const count = Math.max(declared, rows.length);
  if (count <= 0) return null;
  return { count, rows, truncated: rows.length < count };
}

/** i18n key for a not_affected justification; an unknown word gets the generic label. */
export function reachabilityJustificationKey(justification: string | undefined): string {
  return justification === "code_not_present"
    ? "result.reachabilityJustification.codeNotPresent"
    : justification === "code_not_reachable"
      ? "result.reachabilityJustification.codeNotReachable"
      : "result.reachabilityJustification.other";
}

/** Whether the scan form offers Go reachability: govulncheck is in this image
 *  and the input is a source tree (SOURCE) or an uploaded executable (BINARY).
 *  `effectiveSource` is what the form submits (a picked folder scanned deep
 *  becomes "scan-target-src"). */
export function reachabilityOffered(
  source: SourceType,
  effectiveSource: SourceType,
  capable: boolean | undefined,
): boolean {
  if (!capable) return false;
  return (
    source === "current-dir" ||
    source === "git-url" ||
    source === "zip-upload" ||
    source === "package-upload" ||
    effectiveSource === "scan-target-src"
  );
}
