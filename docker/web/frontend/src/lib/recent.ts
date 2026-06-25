/**
 * Pure helpers for the Recent scans home screen — kept free of React/i18n so
 * the aggregation and time formatting stay unit-testable in isolation (same
 * pattern as nav.ts / overview.ts). The component supplies `now` and `locale`.
 *
 * Honesty note: the only scan-type signal `/scans` carries is `isAiScan`
 * (a machine-learning-model component). Source/Image/Firmware are NOT
 * distinguishable from the SBOM alone, so we expose just AI vs generic SBOM —
 * we never invent a finer type. See the plan's data-honesty constraint.
 */
import type { RecentScan } from "./api";

export interface RecentSummary {
  /** Total stored scans. */
  total: number;
  /** Scans whose top severity is CRITICAL or HIGH. */
  atRisk: number;
  /** Scans that are AI-model SBOMs. */
  ai: number;
}

/** Aggregate the Recent list into the summary-strip counts (real data only). */
export function summarizeRecent(scans: RecentScan[]): RecentSummary {
  return {
    total: scans.length,
    atRisk: scans.filter(
      (s) => s.maxSeverity === "CRITICAL" || s.maxSeverity === "HIGH",
    ).length,
    ai: scans.filter((s) => s.isAiScan).length,
  };
}

/**
 * i18n key for a scan's Type badge. AI scans (ML-model component) win; otherwise
 * we map the CycloneDX root component.type the SBOM declared — an honest signal,
 * not an invented one. Unknown/absent types fall back to a generic "SBOM".
 */
export function scanTypeLabelKey(scan: RecentScan): string {
  if (scan.isAiScan) return "recent.typeAi";
  switch (scan.componentType) {
    case "firmware":
      return "recent.typeFirmware";
    case "container":
      return "recent.typeContainer";
    case "operating-system":
      return "recent.typeRootfs";
    case "application":
    case "library":
    case "framework":
      return "recent.typeSource";
    default:
      return "recent.typeSbom";
  }
}

/**
 * Human "2 hours ago" / "yesterday" / "just now" for a unix-seconds timestamp.
 * `nowMs` is injected (Date.now() in the caller) so the result is deterministic
 * under test. Uses Intl.RelativeTimeFormat, so it localizes for free.
 */
export function formatRelativeTime(
  unixSec: number,
  nowMs: number,
  locale: string,
): string {
  const diffSec = Math.round(unixSec - nowMs / 1000); // negative = past
  const abs = Math.abs(diffSec);
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  if (abs < 45) return rtf.format(0, "second");
  if (abs < 3600) return rtf.format(Math.round(diffSec / 60), "minute");
  if (abs < 86_400) return rtf.format(Math.round(diffSec / 3600), "hour");
  if (abs < 86_400 * 30) return rtf.format(Math.round(diffSec / 86_400), "day");
  if (abs < 86_400 * 365)
    return rtf.format(Math.round(diffSec / (86_400 * 30)), "month");
  return rtf.format(Math.round(diffSec / (86_400 * 365)), "year");
}
