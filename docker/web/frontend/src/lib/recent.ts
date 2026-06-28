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
import { type RecentScan, SEVERITY_ORDER } from "./api";

export interface RecentSummary {
  /** Total stored scans. */
  total: number;
  /** Scans whose top severity is CRITICAL or HIGH. */
  atRisk: number;
  /** Distinct projects across the stored scans (coverage breadth). */
  projects: number;
}

/** True when a scan's worst severity is CRITICAL or HIGH (the "at risk" set). */
export function isAtRisk(scan: RecentScan): boolean {
  return scan.maxSeverity === "CRITICAL" || scan.maxSeverity === "HIGH";
}

/** Aggregate the Recent list into the summary-strip counts (real data only). */
export function summarizeRecent(scans: RecentScan[]): RecentSummary {
  return {
    total: scans.length,
    atRisk: scans.filter(isAtRisk).length,
    projects: new Set(scans.map((s) => s.project)).size,
  };
}

export interface RecentFilter {
  /** Free text matched against project + version (case-insensitive). */
  query: string;
  /** Keep only this scan type, or "all" for no type filter. */
  type: ScanType | "all";
  /** Keep only scans whose top severity is CRITICAL or HIGH. */
  atRisk: boolean;
}

/**
 * Filter the Scan management list by free text (project/version), scan type, and
 * the at-risk toggle. Pure, so it's unit-tested alongside sort/summarize.
 */
export function filterRecent(
  scans: RecentScan[],
  { query, type, atRisk }: RecentFilter,
): RecentScan[] {
  const q = query.trim().toLowerCase();
  return scans.filter((s) => {
    if (q && !`${s.project} ${s.version ?? ""}`.toLowerCase().includes(q)) {
      return false;
    }
    if (type !== "all" && scanType(s) !== type) return false;
    if (atRisk && !isAtRisk(s)) return false;
    return true;
  });
}

/**
 * A scan's kind, derived only from honest SBOM signals: `isAiScan` (an
 * ML-model component) wins, otherwise the CycloneDX root component.type the SBOM
 * declared. Unknown/absent types fall back to a generic "sbom" — we never invent
 * a finer type than the data supports.
 */
export type ScanType = "ai" | "source" | "firmware" | "container" | "rootfs" | "sbom";

export function scanType(scan: RecentScan): ScanType {
  if (scan.isAiScan) return "ai";
  switch (scan.componentType) {
    case "firmware":
      return "firmware";
    case "container":
      return "container";
    case "operating-system":
      return "rootfs";
    case "application":
    case "library":
    case "framework":
      return "source";
    default:
      return "sbom";
  }
}

const TYPE_LABEL: Record<ScanType, string> = {
  ai: "recent.typeAi",
  source: "recent.typeSource",
  firmware: "recent.typeFirmware",
  container: "recent.typeContainer",
  rootfs: "recent.typeRootfs",
  sbom: "recent.typeSbom",
};

/** i18n key for a scan's Type badge — the single source the filter chips reuse. */
export function scanTypeLabelKey(scan: RecentScan): string {
  return TYPE_LABEL[scanType(scan)];
}

/** i18n key for a scan-type id (for the filter chips). */
export function scanTypeLabelKeyFor(type: ScanType): string {
  return TYPE_LABEL[type];
}

// Display order for the type filter; only types actually present are shown.
const TYPE_ORDER: ScanType[] = [
  "source",
  "container",
  "rootfs",
  "firmware",
  "ai",
  "sbom",
];

/** The distinct scan types present in the list, in display order. */
export function presentTypes(scans: RecentScan[]): ScanType[] {
  const set = new Set(scans.map(scanType));
  return TYPE_ORDER.filter((t) => set.has(t));
}

export interface ScanComparison {
  /** The previous scan of the same project this one is compared against. */
  prev: RecentScan;
  /** current.components − prev.components (positive = grew). */
  componentsDelta: number;
  /** Whether the worst severity rose, fell, or held vs the previous scan. */
  severityDir: "up" | "down" | "same";
}

export type RecentSortKey = "scan" | "generated" | "components" | "severity";
export type RecentSortDir = "asc" | "desc";

/**
 * Sort the Recent list by a column. Pure and stable: the chosen key drives the
 * primary order (direction-aware), with most-recent-first as the tiebreak so
 * equal rows keep a sensible order. The default view is generated/desc.
 */
export function sortRecent(
  scans: RecentScan[],
  key: RecentSortKey,
  dir: RecentSortDir,
): RecentScan[] {
  const factor = dir === "asc" ? 1 : -1;
  const primary = (a: RecentScan, b: RecentScan): number => {
    switch (key) {
      case "scan":
        return (
          a.project.localeCompare(b.project) ||
          (a.version || "").localeCompare(b.version || "")
        );
      case "components":
        return a.components - b.components;
      case "severity":
        return severityRank(a.maxSeverity) - severityRank(b.maxSeverity);
      default:
        return a.generatedAt - b.generatedAt;
    }
  };
  return [...scans].sort(
    (a, b) => factor * primary(a, b) || b.generatedAt - a.generatedAt,
  );
}

/** Worst-severity rank, higher = more severe; null/none = 0. */
function severityRank(s: RecentScan["maxSeverity"]): number {
  if (!s) return 0;
  const i = SEVERITY_ORDER.indexOf(s);
  // SEVERITY_ORDER is most-severe-first, so invert to make higher = worse.
  return i < 0 ? 0 : SEVERITY_ORDER.length - i;
}

/**
 * Compare a scan to the most recent earlier scan of the same project. Local and
 * summary-only (component count + worst severity from the Recent list) — no full
 * SBOM is loaded, in keeping with the no-server-state, single-run identity.
 * Returns null when the scan isn't in the list or has no prior run to compare.
 */
export function scanComparison(
  recent: RecentScan[],
  currentId: string,
): ScanComparison | null {
  const current = recent.find((s) => s.id === currentId);
  if (!current) return null;
  const prev = recent
    .filter(
      (s) =>
        s.id !== currentId &&
        s.project === current.project &&
        s.generatedAt < current.generatedAt,
    )
    .sort((a, b) => b.generatedAt - a.generatedAt)[0];
  if (!prev) return null;
  const dr = severityRank(current.maxSeverity) - severityRank(prev.maxSeverity);
  return {
    prev,
    componentsDelta: current.components - prev.components,
    severityDir: dr > 0 ? "up" : dr < 0 ? "down" : "same",
  };
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
