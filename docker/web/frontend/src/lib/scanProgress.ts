/**
 * Derive the scan's current stage from its live log lines. The pipeline emits
 * recognizable markers in order ([1/2] generate → [normalize] → [notice] →
 * [security] → [risk]); the furthest marker seen is the current stage. Honest
 * and monotonic — stages only ever light up once their marker actually appears,
 * and a skipped stage (option off) is treated as passed once a later one runs.
 */
export interface ScanStage {
  id: string;
  labelKey: string;
  match: RegExp;
}

export const SCAN_STAGES: ScanStage[] = [
  { id: "generate", labelKey: "run.stageGenerate", match: /\[1\/2\]|cdxgen|\bsyft\b|aibom|generating sbom|merging/i },
  { id: "normalize", labelKey: "run.stageNormalize", match: /\[normalize\]/i },
  { id: "notice", labelKey: "run.stageNotice", match: /\[notice\]/i },
  { id: "security", labelKey: "run.stageSecurity", match: /\[security\]/i },
  { id: "report", labelKey: "run.stageReport", match: /\[risk\]/i },
];

/** Index of the furthest stage reached (0 before any recognizable marker). */
export function scanStageIndex(logs: string[]): number {
  for (let i = SCAN_STAGES.length - 1; i >= 0; i--) {
    if (logs.some((line) => SCAN_STAGES[i].match.test(line))) return i;
  }
  return 0;
}

/**
 * A monotonic, honest percent (0–100) from the furthest pipeline stage reached.
 * The active stage counts as half done, so the bar advances with real progress
 * and never claims completion before the scan's done event. Replaces the old
 * log-volume guess; the caller snaps to 100 once the scan finishes.
 */
export function stageProgress(logs: string[]): number {
  return Math.round(((scanStageIndex(logs) + 0.5) / SCAN_STAGES.length) * 100);
}

export type StageStatus = "done" | "active" | "pending";

/** Per-stage status for the given logs and run state. */
export function stageStatuses(logs: string[], finished: boolean): StageStatus[] {
  if (finished) return SCAN_STAGES.map(() => "done");
  const current = scanStageIndex(logs);
  return SCAN_STAGES.map((_, i) =>
    i < current ? "done" : i === current ? "active" : "pending",
  );
}
