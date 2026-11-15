// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

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
  { id: "deepCve", labelKey: "run.stageDeepCve", match: /\[nvd-cpe\]/i },
  { id: "report", labelKey: "run.stageReport", match: /\[risk\]/i },
];

/** Index of the furthest stage reached (0 before any recognizable marker). */
export function scanStageIndex(logs: string[]): number {
  for (let i = SCAN_STAGES.length - 1; i >= 0; i--) {
    if (logs.some((line) => SCAN_STAGES[i].match.test(line))) return i;
  }
  return 0;
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

/** Whether any step's marker has appeared in the log yet. */
export function anyStageMarker(logs: string[]): boolean {
  return SCAN_STAGES.some((stage) => logs.some((line) => stage.match.test(line)));
}

export interface VisibleStage {
  stage: ScanStage;
  status: StageStatus;
}

/**
 * The steps this run has. Deep CVE matching is left out when the run did not
 * ask for it, since its marker never appears. `finished` marks every step done
 * (a scan that ended); a failed run passes false so the step it stopped on
 * stays the active one.
 */
export function visibleStages(logs: string[], finished: boolean, deepCve: boolean): VisibleStage[] {
  const statuses = stageStatuses(logs, finished);
  return SCAN_STAGES.map((stage, i) => ({ stage, status: statuses[i] })).filter(
    ({ stage }) => stage.id !== "deepCve" || deepCve,
  );
}

/**
 * Percent over the steps this run has, so a step it skips is not counted. The
 * active step counts as half done; no active step (finished) is 100.
 */
export function visiblePercent(visible: VisibleStage[]): number {
  const cur = visible.findIndex((v) => v.status === "active");
  if (cur < 0) return 100;
  return Math.round(((cur + 0.5) / visible.length) * 100);
}
