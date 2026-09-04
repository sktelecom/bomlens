// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Derivations from a finished scan (DoneEvent) that the new shell needs:
 * which artifacts exist, the rail's scan context, and per-section counts.
 * Pure functions, unit tested — the rail's adaptation depends on them.
 */
import type { DoneEvent } from "./api";
import { verdictTally } from "./conformance";
import { EMPTY_SCAN, type ScanContext, type SectionId } from "./nav";

/** The generated CycloneDX SBOM artifact, if present (drives the graph view). */
export function sbomFileName(result: DoneEvent): string | undefined {
  return result.results.find((r) => r.name.endsWith("_bom.json"))?.name;
}

/** The ScanCode artifact, if present (carries per-file licenses). */
export function scancodeFileName(result: DoneEvent): string | undefined {
  return result.results.find((r) => r.name.includes("_scancode"))?.name;
}

/** The structure-only source file tree (`_files.json`), if present. */
export function sourceFilesFileName(result: DoneEvent): string | undefined {
  return result.results.find((r) => r.name.endsWith("_files.json"))?.name;
}

/**
 * The artifact that drives the source-tree view. Both ScanCode output and the
 * structure-only `_files.json` share the same shape (parseScanCode reads both);
 * ScanCode wins when present because it also carries per-file licenses.
 */
export function sourceTreeFileName(result: DoneEvent): string | undefined {
  return scancodeFileName(result) ?? sourceFilesFileName(result);
}

/**
 * The source snapshot (`_source.json`), if present: the file contents behind the
 * tree. Absent for scans with nothing readable on disk, and for scans run before
 * the scanner started capturing it — the tree renders either way.
 */
export function sourceSnapshotFileName(result: DoneEvent): string | undefined {
  return result.results.find((r) => r.name.endsWith("_source.json"))?.name;
}

/**
 * The supplier-SBOM header summary (`_input.json`), written by an ANALYZE scan
 * from the document as it arrived — before the conversion to CycloneDX that the
 * rest of the result describes.
 */
export function inputSbomFileName(result: DoneEvent): string | undefined {
  return result.results.find((r) => r.name.endsWith("_input.json"))?.name;
}

/** Build the rail's scan context from a result (null before any scan). */
export function deriveScanContext(result: DoneEvent | null): ScanContext {
  if (!result) return EMPTY_SCAN;
  return {
    mode: result.mode ?? null,
    isAiScan: isAiScan(result),
    hasDependencies: Boolean(sbomFileName(result)),
    hasSourceTree: Boolean(sourceTreeFileName(result)),
    hasInputSbom: Boolean(inputSbomFileName(result)),
    hasConformance: (result.conformance?.checks ?? []).length > 0,
  };
}

/**
 * An AI scan is one whose SBOM carries a machine-learning-model component —
 * the same signal validate-sbom.sh uses to add the G7 AI checks. Content-based,
 * since the web UI has no dedicated AI mode (AI SBOMs arrive via ANALYZE or a
 * generated AIBOM).
 */
export function isAiScan(result: DoneEvent): boolean {
  if ((result.sbom?.componentList ?? []).some((c) => c.type === "machine-learning-model")) {
    return true;
  }
  // A dataset scan carries no model at all: the published item is the document,
  // and `data` as a root type is what only that scan produces (every other mode
  // roots at application / firmware / container / operating-system). Without
  // this the AI section stays hidden on exactly the scan it exists for.
  return result.sbom?.componentType === "data";
}

/**
 * Conformance coverage as a `passed/total` string: the mandatory checks, which
 * are the ones that decide the verdict. Undefined when there is nothing to
 * count, so both the rail badge and the overview tile can simply omit it.
 *
 * It used to mean two different things depending on the scan. An AI scan showed
 * G7 coverage, everything else showed passes over every check advisory ones
 * included — so the same badge read "20/41" on one scan and "15/40" on another
 * while neither number said whether the SBOM was acceptable. The advisory
 * baselines have their own headlines inside the panel; the badge answers the
 * question a badge is asked.
 */
export function conformanceCount(result: DoneEvent): string | undefined {
  const checks = result.conformance?.checks ?? [];
  const v = verdictTally(checks);
  if (v.mandatoryTotal > 0) return `${v.mandatoryPassed}/${v.mandatoryTotal}`;
  return undefined;
}

/**
 * Counts shown as trailing rail badges (mirrors the classic tab counts). Most
 * are a single number; dependencies is a `direct/transitive` split, which is
 * more telling than the total (the total just mirrors the component count).
 */
export function sectionCounts(
  result: DoneEvent,
): Partial<Record<SectionId, number | string>> {
  const componentList = result.sbom?.componentList ?? [];
  // Dependency graph as a direct/transitive split. Omit when there's no graph
  // (flat firmware/image SBOMs) so the rail shows no misleading 0.
  const direct = result.sbom?.directCount ?? 0;
  const transitive = result.sbom?.transitiveCount ?? 0;
  // Distinct license ids — the rows the Licenses distribution leads with.
  const licenses = new Set<string>();
  for (const c of componentList) for (const l of c.licenses) licenses.add(l);
  return {
    components: result.sbom?.components ?? 0,
    // The split is what makes this badge worth more than the component count,
    // but only while there is something on both sides of it. An AI scan's root
    // model is not a dependency of itself, so every AI scan has a transitive
    // count of zero and "3/0" printed a zero that carried no information.
    dependencies:
      direct + transitive === 0
        ? undefined
        : transitive === 0
          ? `${direct}`
          : `${direct}/${transitive}`,
    // No security report means the scan never asked, which is not the same as
    // asking and finding nothing. Writing 0 claimed the second. The section
    // itself says so ("no report was generated"); the badge must not contradict
    // it before the reader gets there. Same rule the dependency badge uses.
    vulnerabilities: result.security ? result.security.TOTAL : undefined,
    conformance: conformanceCount(result),
    licenses: licenses.size > 0 ? licenses.size : undefined,
    artifacts: result.results.length,
    // The section is "Models & datasets" and shows both, so the badge counts
    // both. Counting only the models left a scan reading "1" beside a screen
    // holding one model and three datasets.
    models: componentList.filter(
      (c) => c.type === "machine-learning-model" || c.type === "data",
    ).length,
  };
}
