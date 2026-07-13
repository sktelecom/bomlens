/**
 * Derivations from a finished scan (DoneEvent) that the new shell needs:
 * which artifacts exist, the rail's scan context, and per-section counts.
 * Pure functions, unit tested — the rail's adaptation depends on them.
 */
import type { DoneEvent } from "./api";
import { baseTally, g7Tally, splitChecks } from "./conformance";
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

/** Build the rail's scan context from a result (null before any scan). */
export function deriveScanContext(result: DoneEvent | null): ScanContext {
  if (!result) return EMPTY_SCAN;
  return {
    mode: result.mode ?? null,
    isAiScan: isAiScan(result),
    hasDependencies: Boolean(sbomFileName(result)),
    hasSourceTree: Boolean(sourceTreeFileName(result)),
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
  return (result.sbom?.componentList ?? []).some(
    (c) => c.type === "machine-learning-model",
  );
}

/**
 * Conformance coverage as a `passed/total` string, mirroring the panel
 * headlines: G7 `present/autoTotal` when the scan has G7 AI checks, otherwise
 * the base format tally. Undefined when there is nothing to count, so both
 * the rail badge and the overview tile can simply omit it.
 */
export function conformanceCount(result: DoneEvent): string | undefined {
  const { base, g7 } = splitChecks(result.conformance?.checks ?? []);
  const g7t = g7Tally(g7);
  if (g7t.autoTotal > 0) return `${g7t.present}/${g7t.autoTotal}`;
  const baseT = baseTally(base);
  if (baseT.total > 0) return `${baseT.passed}/${baseT.total}`;
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
    dependencies: direct + transitive > 0 ? `${direct}/${transitive}` : undefined,
    vulnerabilities: result.security?.TOTAL ?? 0,
    conformance: conformanceCount(result),
    licenses: licenses.size > 0 ? licenses.size : undefined,
    artifacts: result.results.length,
    models: componentList.filter((c) => c.type === "machine-learning-model")
      .length,
  };
}
