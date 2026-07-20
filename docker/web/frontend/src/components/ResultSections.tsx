import { useTranslation } from "react-i18next";

import { EmptyState } from "@/components/ui/state";
import type { DoneEvent, RecentScan, ResultFile, Severity } from "@/lib/api";
import type { LicenseRiskTier } from "@/lib/licenses";
import type { SectionId } from "@/lib/nav";
import { sbomFileName, scancodeFileName, sourceTreeFileName } from "@/lib/results";

import { ArtifactsSection, Overview } from "./Overview";
import { ComponentsTable } from "./ComponentsTable";
import { ConformancePanel } from "./ConformancePanel";
import { DependenciesPanel } from "./DependenciesPanel";
import { Licenses } from "./Licenses";
import { ModelsDatasets } from "./ModelsDatasets";
import { SourceTreePanel } from "./SourceTreePanel";
import { VulnerabilitiesTable } from "./VulnerabilitiesTable";

/**
 * Renders one result section's content inside the shell canvas. The detail
 * components are the same ones the classic dashboard used; the Overview is the
 * decision-first landing (needs-attention + summaries + jump cards).
 */
export function ResultSection({
  section,
  result,
  scanId,
  recent,
  searchQuery,
  seedSeverity,
  seedTier,
  onPick,
  onResultsChange,
}: {
  section: SectionId;
  result: DoneEvent;
  /** The scan's id, so Overview can link into sections via `#/scan/<id>/…`. */
  scanId: string | null;
  /** Local Recent-scans list, for the Overview "vs previous scan" line. */
  recent?: RecentScan[];
  /** Term seeded from global search into this section's table search. */
  searchQuery?: string;
  /** Severity seeded into the Vulnerabilities filter (Overview bar click). */
  seedSeverity?: string;
  /** License tier seeded into the Licenses filter (Overview bar click). */
  seedTier?: LicenseRiskTier | "";
  /** Route into a section with a filter pre-applied (the Overview risk bars). */
  onPick?: (
    section: SectionId,
    seed: { severity?: Severity; tier?: LicenseRiskTier },
  ) => void;
  /** An artifact was produced after the scan (the on-demand SPDX export), so
   *  the owner can refresh the result it holds. */
  onResultsChange?: (files: ResultFile[]) => void;
}) {
  const { t } = useTranslation();

  switch (section) {
    case "overview":
      return (
        <Overview result={result} scanId={scanId} recent={recent} onPick={onPick} />
      );

    case "components":
      return (
        <ComponentsTable
          items={result.sbom?.componentList ?? []}
          total={result.sbom?.components ?? 0}
          truncated={result.sbom?.truncated}
          initialQuery={searchQuery}
        />
      );

    case "vulnerabilities":
      return result.security ? (
        <VulnerabilitiesTable
          security={result.security}
          initialQuery={searchQuery}
          initialSeverity={seedSeverity}
        />
      ) : (
        <EmptyState>{t("result.noSecurity")}</EmptyState>
      );

    case "licenses":
      return (
        <Licenses
          components={result.sbom?.componentList ?? []}
          initialTier={seedTier}
        />
      );

    case "dependencies": {
      const sbomFile = sbomFileName(result);
      return sbomFile ? (
        <DependenciesPanel
          scanId={scanId}
          sbomFile={sbomFile}
          components={result.sbom?.componentList ?? []}
        />
      ) : null;
    }

    case "sourceTree": {
      const sourceFile = sourceTreeFileName(result);
      if (!sourceFile) return null;
      // ScanCode output carries per-file licenses; the structure-only
      // `_files.json` fallback does not, so hint that licenses need ScanCode.
      const hasLicenses = Boolean(scancodeFileName(result));
      return (
        <SourceTreePanel
          scanId={scanId}
          sourceFile={sourceFile}
          hasLicenses={hasLicenses}
        />
      );
    }

    case "artifacts":
      return (
        <ArtifactsSection
          result={result}
          scanId={scanId}
          onResultsChange={onResultsChange}
        />
      );

    case "models": {
      const sbomFile = sbomFileName(result);
      return sbomFile ? (
        <ModelsDatasets scanId={scanId} sbomFile={sbomFile} />
      ) : null;
    }

    case "conformance":
      return result.conformance ? (
        <ConformancePanel
          conformance={result.conformance}
          aiProfile={result.aiProfile ?? null}
        />
      ) : null;

    default:
      return null;
  }
}
