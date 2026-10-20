// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

import { EmptyState } from "@/components/ui/state";
import type { DoneEvent, RecentScan, ResultFile, Severity } from "@/lib/api";
import type { LicenseRiskTier } from "@/lib/licenses";
import type { SectionId } from "@/lib/nav";
import {
  inputSbomFileName,
  isAiScan,
  sbomFileName,
  scancodeFileName,
  sourceSnapshotFileName,
  sourceTreeFileName,
} from "@/lib/results";
import { scanHash, type RouteQuery } from "@/lib/route";

import { AiSummaryCard } from "./AiSummaryCard";
import { ArtifactsSection, Overview } from "./Overview";
import { ComponentsTable } from "./ComponentsTable";
import { ConformancePanel } from "./ConformancePanel";
import { DependenciesPanel } from "./DependenciesPanel";
import { InputSbomPanel } from "./InputSbomPanel";
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
  generatedAt,
  query,
  onQueryChange,
  onPick,
  onResultsChange,
  onResultPatch,
  onRescan,
  onRescanWithLicense,
}: {
  section: SectionId;
  result: DoneEvent;
  /** The scan's id, so Overview can link into sections via `#/scan/<id>/…`. */
  scanId: string | null;
  /** Local Recent-scans list, for the Overview "vs previous scan" line. */
  recent?: RecentScan[];
  /** Unix seconds when the scan was made, for the Overview's source and time lines. */
  generatedAt?: number;
  /** This section's filter and sort state, as carried in the URL hash. Arrives
   *  from a shared link, a reload, or a pick routed in from another section. */
  query?: RouteQuery;
  /** The section changed its own filters; the shell puts them in the URL. */
  onQueryChange?: (query: RouteQuery) => void;
  /** Route into a section with a filter pre-applied (the Overview risk bars, a
   *  Licenses distribution row, a component or package name from the table the
   *  user is reading). */
  onPick?: (
    section: SectionId,
    seed: {
      severity?: Severity;
      tier?: LicenseRiskTier;
      license?: string;
      term?: string;
      /** Paired with `term` for a "View in Dependencies" jump, when the
       *  package name alone would be ambiguous (the same name resolved to two
       *  different versions in the tree). */
      version?: string;
    },
  ) => void;
  /** An artifact was produced after the scan (the on-demand SPDX export), so
   *  the owner can refresh the result it holds. */
  onResultsChange?: (files: ResultFile[]) => void;
  /** A later action changed more of the result than its listing (saving an AI
   *  declaration also refreshes the SPDX 3.0.1 summary). */
  onResultPatch?: (patch: Partial<DoneEvent>) => void;
  /** Open the scan again with its settings (the top bar's re-scan). */
  onRescan?: () => void;
  /** Re-scan from the Licenses section with the outbound-license field in focus. */
  onRescanWithLicense?: () => void;
}) {
  const { t } = useTranslation();

  switch (section) {
    case "overview":
      return (
        <div className="space-y-6">
          {isAiScan(result) && <AiSummaryCard result={result} scanId={scanId} />}
          <Overview
            result={result}
            scanId={scanId}
            recent={recent}
            generatedAt={generatedAt}
            onPick={onPick}
          />
        </div>
      );

    case "components":
      return (
        <ComponentsTable
          items={result.sbom?.componentList ?? []}
          total={result.sbom?.components ?? 0}
          truncated={result.sbom?.truncated}
          scanId={scanId}
          query={query}
          onQueryChange={onQueryChange}
          onPickVulns={
            onPick && result.security
              ? (name) => onPick("vulnerabilities", { term: name })
              : undefined
          }
          onPickDependency={
            onPick
              ? (name, version) => onPick("dependencies", { term: name, version })
              : undefined
          }
        />
      );

    case "vulnerabilities":
      return result.security ? (
        <VulnerabilitiesTable
          security={result.security}
          scanId={scanId}
          query={query}
          onQueryChange={onQueryChange}
          onResultsChange={onResultsChange}
          onPickComponent={
            onPick ? (name) => onPick("components", { term: name }) : undefined
          }
          onPickDependency={
            onPick
              ? (name, version) => onPick("dependencies", { term: name, version })
              : undefined
          }
        />
      ) : (
        <EmptyState hint={t("result.noSecurityHint")}>
          {t("result.noSecurity")}
        </EmptyState>
      );

    case "licenses":
      return (
        <Licenses
          components={result.sbom?.componentList ?? []}
          query={query}
          onQueryChange={onQueryChange}
          outboundLicense={result.sbom?.outboundLicense}
          onPickLicense={
            onPick ? (license) => onPick("components", { license }) : undefined
          }
          onRescanWithLicense={onRescanWithLicense}
        />
      );

    case "dependencies": {
      const sbomFile = sbomFileName(result);
      return sbomFile ? (
        <DependenciesPanel
          scanId={scanId}
          sbomFile={sbomFile}
          components={result.sbom?.componentList ?? []}
          query={query}
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
          snapshotFile={sourceSnapshotFileName(result)}
          hasLicenses={hasLicenses}
        />
      );
    }

    case "inputSbom": {
      const inputFile = inputSbomFileName(result);
      if (!inputFile) return null;
      return (
        <InputSbomPanel
          scanId={scanId}
          inputFile={inputFile}
          componentsHref={scanId ? scanHash(scanId, "components") : undefined}
        />
      );
    }

    case "artifacts":
      return (
        <ArtifactsSection
          result={result}
          scanId={scanId}
          onResultsChange={onResultsChange}
          onResultPatch={onResultPatch}
        />
      );

    case "models": {
      const sbomFile = sbomFileName(result);
      // A submitted AI SBOM shows its G7 checks on the Conformance screen
      // instead (that is a real review of someone else's document); only a
      // self-generated AI SBOM's disclosure gaps belong here.
      const supplied = Boolean(inputSbomFileName(result));
      return sbomFile ? (
        <ModelsDatasets
          scanId={scanId}
          sbomFile={sbomFile}
          conformance={supplied ? null : result.conformance}
          spdx3={result.spdx3}
          results={result.results}
          title={
            result.scanConfig
              ? `${result.scanConfig.project} ${result.scanConfig.version}`
              : (scanId ?? "")
          }
          onResultPatch={onResultPatch}
          onRescan={onRescan}
          declaredScan={result.scanConfig?.source === "ai-declare"}
          // The Overview's "fill" link carries ?fill=1; dropped once the
          // questions open, so a reload does not open them again.
          autoFill={query?.fill === "1"}
          onAutoFill={() => onQueryChange?.({})}
        />
      ) : null;
    }

    case "conformance":
      // nav.ts shows this section for every scan except a self-generated AI
      // SBOM, whose G7 rollup lives in Models & datasets above instead (to
      // avoid showing it twice) — see that file for the full gate.
      return result.conformance ? (
        <ConformancePanel
          conformance={result.conformance}
          scanId={scanId}
          results={result.results}
          isSuppliedDocument={Boolean(inputSbomFileName(result))}
          isAiDocument={isAiScan(result)}
        />
      ) : null;

    default:
      return null;
  }
}
