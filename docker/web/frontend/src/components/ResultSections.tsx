// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

import { EmptyState } from "@/components/ui/state";
import type { DoneEvent, RecentScan, ResultFile, Severity } from "@/lib/api";
import type { LicenseRiskTier } from "@/lib/licenses";
import type { SectionId } from "@/lib/nav";
import {
  inputSbomFileName,
  sbomFileName,
  scancodeFileName,
  sourceSnapshotFileName,
  sourceTreeFileName,
} from "@/lib/results";
import { scanHash, type RouteQuery } from "@/lib/route";

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
  query,
  onQueryChange,
  onPick,
  onResultsChange,
}: {
  section: SectionId;
  result: DoneEvent;
  /** The scan's id, so Overview can link into sections via `#/scan/<id>/…`. */
  scanId: string | null;
  /** Local Recent-scans list, for the Overview "vs previous scan" line. */
  recent?: RecentScan[];
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
    },
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
          scanId={scanId}
          query={query}
          onQueryChange={onQueryChange}
          onPickVulns={
            onPick && result.security
              ? (name) => onPick("vulnerabilities", { term: name })
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
          onPickComponent={
            onPick ? (name) => onPick("components", { term: name }) : undefined
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
          scanId={scanId}
          results={result.results}
        />
      ) : null;

    default:
      return null;
  }
}
