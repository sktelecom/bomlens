// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  ContainerIcon,
  CpuIcon,
  FileDirectoryIcon,
  FileIcon,
  GitBranchIcon,
} from "@primer/octicons-react";
import type { ElementType } from "react";
import { useTranslation } from "react-i18next";

import type { DoneEvent, RecentScan, ResultFile } from "@/lib/api";
import { type ProvenanceKind, provenanceOf } from "@/lib/provenance";
import { isAiScan, sbomFileName } from "@/lib/results";

import { AiSummaryCard } from "./AiSummaryCard";
import { AttentionBox } from "./overview/Attention";
import { ComparisonBox } from "./overview/Comparison";
import { FailureBanner, OverviewNotices } from "./overview/Notices";
import { LicensePanel, RiskyBox, SeverityPanel } from "./overview/Risk";
import { SectionsBox, YoctoVexNote } from "./overview/Sections";
import { ResultsList } from "./ResultsList";

/** Icon per provenance kind, so the input reads at a glance. */
const PROVENANCE_ICON: Record<ProvenanceKind, ElementType> = {
  folder: FileDirectoryIcon,
  yocto: FileDirectoryIcon,
  git: GitBranchIcon,
  image: ContainerIcon,
  file: FileIcon,
  sbom: FileIcon,
  model: CpuIcon,
  declaration: FileIcon,
};

/**
 * What was scanned and how it was read, as the lines under the Overview's
 * title. They frame the counts: the same "71 components" means something
 * different for a folder on disk than for an image someone pulled, and a scan
 * that read a lock file skipped the build, which is why it finished quickly and
 * what its dependency list rests on.
 */
export function OverviewHeaderLines({ result }: { result: DoneEvent }) {
  const { t } = useTranslation();
  const provenance = provenanceOf(result.scanConfig);
  const Icon = provenance ? PROVENANCE_ICON[provenance.kind] : null;
  return (
    <>
      {provenance && Icon && (
        <span className="bl-ov-prov" data-testid="provenance">
          <Icon size={14} />
          <span>{t(provenance.labelKey)}</span>
          <code title={provenance.value}>{provenance.value}</code>
        </span>
      )}
      {result.sbom?.detection === "static" && (
        <span className="bl-ov-prov" data-testid="detection">
          {result.sbom.detectionSource
            ? t("overview.detectionStaticFrom", { file: result.sbom.detectionSource })
            : t("overview.detectionStatic")}
        </span>
      )}
    </>
  );
}

/**
 * Decision-first Overview: notices about how far to trust the result, then in
 * the main column what to look at first (with what else needs attention), how
 * this run moved against the last one and the riskiest components, and in the
 * side column the two risk axes (severity, license class) and what the
 * navigation counts leave out.
 *
 * Only risk axes belong here. A component-type distribution used to sit below
 * them and was dropped: type is an inventory fact the Components table already
 * filters on, and as a chart it was mostly one bar (a single-ecosystem SBOM is
 * all "library") or one bar drowning the rest (a container image is nearly all
 * "file").
 */
export function Overview({
  result,
  scanId,
  recent = [],
  generatedAt,
  onReportProblem,
}: {
  result: DoneEvent;
  /** The scan's id; section links resolve to `#/scan/<id>/<section>`. */
  scanId: string | null;
  /** Local Recent-scans list, for the "vs previous scan" comparison. */
  recent?: RecentScan[];
  /** Unix seconds when this scan was made; the "check first" block names it as
   *  the point the counts are taken at. */
  generatedAt?: number;
  /** Open the report-a-problem dialog (shown on a failed scan). */
  onReportProblem?: (trigger: HTMLElement) => void;
}) {
  const hasDeps = Boolean(sbomFileName(result));
  const ai = isAiScan(result);
  return (
    <>
      <div className="bl-ov-notices">
        <FailureBanner result={result} scanId={scanId} onReportProblem={onReportProblem} />
      </div>
      <OverviewNotices result={result} />
      <div className="bl-ov">
        <div className="bl-ov-col">
          {ai && <AiSummaryCard result={result} scanId={scanId} />}
          <AttentionBox result={result} scanId={scanId} generatedAt={generatedAt} />
          {result.yoctoVex && <YoctoVexNote vex={result.yoctoVex} />}
          <ComparisonBox result={result} scanId={scanId} recent={recent} />
          <RiskyBox result={result} scanId={scanId} />
        </div>
        <div className="bl-ov-col">
          {result.security && <SeverityPanel security={result.security} scanId={scanId} />}
          <LicensePanel result={result} scanId={scanId} />
          <SectionsBox result={result} scanId={scanId} hasDeps={hasDeps} />
        </div>
      </div>
    </>
  );
}

/** The standalone Artifacts section (a link target of the Sections box). */
export function ArtifactsSection({
  result,
  scanId,
  onResultsChange,
  onResultPatch,
}: {
  result: DoneEvent;
  scanId: string | null;
  /** Passed through so an on-demand SPDX export updates the owning result. */
  onResultsChange?: (files: ResultFile[]) => void;
  /** The SPDX 3.0.1 actions also refresh the document's summary. */
  onResultPatch?: (patch: Partial<DoneEvent>) => void;
}) {
  return (
    <ResultsList
      results={result.results}
      scanId={scanId}
      onResultsChange={onResultsChange}
      aiScan={isAiScan(result)}
      uploadedSbom={result.scanConfig?.source === "sbom-upload"}
      spdx3={result.spdx3}
      onResultPatch={onResultPatch}
    />
  );
}
