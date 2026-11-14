// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CpuIcon } from "@primer/octicons-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import type { ConformanceSummary, DoneEvent, ResultFile, Spdx3Summary } from "@/lib/api";
import {
  type AiModelData,
  type DeclaredService,
  parseDeclaredServices,
  parseModelCards,
} from "@/lib/models";
import { loadSbom } from "@/lib/sbomGraph";

import { DatasetsBox, Disclaimer, G7Disclosure, ModelCardBox, ServiceBox } from "./models/ModelCards";
import { ModelsEmpty, ModelsError, ModelsLoading } from "./models/states";
import "./models/models.css";
import { Spdx3Panel } from "./Spdx3Panel";

/**
 * Models & Datasets, the AI surface. Fetches the raw ML-BOM, parses each
 * machine-learning-model's card (identifier, architecture, task, license,
 * integrity, references, limitations), shows the four openness-disclosure axes
 * and the datasets the models reference. Only reachable for AI/ANALYZE scans.
 */
export function ModelsDatasets({
  scanId,
  sbomFile,
  conformance,
  spdx3,
  results,
  title,
  onResultPatch,
  onRescan,
  declaredScan,
  autoFill,
  onAutoFill,
}: {
  scanId: string | null;
  sbomFile: string;
  conformance?: ConformanceSummary | null;
  /** The SPDX 3.0.1 AI document's check summary, when this scan has one. */
  spdx3?: Spdx3Summary | null;
  /** The scan's artifacts, to find a declaration saved earlier. */
  results: ResultFile[];
  /** Project and version, shown above the question flow's steps. */
  title: string;
  /** A save or a write changed the result (its listing, its SPDX 3 summary). */
  onResultPatch?: (patch: Partial<DoneEvent>) => void;
  /** Open the scan again with its settings (a declared service reaches the
   *  CycloneDX SBOM only from a new scan). */
  onRescan?: () => void;
  /** The scan was made from a declaration alone (its input is that file). */
  declaredScan?: boolean;
  /** Open the SPDX 3.0.1 questions on arrival (the Overview's "fill" link). */
  autoFill?: boolean;
  onAutoFill?: () => void;
}) {
  // While the publisher answers the questions, the flow takes the whole
  // screen; the model cards come back when it closes.
  const [filling, setFilling] = useState(false);
  const panel = (
    <Spdx3Panel
      scanId={scanId}
      title={title}
      summary={spdx3}
      results={results}
      onPatch={onResultPatch}
      onRescan={onRescan}
      onFillingChange={setFilling}
      declaredScan={declaredScan}
      autoFill={autoFill}
      onAutoFill={onAutoFill}
    />
  );
  // The panel stays at the same place in the tree either way, so it keeps its
  // state (the open flow) when the body around it goes away.
  return (
    <div className="bl-md">
      {panel}
      {!filling && <ModelsDatasetsBody scanId={scanId} sbomFile={sbomFile} conformance={conformance} />}
    </div>
  );
}

function ModelsDatasetsBody({
  scanId,
  sbomFile,
  conformance,
}: {
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  sbomFile: string;
  /** The G7 minimum-element checks, when BomLens generated this AI SBOM
   *  itself (AIBOM/model-file/dataset) rather than reviewing one someone
   *  submitted — an uploaded AI SBOM shows its G7 checks on the Conformance
   *  screen instead (a real submission-review verdict), so callers pass null
   *  there to avoid showing the rollup twice. The headline (risk grade, G7
   *  count, crosswalk) is AiSummaryCard's job, shown once at the top of
   *  Overview for any AI scan — this is only the detailed cluster listing. */
  conformance?: ConformanceSummary | null;
}) {
  const { t } = useTranslation();
  const [data, setData] = useState<AiModelData | null>(null);
  const [services, setServices] = useState<DeclaredService[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setState("loading");
    void loadSbom(scanId, sbomFile)
      .then((sbom) => {
        if (!active) return;
        setData(parseModelCards(sbom));
        setServices(parseDeclaredServices(sbom));
        setState("ready");
      })
      .catch(() => active && setState("error"));
    return () => {
      active = false;
    };
  }, [scanId, sbomFile, reloadKey]);

  if (state === "loading") return <ModelsLoading text={t("models.loading")} />;
  if (state === "error" || !data) {
    return <ModelsError text={t("models.loadError")} onRetry={() => setReloadKey((k) => k + 1)} />;
  }
  if (data.models.length === 0 && data.datasets.length === 0) {
    return <ModelsEmpty icon={CpuIcon} title={t("models.empty")} hint={t("models.emptyHint")} />;
  }

  // The assessment surface only exists when the pipeline stamped one (older
  // BOMs and non-assessed runs render exactly as before).
  const hasAssessment = data.models.some((m) => m.assessment) || data.datasets.some((d) => d.assessment);

  return (
    <div className="bl-md-body">
      {data.models.map((m, i) => (
        <ModelCardBox key={m.purl || `${m.name}-${i}`} model={m} />
      ))}
      {services.map((s, i) => (
        <ServiceBox key={s.ref ?? `${s.name}-${i}`} service={s} />
      ))}
      {data.datasets.length > 0 && <DatasetsBox datasets={data.datasets} />}
      {hasAssessment && <Disclaimer />}
      {conformance ? <G7Disclosure conformance={conformance} /> : null}
    </div>
  );
}
