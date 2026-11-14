// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CpuIcon } from "@primer/octicons-react";
import { Label, Link } from "@primer/react";
import { type ReactNode, useMemo } from "react";
import { useTranslation } from "react-i18next";

import type { DoneEvent, Spdx3Summary } from "@/lib/api";
import { computeAiSummary, type AiSummaryRisk } from "@/lib/aiSummary";
import { type AssessmentGrade, GRADE_LABEL_KEY, GRADE_SEVERITY_ORDER } from "@/lib/models";
import { inputSbomFileName } from "@/lib/results";
import { scanHash } from "@/lib/route";

import { PackageCoordinate } from "./primer";
import { OvBox } from "./overview/parts";

/** Primer Label variant per stamped grade. */
const GRADE_VARIANT: Record<AssessmentGrade, "success" | "attention" | "severe" | "danger"> = {
  ok: "success",
  conditional: "attention",
  review: "severe",
  caution: "danger",
};

/** First tile's sub-line: a single graded model's condition count, or (several
 *  models / no single model to name) a grade distribution, either way with the
 *  license-review count folded on. */
function riskSubline(t: (key: string, opts?: Record<string, unknown>) => string, risk: AiSummaryRisk): string {
  const parts: string[] = [];
  if (risk.single) {
    parts.push(t("aiSummary.conditionCount", { count: risk.single.conditionCount }));
  } else {
    const dist = GRADE_SEVERITY_ORDER.filter((g) => (risk.counts[g] ?? 0) > 0)
      .map((g) => `${t(GRADE_LABEL_KEY[g])} ${risk.counts[g]}`)
      .join(", ");
    if (dist) parts.push(dist);
  }
  parts.push(t("aiSummary.licenseReviewCount", { count: risk.licenseReviewCount }));
  return parts.join(" · ");
}

/** A model id such as `google-bert/bert-base-uncased`: the owner muted, the name plain. */
function splitModelName(name: string): { group?: string; name: string } {
  const i = name.indexOf("/");
  return i > 0 && i < name.length - 1 ? { group: name.slice(0, i), name: name.slice(i + 1) } : { name };
}

function Tile({ label, value, detail }: { label: string; value: ReactNode; detail?: string }) {
  return (
    <div className="bl-ai-tile">
      <span className="bl-muted bl-small">{label}</span>
      <b>{value}</b>
      {detail && <span className="bl-muted bl-small">{detail}</span>}
    </div>
  );
}

/**
 * AI model SBOM summary, the entry point for an AI scan's findings, shown at the
 * top of the Overview only when `isAiScan(result)`. A compact rollup (one head,
 * up to three tiles, one summary line, two links, one disclaimer) that jumps into
 * Models & datasets and Conformance for the detail; neither section is replaced
 * or duplicated here.
 */
export function AiSummaryCard({ result, scanId }: { result: DoneEvent; scanId: string | null }) {
  const { t, i18n } = useTranslation();
  const summary = useMemo(() => computeAiSummary(result, i18n.language ?? ""), [result, i18n.language]);
  const { header, grade, risk, g7, crosswalk, modelCount, datasetCount } = summary;
  // The Conformance screen only exists for a submitted document under review
  // (nav.ts gates the section on the input SBOM); a self-generated AI SBOM's G7
  // detail lives on Models & datasets, which "View models" already reaches.
  const hasConformance = Boolean(inputSbomFileName(result));
  // The pipeline's own disclaimer travels with a risk assessment; an older run
  // graded only through `assessCounts` carries no such text, but a rendered risk
  // verdict still needs the guidance caveat.
  const disclaimer = summary.disclaimer || (risk ? t("aiSummary.disclaimer") : "");
  const hasTiles = Boolean(risk || g7 || crosswalk);

  return (
    <OvBox
      testId="ai-summary"
      icon={CpuIcon}
      title={t("aiSummary.title")}
      head={
        <>
          {header.kind === "single" && (
            <span className="bl-breakall">
              <PackageCoordinate {...splitModelName(header.name)} strongName />
              {header.version && <span className="bl-muted bl-mono"> {header.version}</span>}
            </span>
          )}
          {header.kind === "multi" && <span>{t("aiSummary.modelsCount", { count: header.count })}</span>}
          {header.kind === "datasets" && <span>{t("aiSummary.datasetsCount", { count: header.count })}</span>}
        </>
      }
    >
      <div className="bl-box-body bl-stack-8" style={{ gap: "var(--base-size-12)" }}>
        {hasTiles ? (
          <div className="bl-ai-tiles">
            {risk && (
              <Tile
                label={t("aiSummary.riskLabel")}
                value={
                  grade ? (
                    <Label variant={GRADE_VARIANT[grade]} size="large">
                      {t(GRADE_LABEL_KEY[grade])}
                    </Label>
                  ) : (
                    t("aiSummary.riskUnknown")
                  )
                }
                detail={riskSubline(t, risk)}
              />
            )}
            {g7 &&
              (g7.auto === 0 ? (
                <Tile label={t("aiSummary.g7Label")} value={<span className="bl-muted">{t("aiSummary.g7None")}</span>} />
              ) : (
                <Tile
                  label={t("aiSummary.g7Label")}
                  value={t("aiSummary.g7Value", { present: g7.present, auto: g7.auto })}
                  detail={t("aiSummary.g7Detail", { gap: g7.gap, review: g7.review })}
                />
              ))}
            {crosswalk && (
              <Tile
                label={t("aiSummary.crosswalkLabel")}
                value={t("aiSummary.crosswalkValue", { count: crosswalk.frameworkCount })}
                detail={t("aiSummary.crosswalkDetail", { present: crosswalk.present, total: crosswalk.total })}
              />
            )}
          </div>
        ) : (
          <p className="bl-muted bl-flat">{t("aiSummary.countLine", { models: modelCount, datasets: datasetCount })}</p>
        )}
        {risk?.single && <p className="bl-flat">{risk.single.summary}</p>}
        {scanId && (
          <div className="bl-inline bl-wrap" style={{ gap: "var(--base-size-16)" }}>
            <Link href={scanHash(scanId, "models")}>{t("aiSummary.viewModels")}</Link>
            {hasConformance && <Link href={scanHash(scanId, "conformance")}>{t("aiSummary.viewConformance")}</Link>}
          </div>
        )}
        {disclaimer && <p className="bl-muted bl-small bl-flat">{disclaimer}</p>}
      </div>
      {result.spdx3 && <Spdx3Line spdx3={result.spdx3} scanId={scanId} />}
    </OvBox>
  );
}

/** The SPDX 3.0.1 AI document in one line: draft or complete, how many required
 *  fields are left, and the way to Models & datasets to fill them. */
function Spdx3Line({ spdx3, scanId }: { spdx3: Spdx3Summary; scanId: string | null }) {
  const { t } = useTranslation();
  const missing = spdx3.counts.missingRequired ?? 0;
  return (
    <div className="bl-ai-spdx" data-testid="ai-summary-spdx3">
      <span className="bl-muted bl-small bl-strong">{t("spdx3.band.title")}</span>
      <Label variant={spdx3.draft ? "attention" : "success"}>{spdx3.draft ? t("spdx3.draft") : t("spdx3.complete")}</Label>
      <span className="bl-small">{spdx3.draft ? t("aiSummary.spdx3Open", { count: missing }) : t("aiSummary.spdx3Done")}</span>
      {scanId && (
        <span className="bl-box-head-end">
          <Link href={spdx3.draft ? scanHash(scanId, "models", { fill: "1" }) : scanHash(scanId, "models")}>
            {spdx3.draft ? t("aiSummary.spdx3Fill") : t("aiSummary.spdx3View")}
          </Link>
        </span>
      )}
    </div>
  );
}
