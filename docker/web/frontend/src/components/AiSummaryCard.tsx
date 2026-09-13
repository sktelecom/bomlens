// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Cpu } from "lucide-react";
import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type { DoneEvent } from "@/lib/api";
import { computeAiSummary, type AiSummaryRisk } from "@/lib/aiSummary";
import { GRADE_LABEL_KEY, GRADE_SEVERITY_ORDER, GradeBadge, type AssessmentGrade } from "@/lib/models";
import { inputSbomFileName } from "@/lib/results";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

/** Text link style shared with the Overview's jump-through links (Overview.tsx
 *  `topRiskAll`), so the card's two links read as the same kind of thing. */
const LINK_CLASS =
  "rounded text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1";

/** First tile's sub-line: a single graded model's condition count, or (several
 *  models / no single model to name) a grade distribution — either way with the
 *  license-review count folded on, since that count lost its own tile here. */
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

/**
 * AI model SBOM summary — the entry point for an AI scan's findings, shown at
 * the top of the Overview only when `isAiScan(result)`. A compact rollup (one
 * header line, up to three tiles, one summary line, two links, one disclaimer)
 * that jumps into Models & datasets and Conformance for the detail; neither
 * section is replaced or duplicated here.
 */
export function AiSummaryCard({
  result,
  scanId,
}: {
  result: DoneEvent;
  scanId: string | null;
}) {
  const { t, i18n } = useTranslation();
  const summary = useMemo(
    () => computeAiSummary(result, i18n.language ?? ""),
    [result, i18n.language],
  );
  const { header, grade, risk, g7, crosswalk, modelCount, datasetCount } = summary;

  const tileCount = (risk ? 1 : 0) + (g7 ? 1 : 0) + (crosswalk ? 1 : 0);
  // The Conformance screen only exists for a submitted document under review
  // (nav.ts gates the section on hasInputSbom) — a self-generated AI SBOM's G7
  // detail lives on Models & datasets instead, which "View models" already
  // reaches, so the second link would otherwise point at a hidden section.
  const hasConformance = Boolean(inputSbomFileName(result));
  // The pipeline's own disclaimer travels with a risk assessment; an older run
  // graded only through `assessCounts` carries no such text, but a rendered
  // risk verdict still needs the guidance caveat, so fall back to the generic
  // static copy rather than showing nothing.
  const disclaimer = summary.disclaimer || (risk ? t("aiSummary.disclaimer") : "");

  return (
    <Card data-testid="ai-summary">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Cpu className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="text-sm font-semibold text-foreground">{t("aiSummary.title")}</span>
          {header.kind === "single" && (
            <span className="min-w-0 truncate font-mono text-sm text-foreground">
              {header.name}
              {header.version && <span className="text-muted-foreground"> {header.version}</span>}
            </span>
          )}
          {header.kind === "multi" && (
            <span className="text-sm text-foreground">
              {t("aiSummary.modelsCount", { count: header.count })}
            </span>
          )}
          {header.kind === "datasets" && (
            <span className="text-sm text-foreground">
              {t("aiSummary.datasetsCount", { count: header.count })}
            </span>
          )}
          {grade && <GradeBadge grade={grade} />}
        </div>

        {tileCount > 0 ? (
          <div className={cn("grid gap-3", tileCount >= 3 ? "sm:grid-cols-3" : "sm:grid-cols-2")}>
            {risk && <RiskTile grade={grade} risk={risk} />}
            {g7 && <G7Tile g7={g7} />}
            {crosswalk && <CrosswalkTile crosswalk={crosswalk} />}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            {t("aiSummary.countLine", { models: modelCount, datasets: datasetCount })}
          </p>
        )}

        {risk?.single && <p className="text-sm text-foreground">{risk.single.summary}</p>}

        <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
          {scanId && (
            <a href={scanHash(scanId, "models")} className={LINK_CLASS}>
              {t("aiSummary.viewModels")}
            </a>
          )}
          {scanId && hasConformance && (
            <>
              <span className="text-xs text-muted-foreground" aria-hidden>
                ·
              </span>
              <a href={scanHash(scanId, "conformance")} className={LINK_CLASS}>
                {t("aiSummary.viewConformance")}
              </a>
            </>
          )}
        </div>

        {disclaimer && <p className="text-xs text-muted-foreground">{disclaimer}</p>}
      </CardContent>
    </Card>
  );
}

function RiskTile({
  grade,
  risk,
}: {
  grade: AssessmentGrade | null;
  risk: AiSummaryRisk;
}) {
  const { t } = useTranslation();
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs font-medium text-muted-foreground">{t("aiSummary.riskLabel")}</div>
      <div className="mt-0.5 text-lg font-semibold tabular-nums text-foreground">
        {grade ? t(GRADE_LABEL_KEY[grade]) : t("aiSummary.riskUnknown")}
      </div>
      <div className="mt-0.5 text-xs text-muted-foreground">{riskSubline(t, risk)}</div>
    </div>
  );
}

function G7Tile({ g7 }: { g7: NonNullable<ReturnType<typeof computeAiSummary>["g7"]> }) {
  const { t } = useTranslation();
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs font-medium text-muted-foreground">{t("aiSummary.g7Label")}</div>
      {g7.auto === 0 ? (
        <div className="mt-0.5 text-lg font-semibold text-muted-foreground">
          {t("aiSummary.g7None")}
        </div>
      ) : (
        <>
          <div className="mt-0.5 text-lg font-semibold tabular-nums text-foreground">
            {t("aiSummary.g7Value", { present: g7.present, auto: g7.auto })}
          </div>
          <div className="mt-0.5 text-xs text-muted-foreground">
            {t("aiSummary.g7Detail", { gap: g7.gap, review: g7.review })}
          </div>
        </>
      )}
    </div>
  );
}

function CrosswalkTile({
  crosswalk,
}: {
  crosswalk: NonNullable<ReturnType<typeof computeAiSummary>["crosswalk"]>;
}) {
  const { t } = useTranslation();
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs font-medium text-muted-foreground">
        {t("aiSummary.crosswalkLabel")}
      </div>
      <div className="mt-0.5 text-lg font-semibold tabular-nums text-foreground">
        {t("aiSummary.crosswalkValue", { count: crosswalk.frameworkCount })}
      </div>
      <div className="mt-0.5 text-xs text-muted-foreground">
        {t("aiSummary.crosswalkDetail", { present: crosswalk.present, total: crosswalk.total })}
      </div>
    </div>
  );
}
