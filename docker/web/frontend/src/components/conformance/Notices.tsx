// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Banner } from "@primer/react";
import { useTranslation } from "react-i18next";

import type { Completeness, ConformanceSummary } from "@/lib/api";
import { gradeLabel, isIncomplete } from "@/lib/completeness";
import type { ResultQuality } from "@/lib/conformance";
import { pipelineStepLabelKey } from "@/lib/pipelineSteps";

import { CompletenessReasons } from "../CompletenessReasons";
import "./conformance.css";

function StepList({ steps, more }: { steps: string[]; more: number }) {
  const { t } = useTranslation();
  return (
    <ul className="bl-cf-steps">
      {steps.map((step) => {
        const key = pipelineStepLabelKey(step);
        // A step id from a submitted document is text, never markup.
        return <li key={step}>{key ? t(key) : <span className="bl-mono">{step}</span>}</li>;
      })}
      {more > 0 && <li className="bl-muted">{t("pipelineNote.more", { count: more })}</li>}
    </ul>
  );
}

/**
 * Best-effort post-process steps that failed while the SBOM was generated. In
 * this report they may belong to a document the reader did not generate, so a
 * supplied one is pointed back at its supplier.
 */
export function PipelineNote({
  steps,
  more = 0,
  supplied = false,
}: {
  steps: string[];
  more?: number;
  supplied?: boolean;
}) {
  const { t } = useTranslation();
  if (steps.length === 0) return null;
  return (
    <Banner
      variant="warning"
      data-testid="conformance-pipeline-steps-failed"
      title={t("pipelineNote.titleConformance")}
      description={
        <>
          <StepList steps={steps} more={more} />
          <p className="bl-flat">{t("pipelineNote.hintConformance")}</p>
          {supplied && <p className="bl-flat" style={{ marginTop: "var(--base-size-4)" }}>{t("pipelineNote.supplierHint")}</p>}
        </>
      }
    />
  );
}

/**
 * Warns about a result the verdict cannot: nothing found, or no license
 * declared anywhere, so a green "pass" never stands alone beside an empty or
 * unlicensed result. A healthy coverage figure is not repeated here.
 */
export function QualityNote({
  quality,
  supplied,
  completeness,
}: {
  quality: ResultQuality;
  supplied: boolean;
  /** The engine's completeness result; when it is partial or unreliable its reasons replace the generic empty-result wording. */
  completeness?: Completeness | null;
}) {
  const { t, i18n } = useTranslation();
  if (quality.empty && isIncomplete(completeness)) {
    return (
      <Banner
        variant="warning"
        data-testid="conformance-empty-result"
        title={t("completeness.bannerTitle", { grade: gradeLabel(completeness, i18n.language ?? "en") })}
        description={<CompletenessReasons completeness={completeness} />}
      />
    );
  }
  if (quality.empty) {
    return (
      <Banner
        variant="warning"
        data-testid="conformance-empty-result"
        title={t("conf.qualityEmptyTitle")}
        description={t(supplied ? "conf.qualityEmptyBodySupplied" : "conf.qualityEmptyBody")}
      />
    );
  }
  if (!quality.license) return null;
  if (quality.noLicenses) {
    return (
      <Banner
        variant="warning"
        data-testid="conformance-no-licenses"
        title={t("conf.qualityLicenseTitle")}
        description={t("conf.qualityLicenseBody", quality.license)}
      />
    );
  }
  return null;
}

/** With no checks: the failed-steps warning and the result-quality warning, as one Banner when both apply. */
export function EmptyNotices({
  conformance,
  quality,
  supplied,
  completeness,
}: {
  conformance: ConformanceSummary;
  quality: ResultQuality;
  supplied: boolean;
  completeness?: Completeness | null;
}) {
  const { t, i18n } = useTranslation();
  const steps = conformance.pipelineStepsFailed ?? [];
  const warnQuality = quality.empty || quality.noLicenses;
  if (steps.length === 0 || !warnQuality) {
    return (
      <>
        <PipelineNote steps={steps} more={conformance.pipelineStepsFailedMore ?? 0} supplied={supplied} />
        <QualityNote quality={quality} supplied={supplied} completeness={completeness} />
      </>
    );
  }
  const graded = quality.empty && isIncomplete(completeness);
  return (
    <Banner
      variant="warning"
      data-testid="conformance-notices"
      title={t("conf.notices", { count: 2 })}
      description={
        <ol className="bl-cf-steps">
          <li data-testid="conformance-pipeline-steps-failed" style={{ marginBottom: "var(--base-size-8)" }}>
            <span className="bl-strong">{t("pipelineNote.titleConformance")}</span>
            <StepList steps={steps} more={conformance.pipelineStepsFailedMore ?? 0} />
            <span>{t("pipelineNote.hintConformance")}</span>
            {supplied && <span> {t("pipelineNote.supplierHint")}</span>}
          </li>
          <li data-testid={quality.empty ? "conformance-empty-result" : "conformance-no-licenses"}>
            <span className="bl-strong">
              {graded
                ? t("completeness.bannerTitle", { grade: gradeLabel(completeness!, i18n.language ?? "en") })
                : quality.empty
                  ? t("conf.qualityEmptyTitle")
                  : t("conf.qualityLicenseTitle")}
            </span>
            <span style={{ display: "block" }}>
              {graded
                ? <CompletenessReasons completeness={completeness!} />
                : quality.empty
                ? t(supplied ? "conf.qualityEmptyBodySupplied" : "conf.qualityEmptyBody")
                : t("conf.qualityLicenseBody", quality.license ?? {})}
            </span>
          </li>
        </ol>
      }
    />
  );
}
