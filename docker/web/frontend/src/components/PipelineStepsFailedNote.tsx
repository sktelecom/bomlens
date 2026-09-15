// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

import { pipelineStepLabelKey } from "@/lib/pipelineSteps";

/**
 * Best-effort post-process steps that failed (docker/lib/pipeline-step.sh),
 * stamped on the SBOM itself rather than only logged, so it still shows on a
 * re-open, a re-analyzed document, or one shared without its scan log.
 *
 * Shared between Overview (a scan the reader ran) and the conformance panel
 * (a report that may judge a document the reader did not generate): `context`
 * picks the title and default hint, since "re-scan" only makes sense for the
 * former. `isSuppliedDocument` (an ANALYZE run against an uploaded SBOM, see
 * `inputSbomFileName`) swaps the scan-context hint for the same "ask the
 * supplier" line the conformance context appends below its own hint, since a
 * reader looking at someone else's document cannot re-scan it either way.
 */
export function PipelineStepsFailedNote({
  steps,
  more = 0,
  context,
  isSuppliedDocument = false,
  testId = "pipeline-steps-failed",
}: {
  steps: string[];
  more?: number;
  context: "scan" | "conformance";
  isSuppliedDocument?: boolean;
  testId?: string;
}) {
  const { t } = useTranslation();
  if (steps.length === 0) return null;

  const title =
    context === "scan" ? t("pipelineNote.titleScan") : t("pipelineNote.titleConformance");
  const hint =
    context === "scan" && isSuppliedDocument
      ? t("pipelineNote.supplierHint")
      : context === "scan"
        ? t("pipelineNote.hintScan")
        : t("pipelineNote.hintConformance");

  return (
    <div
      className="rounded-md border border-warning-border/60 bg-warning-surface px-4 py-3 text-warning dark:border-warning-border/20 dark:bg-warning-surface/30"
      data-testid={testId}
    >
      <div className="text-sm font-medium">{title}</div>
      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs">
        {steps.map((step) => {
          const key = pipelineStepLabelKey(step);
          return <li key={step}>{key ? t(key) : <span className="font-mono">{step}</span>}</li>;
        })}
      </ul>
      {more > 0 && (
        <p className="mt-1 text-xs">{t("pipelineNote.more", { count: more })}</p>
      )}
      <p className="mt-1 text-xs">{hint}</p>
      {context === "conformance" && isSuppliedDocument && (
        <p className="mt-1 text-xs">{t("pipelineNote.supplierHint")}</p>
      )}
    </div>
  );
}
