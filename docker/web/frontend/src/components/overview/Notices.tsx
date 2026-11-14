// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { DownloadIcon, LinkExternalIcon } from "@primer/octicons-react";
import { Banner, Button } from "@primer/react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { type DoneEvent, fileUrl } from "@/lib/api";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { pipelineStepLabelKey } from "@/lib/pipelineSteps";
import { inputSbomFileName, isAiScan } from "@/lib/results";
import { formatBytes } from "@/lib/utils";

import { ReportProblemBody } from "../ReportProblemDialog";

/** Which body copy explains why cdxgen fell back to a direct-deps-only scan. */
export function sbomDegradedBodyKey(reason: string): string {
  switch (reason) {
    case "disk-space":
      return "result.sbomDegradedDisk";
    case "oom":
      return "result.sbomDegradedOom";
    case "network":
      return "result.sbomDegradedNetwork";
    case "cdxgen-crash":
      return "result.sbomDegradedCrash";
    case "cdxgen-unavailable":
      return "result.sbomDegradedNotRun";
    default:
      return "result.sbomDegradedBody";
  }
}

/**
 * The failed-scan banner. A scan that ended in `done.ok=false` still lands on
 * the Overview, with everything below it showing the empty shape of a scan that
 * produced nothing. `errorMessage` is the scanner's own [ERROR] block when the
 * server had no other classification (server.py's _ScanErrorTracker). A refused
 * declaration file gets its own wording, reasons and the refused SBOM. Both carry
 * the way to report the problem, which the page used to open by default.
 */
export function FailureBanner({
  result,
  scanId,
  onReportProblem,
}: {
  result: DoneEvent;
  scanId: string | null;
  /** Open the dialog; gets the button that was pressed, so focus can return to it. */
  onReportProblem?: (trigger: HTMLElement) => void;
}) {
  const { t } = useTranslation();
  if (result.ok) return null;
  const refused = result.declarationRefused;
  const report = onReportProblem ? (
    <Banner.SecondaryAction onClick={(e) => onReportProblem(e.currentTarget as HTMLElement)}>
      {t("report.open")}
    </Banner.SecondaryAction>
  ) : undefined;
  // A failed scan shows its diagnostics summary expanded right here, as the old
  // Report a problem panel opened by itself after a failure. The demo has no
  // server to build it.
  const inlineReport = IS_STATIC_DEMO ? null : (
    <div style={{ marginTop: "var(--base-size-8)" }}>
      <div className="bl-strong" style={{ marginBottom: "var(--base-size-4)" }}>
        {t("report.open")}
      </div>
      <ReportProblemBody scanId={result.id ?? scanId} errorMessage={result.errorMessage} inline />
    </div>
  );
  if (refused) {
    const href = fileUrl(result.id ?? scanId, refused.file);
    return (
      <Banner
        variant="critical"
        role="alert"
        title={t("run.declarationRefusedTitle")}
        data-testid="declaration-refused"
        secondaryAction={report}
        description={
          <div className="bl-stack-8">
            <p className="bl-flat">{t("run.declarationRefusedBody", { file: refused.file })}</p>
            {refused.reasons.length === 0 && result.errorMessage && (
              <p className="bl-flat bl-mono bl-breakall" style={{ whiteSpace: "pre-wrap" }}>
                {result.errorMessage}
              </p>
            )}
            {refused.reasons.length > 0 && (
              <ul className="bl-flat" style={{ paddingLeft: "var(--base-size-20)" }}>
                {refused.reasons.map((reason) => (
                  <li key={reason} className="bl-mono bl-breakall">
                    {reason}
                  </li>
                ))}
              </ul>
            )}
            <p className="bl-flat">{t("run.declarationRefusedFix")}</p>
            <div className="bl-inline bl-wrap">
              <Button as="a" size="small" href={href} target="_blank" rel="noopener noreferrer" trailingVisual={LinkExternalIcon}>
                {t("run.declarationRefusedView")}
              </Button>
              <Button as="a" size="small" href={href} download={refused.file} leadingVisual={DownloadIcon}>
                {t("run.declarationRefusedDownload")}
              </Button>
            </div>
            {inlineReport}
          </div>
        }
      />
    );
  }
  return (
    <Banner
      variant="critical"
      role="alert"
      data-testid="scan-failed"
      title={t("run.failedTitle")}
      secondaryAction={report}
      description={
        <div className="bl-stack-8">
          <span className="bl-breakall" style={{ whiteSpace: "pre-wrap" }}>
            {result.errorMessage || t("run.failedBody")}
          </span>
          {inlineReport}
        </div>
      }
    />
  );
}

interface Notice {
  /** i18n id under `overview.notice.*` for the merged one-line form. */
  id: "pipeline" | "warnings" | "vendored" | "degraded" | "zero" | "graph" | "scanossUnavailable" | "scanossNoMatch" | "unpinned" | "firmware";
  variant: "warning" | "info";
  title: string;
  testId?: string;
  body: ReactNode;
}

/**
 * Every conditional notice the Overview can show, in a fixed order. Each is a
 * Banner; two or more of one severity are gathered into a single Banner whose
 * lines name each one and whose "Details" holds the full text of each.
 */
export function OverviewNotices({ result }: { result: DoneEvent }) {
  const { t } = useTranslation();
  const ai = isAiScan(result);
  const sb = result.sbom;
  const hasConformance = Boolean(result.conformance?.checks?.length) && (Boolean(inputSbomFileName(result)) || !ai);
  const fs = sb?.firmwareScope;
  const notices: Notice[] = [];

  // Zero components is the one result a reader reliably misreads: it looks like
  // "nothing to worry about" when it almost always means the scan had nothing
  // to read. An AI scan is excluded: a model SBOM legitimately carries no
  // components, the model itself being the document.
  if (!ai && sb && sb.components === 0)
    notices.push({
      id: "zero",
      variant: "warning",
      title: t("result.zeroComponentsTitle"),
      testId: "zero-components",
      body: t(sb.sbomToolDegraded ? "result.zeroComponentsBodyDegraded" : "result.zeroComponentsBody"),
    });

  // A fact recorded in the document outranks this run's own log.
  if ((sb?.pipelineStepsFailed?.length ?? 0) > 0)
    notices.push({
      id: "pipeline",
      variant: "warning",
      title: t("pipelineNote.titleScan"),
      testId: "pipeline-steps-failed",
      body: (
        <>
          <ul>
            {sb!.pipelineStepsFailed!.map((s) => {
              const k = pipelineStepLabelKey(s);
              return <li key={s}>{k ? t(k) : <span className="bl-mono">{s}</span>}</li>;
            })}
          </ul>
          {(sb!.pipelineStepsFailedMore ?? 0) > 0 && <p>{t("pipelineNote.more", { count: sb!.pipelineStepsFailedMore })}</p>}
          <p>{inputSbomFileName(result) ? t("pipelineNote.supplierHint") : t("pipelineNote.hintScan")}</p>
        </>
      ),
    });

  // Firmware only: the parts of the image the unpacker could not open. Worded
  // as scope, not failure. A submitted SBOM's properties are the supplier's
  // data, not this scan's own statement, so it is not shown for one.
  if (fs && !inputSbomFileName(result))
    notices.push({
      id: "firmware",
      variant: "info",
      title: t("result.firmwareScopeTitle"),
      testId: "firmware-scope",
      body: (
        <>
          <ul>
            {fs.unknownBytes > 0 && (
              <li>{t("result.firmwareScopeUnknown", { percent: fs.unknownPercent, bytes: formatBytes(fs.unknownBytes) })}</li>
            )}
            {fs.failedSteps > 0 && (
              <li>
                {t("result.firmwareScopeFailed", { count: fs.failedSteps })}
                {fs.failedFormats.length > 0 && ` ${t("result.firmwareScopeFormats", { formats: fs.failedFormats.join(", ") })}`}
              </li>
            )}
            {fs.encryptedRegions > 0 && <li>{t("result.firmwareScopeEncrypted", { count: fs.encryptedRegions })}</li>}
            {fs.missingExtractors.length > 0 && <li>{t("result.firmwareScopeMissing", { tools: fs.missingExtractors.join(", ") })}</li>}
          </ul>
          {fs.namesMore > 0 && <p>{t("result.firmwareScopeMore", { count: fs.namesMore })}</p>}
          <p>{t("result.firmwareScopeBody")}</p>
        </>
      ),
    });

  // What the scan warned about while it ran. The log is streamed and never
  // stored, so a result opened later could not say it had warned at all.
  if ((result.scanWarnings?.length ?? 0) > 0)
    notices.push({
      id: "warnings",
      variant: "warning",
      title: t("result.scanWarningsTitle"),
      testId: "scan-warnings",
      body: (
        <ul>
          {result.scanWarnings!.map((w) => (
            <li key={w} className="bl-mono bl-breakall">
              {w.replace(/^\[WARN\]\s*/, "")}
            </li>
          ))}
        </ul>
      ),
    });

  // Versions the resolver chose, not versions anyone installed.
  if (sb?.versionPinning === "unpinned")
    notices.push({ id: "unpinned", variant: "info", title: t("result.unpinnedTitle"), testId: "version-pinning", body: t("result.unpinnedBody") });

  if (!ai && sb?.suggestIdentifyVendored)
    notices.push({ id: "vendored", variant: "warning", title: t("result.vendoredHintTitle"), testId: "vendored-hint", body: t("result.vendoredHintBody") });

  // Gated on components > 0: at 0 components the zero-components notice already
  // folds in the degraded cause, so this one steps aside.
  if (sb?.sbomToolDegraded && sb.components > 0)
    notices.push({
      id: "degraded",
      variant: "warning",
      title: t("result.sbomDegradedTitle"),
      testId: "sbom-degraded",
      body: t(sbomDegradedBodyKey(sb.sbomToolDegraded)),
    });

  // An empty dependency graph is a pipeline defect (a later step dropped the
  // graph). hasConformance is false only for a self-generated AI SBOM, whose
  // Conformance screen is not shown, so the notice stands in for its row.
  if (!hasConformance && result.conformance?.checks?.some((c) => c.id === "transitive" && c.status === "fail"))
    notices.push({ id: "graph", variant: "warning", title: t("result.sbomGraphEmptyTitle"), testId: "sbom-graph-empty", body: t("result.sbomGraphEmptyBody") });

  if (result.scanoss?.status === "unavailable")
    notices.push({ id: "scanossUnavailable", variant: "warning", title: t("result.scanossUnavailableTitle"), testId: "scanoss-unavailable", body: t("result.scanossUnavailableBody") });
  if (result.scanoss?.status === "no-match")
    notices.push({ id: "scanossNoMatch", variant: "info", title: t("result.scanossNoMatchTitle"), testId: "scanoss-no-match", body: t("result.scanossNoMatchBody") });

  if (notices.length === 0) return null;

  const banners: ReactNode[] = [];
  for (const variant of ["warning", "info"] as const) {
    const group = notices.filter((n) => n.variant === variant);
    if (group.length === 1) {
      const n = group[0];
      banners.push(
        <Banner key={n.id} variant={variant} title={n.title} data-testid={n.testId} description={<div className="bl-ov-notice-body">{n.body}</div>} />,
      );
    } else if (group.length > 1) {
      banners.push(
        <Banner
          key={`merged-${variant}`}
          variant={variant}
          data-testid={`merged-${variant}`}
          title={t(variant === "warning" ? "overview.noticeMissingTitle" : "overview.noticeNotesTitle")}
          description={
            // Folded by default: the title and how many notices it holds. The
            // toggle opens one line per notice and the full text of each.
            <details>
              <summary>
                {t("overview.noticeCount", { count: group.length })}
                <span className="bl-ov-toggle">{t("overview.details")}</span>
              </summary>
              <ul className="bl-ov-bullets" style={{ listStyle: "disc", paddingLeft: "var(--base-size-20)", marginTop: "var(--base-size-8)" }}>
                {group.map((n) => (
                  <li key={n.id}>
                    <strong>{t(`overview.notice.${n.id}.title`)}</strong> {t(`overview.notice.${n.id}.short`)}
                  </li>
                ))}
              </ul>
              <dl>
                {group.map((n) => (
                  <div key={n.id}>
                    <dt>{n.title}</dt>
                    <dd data-testid={n.testId}>{n.body}</dd>
                  </div>
                ))}
              </dl>
            </details>
          }
        />,
      );
    }
  }
  return <div className="bl-ov-notices">{banners}</div>;
}
