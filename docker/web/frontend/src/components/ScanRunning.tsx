// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  CheckCircleIcon,
  CircleIcon,
  PlusIcon,
  SyncIcon,
  XCircleIcon,
  XIcon,
} from "@primer/octicons-react";
import { Banner, Button, Dialog, ProgressBar, Spinner, Timeline } from "@primer/react";
import { useEffect, useRef, useState, type RefObject } from "react";
import { useTranslation } from "react-i18next";

import { explainFailure } from "@/lib/failureExplain";
import { anyStageMarker, visiblePercent, visibleStages, type StageStatus } from "@/lib/scanProgress";
import { useToast } from "@/lib/toast";

import { ScreenHeader } from "./primer";
import { ProgressLog } from "./ProgressLog";
import { ReportProblem } from "./ReportProblem";
import { DialogHeader } from "./ShortcutsDialog";

import "./progress/scan-progress.css";

type Status = "running" | "done" | "error";

/**
 * Scan-running view: the pipeline steps (derived from the live log markers),
 * a running headline, and the SSE log itself. The steps are honest: each lights
 * up only once its marker appears. Partial results are not streamed by the
 * backend, so the log is the live surface until the done event arrives.
 *
 * On failure a banner leads with what went wrong and what to do, in the
 * reader's language, with a way out: retry the same scan when it is safe to
 * replay, and always New scan. The steps stay, showing where it stopped. The
 * scanner's own message sits in the folded run log, and the report-a-problem
 * panel opens by itself.
 */
export function ScanRunning({
  logs,
  status,
  projectLabel,
  errorMessage,
  errorKey,
  newScanHref,
  onNewScan,
  onRetry,
  onCancel,
  deepCveEnabled,
}: {
  logs: string[];
  status: Status;
  projectLabel?: string;
  /** The scanner's failure message, kept as received in the run log. */
  errorMessage?: string | null;
  /** i18n key when the server could classify the failure (e.g. a git clone
   *  against a missing or private repository). */
  errorKey?: string | null;
  /** Hash for the New scan screen, the always-available way out. */
  newScanHref?: string;
  /** Reset to a blank New scan form. A scan started from `#/new` that fails
   *  leaves the hash at `#/new` already, so the anchor's own navigation fires
   *  no `hashchange` and would otherwise do nothing. */
  onNewScan?: () => void;
  /** Re-run the same scan; only provided when the params are safe to replay. */
  onRetry?: () => void;
  /** Stop a running scan (closes the stream; the backend ends the process). */
  onCancel?: () => void;
  /** Whether this run requested deep CVE matching. When false its marker never
   *  appears in the log, so the step is dropped rather than left pending. */
  deepCveEnabled?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const { toast } = useToast();
  const failed = status === "error";
  const [confirming, setConfirming] = useState(false);
  const cancelRef = useRef<HTMLButtonElement>(null);
  // The scan ended (done or failed) behind the dialog: it no longer applies.
  useEffect(() => {
    if (status !== "running") setConfirming(false);
  }, [status]);
  let explained = failed ? explainFailure(logs, errorMessage, errorKey) : null;
  // A server key with no wording here falls back to the generic cause.
  if (explained && !i18n.exists(explained.causeKey)) {
    explained = explainFailure(logs, errorMessage, null);
  }
  // The stream handler appends the message to the log as "✖ <message>", so the
  // log already holds it as received; showing it again above the log would
  // repeat the sentence.
  const messageInLog = Boolean(errorMessage) && logs[logs.length - 1] === `✖ ${errorMessage}`;

  return (
    <div className="bl-run">
      <ScreenHeader
        title={failed ? t("result.failed") : t("form.running")}
        description={projectLabel && <span className="bl-run-name">{projectLabel}</span>}
        actions={
          !failed && onCancel ? (
            <Button ref={cancelRef} leadingVisual={XIcon} onClick={() => setConfirming(true)} data-testid="run-cancel">
              {t("run.cancel")}
            </Button>
          ) : undefined
        }
      />

      {failed && explained && (
        <>
          <Banner
            variant="critical"
            role="alert"
            title={t("run.failedTitle")}
            data-testid="run-failed"
            description={
              <>
                <p className="bl-run-fail-text">{t(explained.causeKey, failureVars(t, explained.vars))}</p>
                <p className="bl-run-fail-text">{t(explained.fixKey, failureVars(t, explained.vars))}</p>
                {!onRetry && <p className="bl-run-fail-text">{t("run.noRetryOneShot")}</p>}
              </>
            }
            primaryAction={
              onRetry ? (
                <Banner.PrimaryAction leadingVisual={SyncIcon} onClick={onRetry}>
                  {t("run.retry")}
                </Banner.PrimaryAction>
              ) : newScanHref ? (
                <Banner.PrimaryAction as="a" href={newScanHref} onClick={onNewScan} leadingVisual={PlusIcon}>
                  {t("shell.newScan")}
                </Banner.PrimaryAction>
              ) : undefined
            }
            secondaryAction={
              onRetry && newScanHref ? (
                <Banner.SecondaryAction as="a" href={newScanHref} onClick={onNewScan} leadingVisual={PlusIcon}>
                  {t("shell.newScan")}
                </Banner.SecondaryAction>
              ) : undefined
            }
          />
        </>
      )}

      <Steps logs={logs} status={status} deepCve={Boolean(deepCveEnabled)} />

      <ProgressLog
        logs={logs}
        status={status}
        open={!failed || !explained?.recognised}
        serverMessage={failed && !messageInLog ? errorMessage : null}
      />

      {/* No run id here: the stream ended before a finished scan existed, so the
          summary is the environment section only. */}
      {failed && <ReportProblem scanId={null} errorMessage={errorMessage} defaultOpen />}

      {confirming && status === "running" && (
        <CancelDialog
          name={projectLabel ?? ""}
          returnFocusRef={cancelRef}
          onKeep={() => setConfirming(false)}
          onConfirm={() => {
            setConfirming(false);
            onCancel?.();
            toast(t("run.cancelled"));
          }}
        />
      )}
    </div>
  );
}

/** The tool and runtime a log did not name are described in words. */
function failureVars(t: (k: string) => string, vars: Record<string, string>) {
  return {
    ...vars,
    tool: vars.tool || t("run.failToolUnknown"),
    runtime: vars.runtime || t("run.failRuntimeUnknown"),
  };
}

function Steps({ logs, status, deepCve }: { logs: string[]; status: Status; deepCve: boolean }) {
  const { t } = useTranslation();
  // A failed run keeps the step it stopped on active, so the reader sees where.
  const raw = visibleStages(logs, status === "done", deepCve);
  // A run that failed before any step's marker (a clone that did not start)
  // stopped at no step: every step waits, none is marked failed.
  const visible =
    status === "error" && !anyStageMarker(logs) ? raw.map((v) => ({ ...v, status: "pending" as const })) : raw;
  const pct = status === "done" ? 100 : visiblePercent(visible);
  const failed = status === "error";
  return (
    <section className="bl-box" aria-labelledby="run-steps" data-testid="run-steps">
      <div className="bl-box-head">
        <h2 id="run-steps">{t("run.runSteps")}</h2>
        {!failed && <span className="bl-run-pct">{pct}%</span>}
      </div>
      <div className="bl-run-bar">
        <ProgressBar
          progress={failed ? (visible.some((v) => v.status !== "pending") ? pct : 0) : pct}
          aria-label={t("run.stepsLabel")}
          bg={failed ? "neutral.emphasis" : status === "done" ? "success.emphasis" : "accent.emphasis"}
        />
      </div>
      <div className="bl-run-steps-body">
        <Timeline clipSidebar>
          {visible.map(({ stage, status: st }) => {
            const shown: StageStatus | "failed" = st === "active" && status === "error" ? "failed" : st;
            return (
              <Timeline.Item key={stage.id} condensed data-state={shown}>
                <Timeline.Badge>
                  <span className="bl-run-icon" aria-hidden data-state={shown}>
                    {shown === "done" ? (
                      <CheckCircleIcon size={16} />
                    ) : shown === "failed" ? (
                      <XCircleIcon size={16} />
                    ) : shown === "active" ? (
                      <Spinner size="small" srText={null} />
                    ) : (
                      <CircleIcon size={16} />
                    )}
                  </span>
                </Timeline.Badge>
                <Timeline.Body>
                  <span className="bl-run-step">
                    <span className={shown === "pending" ? "bl-muted" : shown === "active" ? "bl-strong" : undefined}>
                      {t(stage.labelKey)}
                    </span>
                    <span className="bl-run-step-state" data-state={shown}>
                      {"· "}
                      {t(
                        shown === "failed"
                          ? "run.stepFailed"
                          : shown === "done"
                            ? "run.stepDone"
                            : shown === "active"
                              ? "run.stepActive"
                              : "run.stepPending",
                      )}
                    </span>
                  </span>
                </Timeline.Body>
              </Timeline.Item>
            );
          })}
        </Timeline>
      </div>
    </section>
  );
}

/**
 * Cancelling drops the scan and what it found so far, so it asks first. Focus
 * opens on "Keep scanning", so a stray Enter leaves the scan running.
 */
function CancelDialog({
  name,
  returnFocusRef,
  onKeep,
  onConfirm,
}: {
  name: string;
  returnFocusRef: RefObject<HTMLElement | null>;
  onKeep: () => void;
  onConfirm: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Dialog
      title={t("run.cancelTitle")}
      onClose={onKeep}
      width="medium"
      role="alertdialog"
      returnFocusRef={returnFocusRef as RefObject<HTMLElement>}
      renderHeader={({ dialogLabelId }) => (
        <DialogHeader id={dialogLabelId} title={t("run.cancelTitle")} onClose={onKeep} />
      )}
      footerButtons={[
        { buttonType: "default", content: t("run.cancelKeep"), onClick: onKeep, autoFocus: true },
        { buttonType: "danger", content: t("run.cancelConfirm"), onClick: onConfirm },
      ]}
    >
      <p className="bl-flat" style={{ fontSize: "var(--text-body-size-medium)" }}>
        {name ? t("run.cancelBody", { name }) : t("run.cancelBodyNoName")}
      </p>
    </Dialog>
  );
}

