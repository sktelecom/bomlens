// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Banner, Dialog, Link, Spinner } from "@primer/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  buildAndroidSdkImage,
  cancelAndroidSdkBuild,
  fetchAndroidSdkStatus,
  recordAndroidSdkConsent,
} from "@/lib/api";
import {
  canRetryBuild,
  failureReason,
  firstStage,
  manualBuildCommand,
  type AndroidSdkNeed,
} from "@/lib/androidSdk";

import { ProgressLog } from "./ProgressLog";
import { DialogHeader } from "./ShortcutsDialog";

type Phase =
  | { kind: "consent"; saveFailed?: boolean }
  | { kind: "building"; step: number; steps: number }
  | { kind: "failed"; reason: string; detail?: string }
  | { kind: "manual" };

/**
 * Asks for the Android SDK image a scan of an Android project needs, instead of
 * showing the scan as failed. The SDK is Google's and is not redistributed: the
 * image is built on this computer after the user accepts Google's terms.
 *
 * Choices: accept and build, skip (the scan does not run), or cancel a running
 * build. When the build finishes the caller starts the same scan again.
 */
export function AndroidSdkDialog({
  need,
  capabilityBuild,
  onReady,
  onSkip,
}: {
  need: AndroidSdkNeed;
  /** `capabilities.androidSdkBuild`; false means this run mode cannot build. */
  capabilityBuild: boolean | undefined;
  /** The image is in place: start the scan again. */
  onReady: () => void;
  /** Leave without the image. */
  onSkip: () => void;
}) {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<Phase>(() => {
    const stage = firstStage(need, capabilityBuild);
    return stage === "manual"
      ? { kind: "manual" }
      : stage === "build"
        ? { kind: "building", step: 0, steps: 0 }
        : { kind: "consent" };
  });
  const [logs, setLogs] = useState<string[]>([]);
  const stopRef = useRef<(() => void) | null>(null);
  const startedRef = useRef(false);
  const readyRef = useRef(onReady);
  readyRef.current = onReady;

  const startBuild = useCallback(() => {
    setLogs([]);
    setPhase({ kind: "building", step: 0, steps: 0 });
    stopRef.current = buildAndroidSdkImage(need.api, {
      onLog: (line) => setLogs((prev) => [...prev, line]),
      onProgress: (p) => setPhase({ kind: "building", step: p.step, steps: p.steps }),
      onDone: (d) => {
        stopRef.current = null;
        if (d.ok) readyRef.current();
        else setPhase({ kind: "failed", reason: failureReason(d.reason), detail: d.detail });
      },
    });
  }, [need.api]);

  // Terms already on file: the build starts at once. The ref keeps a repeated
  // effect run (development double mount) from opening two streams.
  useEffect(() => {
    if (phase.kind !== "building" || startedRef.current) return;
    startedRef.current = true;
    // The image may have appeared since the scan asked (a build in another
    // window); then there is nothing to build.
    void fetchAndroidSdkStatus(need.api).then((s) => {
      if (s?.present) readyRef.current();
      else startBuild();
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Closing the dialog while a build runs stops it.
  useEffect(
    () => () => {
      stopRef.current?.();
    },
    [],
  );

  const accept = async () => {
    const ok = await recordAndroidSdkConsent(need.termsUrl);
    if (!ok) {
      setPhase({ kind: "consent", saveFailed: true });
      return;
    }
    startedRef.current = true;
    startBuild();
  };

  const cancelBuild = () => {
    stopRef.current?.();
    stopRef.current = null;
    void cancelAndroidSdkBuild(need.api);
    startedRef.current = true;
    setPhase({ kind: "failed", reason: "cancelled" });
  };

  const leave = () => {
    if (phase.kind === "building") cancelBuild();
    onSkip();
  };

  const title = t("androidSdk.title");
  const building = phase.kind === "building";

  return (
    <Dialog
      title={title}
      onClose={leave}
      width="large"
      renderHeader={({ dialogLabelId }) => <DialogHeader id={dialogLabelId} title={title} onClose={leave} />}
      renderBody={() => (
        <Dialog.Body>
          <div className="bl-stack-8" data-testid="android-sdk-dialog">
            <p style={{ margin: 0 }}>{t("androidSdk.why", { api: need.api })}</p>
            <p style={{ margin: 0 }}>
              <Link href={need.termsUrl} target="_blank" rel="noreferrer">
                {t("androidSdk.termsLink")}
              </Link>
            </p>

            {phase.kind === "consent" && (
              <>
                <p style={{ margin: 0 }} className="bl-muted">
                  {t("androidSdk.consentNote", { image: need.image })}
                </p>
                <p style={{ margin: 0 }} className="bl-muted" data-testid="android-sdk-skip-note">
                  {t("androidSdk.skipNote")}
                </p>
                {phase.saveFailed && (
                  <span className="bl-danger" role="alert">
                    {t("androidSdk.consentFailed")}
                  </span>
                )}
              </>
            )}

            {phase.kind === "building" && (
              <>
                <p style={{ margin: 0 }} className="bl-muted">
                  {t("androidSdk.alreadyAccepted")}
                </p>
                <span role="status" aria-live="polite" className="bl-inline" data-testid="android-sdk-progress">
                  <Spinner size="small" srText={null} />
                  {phase.steps > 0
                    ? t("androidSdk.buildingStep", { step: phase.step, steps: phase.steps })
                    : t("androidSdk.buildingStart")}
                </span>
                <ProgressLog logs={logs} status="running" collapsible open={false} />
              </>
            )}

            {phase.kind === "failed" && (
              <>
                <Banner
                  variant={phase.reason === "cancelled" ? "warning" : "critical"}
                  role="alert"
                  title={t("androidSdk.failedTitle")}
                  data-testid="android-sdk-failed"
                  description={
                    <>
                      <p className="bl-run-fail-text">{t(`androidSdk.failed.${phase.reason}`)}</p>
                      {phase.detail && (
                        <p className="bl-run-fail-text bl-mono" data-testid="android-sdk-detail">
                          {phase.detail}
                        </p>
                      )}
                    </>
                  }
                />
                {logs.length > 0 && <ProgressLog logs={logs} status="error" collapsible open={false} />}
                <p style={{ margin: 0 }} className="bl-muted">
                  {t("androidSdk.manualIntro")}
                </p>
                <code className="bl-code" data-testid="android-sdk-command">
                  {manualBuildCommand(need.api, need.image)}
                </code>
              </>
            )}

            {phase.kind === "manual" && (
              <>
                <p style={{ margin: 0 }} data-testid="android-sdk-manual">
                  {t("androidSdk.manualOnly")}
                </p>
                <code className="bl-code" data-testid="android-sdk-command">
                  {manualBuildCommand(need.api, need.image)}
                </code>
                <p style={{ margin: 0 }} className="bl-muted">
                  {t("androidSdk.skipNote")}
                </p>
              </>
            )}
          </div>
        </Dialog.Body>
      )}
      footerButtons={[
        ...(phase.kind === "consent"
          ? [
              { buttonType: "primary" as const, content: t("androidSdk.accept"), onClick: () => void accept(), autoFocus: true },
              { buttonType: "default" as const, content: t("androidSdk.skip"), onClick: onSkip },
            ]
          : []),
        ...(building ? [{ buttonType: "danger" as const, content: t("androidSdk.cancelBuild"), onClick: cancelBuild }] : []),
        ...(phase.kind === "failed"
          ? [
              ...(canRetryBuild(phase.reason)
                ? [{ buttonType: "primary" as const, content: t("androidSdk.retry"), onClick: startBuild, autoFocus: true }]
                : []),
              { buttonType: "default" as const, content: t("androidSdk.close"), onClick: onSkip },
            ]
          : []),
        ...(phase.kind === "manual"
          ? [{ buttonType: "default" as const, content: t("androidSdk.close"), onClick: onSkip, autoFocus: true }]
          : []),
      ]}
    />
  );
}
