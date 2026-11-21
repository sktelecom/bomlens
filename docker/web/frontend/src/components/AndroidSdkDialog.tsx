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
  releaseTag,
  type AndroidSdkNeed,
} from "@/lib/androidSdk";

import { ProgressLog } from "./ProgressLog";
import { DialogHeader } from "./ShortcutsDialog";

type Phase =
  | { kind: "consent"; saveFailed?: boolean }
  | { kind: "confirm" }
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
  version,
  onReady,
  onSkip,
}: {
  need: AndroidSdkNeed;
  /** `capabilities.androidSdkBuild`; false means this run mode cannot build. */
  capabilityBuild: boolean | undefined;
  /** `capabilities.version`, to point the manual command at this release. */
  version?: string;
  /** The image is in place: start the scan again. */
  onReady: () => void;
  /** Leave without the image. */
  onSkip: () => void;
}) {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<Phase>(() => {
    const stage = firstStage(need, capabilityBuild);
    return stage === "manual" ? { kind: "manual" } : stage === "confirm" ? { kind: "confirm" } : { kind: "consent" };
  });
  const [logs, setLogs] = useState<string[]>([]);
  const stopRef = useRef<(() => void) | null>(null);
  const readyRef = useRef(onReady);
  readyRef.current = onReady;

  const startBuild = useCallback(() => {
    pendingRef.current = true;
    setLogs([]);
    setPhase({ kind: "building", step: 0, steps: 0 });
    stopRef.current = buildAndroidSdkImage(need.api, {
      onLog: (line) => setLogs((prev) => [...prev, line]),
      onProgress: (p) => setPhase({ kind: "building", step: p.step, steps: p.steps }),
      onDone: (d) => {
        stopRef.current = null;
        pendingRef.current = false;
        setPending(false);
        if (d.ok) readyRef.current();
        else setPhase({ kind: "failed", reason: failureReason(d.reason), detail: d.detail });
      },
    });
  }, [need.api]);

  // Set while a click is being handled, so a second press cannot open a second
  // build stream (the first one's stop function would be lost).
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);

  // Terms already on file: the start button comes first, since a build takes
  // time and disk. The image may have appeared since the scan asked (a build in
  // another window); then there is nothing to build.
  const begin = async () => {
    if (pendingRef.current) return;
    pendingRef.current = true;
    setPending(true);
    const s = await fetchAndroidSdkStatus(need.api);
    if (s?.present) readyRef.current();
    else startBuild();
  };

  // Closing the dialog while a build runs stops it.
  useEffect(
    () => () => {
      stopRef.current?.();
    },
    [],
  );

  const accept = async () => {
    if (pendingRef.current) return;
    pendingRef.current = true;
    setPending(true);
    const ok = await recordAndroidSdkConsent(need.termsUrl);
    if (!ok) {
      pendingRef.current = false;
      setPending(false);
      setPhase({ kind: "consent", saveFailed: true });
      return;
    }
    startBuild();
  };

  const cancelBuild = () => {
    stopRef.current?.();
    stopRef.current = null;
    pendingRef.current = false;
    setPending(false);
    void cancelAndroidSdkBuild(need.api);
    setPhase({ kind: "failed", reason: "cancelled" });
  };

  const leave = () => {
    if (phase.kind === "building") cancelBuild();
    onSkip();
  };

  const title = t("androidSdk.title");
  const building = phase.kind === "building";
  const tag = releaseTag(version);

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

            {phase.kind === "confirm" && (
              <>
                <p style={{ margin: 0 }} className="bl-muted">
                  {t("androidSdk.alreadyAccepted")}
                </p>
                <p style={{ margin: 0 }} data-testid="android-sdk-confirm">
                  {t("androidSdk.confirmStart", { image: need.image })}
                </p>
                <p style={{ margin: 0 }} className="bl-muted" data-testid="android-sdk-skip-note">
                  {t("androidSdk.skipNote")}
                </p>
              </>
            )}

            {phase.kind === "building" && (
              <>
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
                  {manualBuildCommand(need.api, need.image, version, need.hostBuildDir)}
                </code>
                {!tag && !need.hostBuildDir && <p style={{ margin: 0 }} className="bl-muted">{t("androidSdk.manualTagNote")}</p>}
              </>
            )}

            {phase.kind === "manual" && (
              <>
                <p style={{ margin: 0 }} data-testid="android-sdk-manual">
                  {t("androidSdk.manualOnly")}
                </p>
                <code className="bl-code" data-testid="android-sdk-command">
                  {manualBuildCommand(need.api, need.image, version, need.hostBuildDir)}
                </code>
                {!tag && !need.hostBuildDir && <p style={{ margin: 0 }} className="bl-muted">{t("androidSdk.manualTagNote")}</p>}
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
              // Focus starts on the safe choice: Enter must not accept legal terms.
              { buttonType: "primary" as const, content: t("androidSdk.accept"), onClick: () => void accept(), disabled: pending },
              { buttonType: "default" as const, content: t("androidSdk.skip"), onClick: onSkip, autoFocus: true },
            ]
          : []),
        ...(phase.kind === "confirm"
          ? [
              { buttonType: "primary" as const, content: t("androidSdk.startBuild"), onClick: () => void begin(), disabled: pending },
              { buttonType: "default" as const, content: t("androidSdk.skip"), onClick: onSkip, autoFocus: true },
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
