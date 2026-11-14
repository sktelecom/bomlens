// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CopyIcon, LinkExternalIcon } from "@primer/octicons-react";
import { Button, Dialog, Textarea } from "@primer/react";
import type { RefObject } from "react";
import { useTranslation } from "react-i18next";

import { copyToClipboard, ISSUE_FORM_URL } from "@/lib/diagnostics";
import { useToast } from "@/lib/toast";

import { useDiagnosticsSummary } from "./ReportProblem";
import { DialogHeader } from "./ShortcutsDialog";

/**
 * The diagnostics summary in full, one button that copies exactly that text and
 * a link to the issue form. Nothing is sent anywhere. The summary is fetched
 * when this mounts. Used by the Help menu's dialog and, expanded inline, by the
 * failed-scan banner (`inline` gives the elements their own test ids so the two
 * can be on screen together).
 */
export function ReportProblemBody({
  scanId,
  errorMessage,
  inline = false,
}: {
  scanId?: string | null;
  errorMessage?: string | null;
  inline?: boolean;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { text, state, copyBlocked, setCopyBlocked } = useDiagnosticsSummary(scanId, errorMessage, true);
  const suffix = inline ? "-inline" : "";
  const copy = async () => {
    if (text === null) return;
    if (await copyToClipboard(text)) {
      setCopyBlocked(false);
      toast(t("report.copied"));
    } else {
      setCopyBlocked(true);
    }
  };
  return (
    <div className="bl-stack-8" data-testid={`report-problem${suffix}`}>
      <p className="bl-flat">{t("report.intro")}</p>
      {/* Present from the start so a screen reader announces the change. */}
      <div className="bl-visually-hidden" aria-live="polite">
        {state === "ready" ? t("report.ready") : ""}
      </div>
      {state === "loading" && <p className="bl-flat bl-muted">{t("report.loading")}</p>}
      {state === "failed" && <p className="bl-flat bl-muted">{t("report.loadFailed")}</p>}
      {state === "ready" && text !== null && (
        <Textarea
          readOnly
          value={text}
          rows={Math.min(inline ? 10 : 18, text.split("\n").length + 1)}
          aria-label={t("report.label")}
          data-testid={`report-text${suffix}`}
          block
          resize="vertical"
          className="bl-mono"
        />
      )}
      {copyBlocked && (
        <p role="status" className="bl-flat bl-muted">
          {t("report.copyFailed")}
        </p>
      )}
      <div className="bl-inline bl-wrap">
        <Button type="button" onClick={copy} disabled={state !== "ready"} leadingVisual={CopyIcon}>
          {t("report.copy")}
        </Button>
        <Button as="a" href={ISSUE_FORM_URL} target="_blank" rel="noreferrer noopener" trailingVisual={LinkExternalIcon}>
          {t("report.openIssue")}
        </Button>
      </div>
    </div>
  );
}

/**
 * "Report a problem" as a dialog, opened from the Help menu and from the failed
 * scan's banner. Focus returns to `returnFocusRef` (the control that opened it)
 * when it closes.
 */
export function ReportProblemDialog({
  scanId,
  errorMessage,
  onClose,
  returnFocusRef,
}: {
  scanId?: string | null;
  errorMessage?: string | null;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement | null>;
}) {
  const { t } = useTranslation();
  return (
    <Dialog
      title={t("report.open")}
      onClose={onClose}
      width="large"
      returnFocusRef={returnFocusRef as RefObject<HTMLElement>}
      renderHeader={({ dialogLabelId }) => <DialogHeader id={dialogLabelId} title={t("report.open")} onClose={onClose} />}
      renderBody={() => (
        <Dialog.Body>
          <ReportProblemBody scanId={scanId} errorMessage={errorMessage} />
        </Dialog.Body>
      )}
    />
  );
}
