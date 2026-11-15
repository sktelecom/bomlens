// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon, IssueOpenedIcon } from "@primer/octicons-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { IS_STATIC_DEMO } from "@/lib/demo";

import { ReportProblemBody } from "./ReportProblemDialog";

import "./progress/scan-progress.css";

/**
 * "Report a problem" as a folded panel: the diagnostics summary in full, one
 * button that puts exactly that text on the clipboard and a link to the issue
 * form. Nothing is sent anywhere: the reader reads it, copies it and pastes it
 * into the issue. A failed scan opens it (`defaultOpen`), because that is when
 * it is wanted; the summary is fetched when the panel is first opened.
 *
 * `scanId` is the finished scan's run id. A scan that failed before it had a
 * run folder passes none plus the error already on screen (`errorMessage`), and
 * the server then returns the environment section with that error.
 */
export function ReportProblem({
  scanId,
  errorMessage,
  defaultOpen = false,
}: {
  scanId?: string | null;
  errorMessage?: string | null;
  defaultOpen?: boolean;
}) {
  const { t } = useTranslation();
  const [opened, setOpened] = useState(defaultOpen);

  // The demo has no server to build a summary; the help menu still links the form.
  if (IS_STATIC_DEMO) return null;

  return (
    <details
      className="bl-box bl-fold"
      open={defaultOpen || undefined}
      onToggle={(e) => {
        if ((e.currentTarget as HTMLDetailsElement).open) setOpened(true);
      }}
      data-testid="report-panel"
    >
      <summary>
        <span className="bl-fold-chev" aria-hidden>
          <ChevronRightIcon size={16} />
        </span>
        <IssueOpenedIcon size={16} />
        <h2>{t("report.open")}</h2>
      </summary>
      <div className="bl-fold-body">
        {opened && <ReportProblemBody scanId={scanId} errorMessage={errorMessage} />}
      </div>
    </details>
  );
}
