// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { AlertIcon, ChevronRightIcon, CopyIcon } from "@primer/octicons-react";
import { Button, Label } from "@primer/react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { copyToClipboard } from "@/lib/diagnostics";
import { useToast } from "@/lib/toast";

import "./progress/scan-progress.css";

export type RunStatus = "running" | "done" | "error";

interface Props {
  logs: string[];
  status: RunStatus;
  /**
   * Start folded. Used on the result screen, where the log is reference
   * material under every section rather than the focus; the live run keeps it
   * open. `open` wins when both are given.
   */
  collapsible?: boolean;
  /** Open or closed, set by the caller (a failed run opens it only when the cause is unknown). */
  open?: boolean;
  /** The scanner's own message, shown as received above the log. */
  serverMessage?: string | null;
}

/** How close to the end still counts as "at the end" (px). */
const END_SLACK = 8;

/**
 * The run log: lines as the stream delivers them in a focusable `role=log` box
 * (resizable, wrapping), the copy button with its caution, and a note when the
 * browser blocks the clipboard. The box follows new lines only while the reader
 * is at its end; scrolling up to read stops it, and returning to the end
 * resumes. The box scrolls itself, never the page (no scrollIntoView).
 */
export function ProgressLog({ logs, status, collapsible = false, open, serverMessage }: Props) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const box = useRef<HTMLDivElement>(null);
  const atEnd = useRef(true);
  // Set by the reader's own input (wheel, touch, keys, a press on the scrollbar).
  // A scroll event with no such input came from the box growing or from our own
  // jump to its end, and says nothing about where the reader wants to be.
  const userInput = useRef(false);
  const pressed = useRef(false);
  const [copyBlocked, setCopyBlocked] = useState(false);

  useEffect(() => {
    const b = box.current;
    if (b && atEnd.current) b.scrollTop = b.scrollHeight;
    if (!pressed.current) userInput.current = false;
  }, [logs]);

  useEffect(() => {
    const up = () => {
      pressed.current = false;
    };
    window.addEventListener("pointerup", up);
    return () => window.removeEventListener("pointerup", up);
  }, []);

  // Copies the lines exactly as they are shown, so what lands on the clipboard
  // is what the reader just saw.
  const copyLog = async () => {
    if (await copyToClipboard(logs.join("\n"))) {
      setCopyBlocked(false);
      toast(t("report.logCopied"));
    } else {
      // A non-secure page (opened over a network address) has no clipboard API:
      // say so instead of doing nothing.
      setCopyBlocked(true);
    }
  };

  return (
    <details className="bl-box bl-fold" open={open ?? !collapsible} data-testid="run-log">
      <summary>
        <span className="bl-fold-chev" aria-hidden>
          <ChevronRightIcon size={16} />
        </span>
        <h2>{t("progress.title")}</h2>
        {/* How the run ended, in words: the old progress bar's finished and failed colours. */}
        <Label variant={status === "error" ? "danger" : status === "done" ? "success" : "accent"} data-testid="run-log-status">
          {t(status === "error" ? "run.logFailed" : status === "done" ? "run.logDone" : "run.logRunning")}
        </Label>
        <span className="bl-fold-count">{t("run.logLines", { count: logs.length })}</span>
      </summary>
      <div className="bl-fold-body">
        {serverMessage && (
          <div>
            <div className="bl-muted bl-strong" style={{ fontSize: "var(--text-body-size-small)" }}>
              {t("run.serverMessage")}
            </div>
            <pre className="bl-log-message" data-testid="run-server-message">
              {serverMessage}
            </pre>
          </div>
        )}
        <div
          ref={box}
          role="log"
          aria-label={t("progress.title")}
          tabIndex={0}
          className="bl-log"
          data-live={status === "running"}
          onWheel={() => (userInput.current = true)}
          onTouchMove={() => (userInput.current = true)}
          onKeyDown={() => (userInput.current = true)}
          onPointerDown={() => {
            userInput.current = true;
            pressed.current = true;
          }}
          onScroll={(e) => {
            if (!userInput.current) return;
            const b = e.currentTarget;
            atEnd.current = b.scrollHeight - b.scrollTop - b.clientHeight < END_SLACK;
          }}
        >
          {logs.length === 0 ? (
            <p className="bl-log-empty">{t("progress.waiting")}</p>
          ) : (
            logs.map((line, i) => <div key={i}>{line}</div>)
          )}
        </div>
        {logs.length > 0 && (
          <>
            <div className="bl-log-tools">
              <Button size="small" leadingVisual={CopyIcon} onClick={copyLog}>
                {t("report.copyLog")}
              </Button>
              <span className="bl-log-hint">
                <AlertIcon size={14} />
                {t("report.logHint")}
              </span>
            </div>
            {copyBlocked && (
              <p role="status" className="bl-log-note">
                {t("report.logCopyFailed")}
              </p>
            )}
          </>
        )}
        {status === "running" && <p className="bl-log-note">{t("run.logFollow")}</p>}
      </div>
    </details>
  );
}
