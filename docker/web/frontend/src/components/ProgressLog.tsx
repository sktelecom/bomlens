// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Copy, TriangleAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { copyToClipboard } from "@/lib/diagnostics";
import { stageProgress } from "@/lib/scanProgress";
import { Disclosure } from "@/components/ui/disclosure";
import { useToast } from "@/lib/toast";
import { cn } from "@/lib/utils";

export type RunStatus = "running" | "done" | "error";

interface Props {
  logs: string[];
  status: RunStatus;
  /**
   * Render as a collapsed-by-default disclosure. Used on the result screen,
   * where the log is reference material under every section rather than the
   * focus — the live run (ScanRunning) keeps it expanded.
   */
  collapsible?: boolean;
}

export function ProgressLog({
  logs,
  status,
  collapsible = false,
}: Props) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const logBoxRef = useRef<HTMLDivElement>(null);
  const [copyBlocked, setCopyBlocked] = useState(false);

  useEffect(() => {
    // Auto-scroll the log box itself — never scrollIntoView, which would also
    // scroll the page canvas to the bottom on mount.
    const box = logBoxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [logs]);

  // There is no real percentage from the backend, so approximate from log
  // volume while running, then snap to 100% on completion.
  const value = status === "running" ? stageProgress(logs) : 100;

  // Copies the lines exactly as they are shown in the box, so what lands on the
  // clipboard is what the user just read.
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

  const body = (
    <>
      <Progress
        value={value}
        aria-label={t("progress.title")}
        indicatorClassName={cn(
          status === "error" && "bg-destructive",
          status === "done" && "bg-success-solid",
        )}
      />
      <div
        ref={logBoxRef}
        role="log"
        aria-label={t("progress.title")}
        tabIndex={0}
        className="h-72 min-h-40 max-h-[80vh] resize-y overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
      >
        {logs.length === 0 ? (
          // foreground/70 (not muted-foreground) clears AA on the muted log panel.
          <p className="text-foreground/70">{t("progress.waiting")}</p>
        ) : (
          logs.map((line, i) => (
            <div
              key={i}
              className="whitespace-pre-wrap break-all text-foreground/90"
            >
              {line}
            </div>
          ))
        )}
      </div>
      {logs.length > 0 && (
        <div className="space-y-2">
          <Button type="button" variant="outline" size="sm" onClick={copyLog}>
            <Copy className="h-4 w-4" aria-hidden />
            {t("report.copyLog")}
          </Button>
          <p className="flex items-start gap-2 text-sm text-foreground/80">
            <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-risk-medium" aria-hidden />
            {t("report.logHint")}
          </p>
          {copyBlocked && (
            <p role="status" className="text-sm text-foreground/70">
              {t("report.logCopyFailed")}
            </p>
          )}
        </div>
      )}
    </>
  );

  if (collapsible) {
    return (
      <Card className="animate-fade-in">
        <Disclosure
          size="md"
          summaryClassName="p-6 text-base font-semibold tracking-tight"
          summary={t("progress.title")}
        >
          <div className="space-y-3 px-6 pb-6">{body}</div>
        </Disclosure>
      </Card>
    );
  }

  return (
    <Card className="animate-fade-in">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t("progress.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">{body}</CardContent>
    </Card>
  );
}
