import {
  CircleCheck,
  CircleDashed,
  Loader2,
  Plus,
  RotateCcw,
  TriangleAlert,
  X,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { ScanProgress } from "@/lib/api";
import { SCAN_STAGES, stageStatuses } from "@/lib/scanProgress";
import { cn } from "@/lib/utils";

import { ProgressLog } from "./ProgressLog";

type Status = "running" | "done" | "error";

/**
 * Scan-running view: the pipeline stages (derived from the live log markers),
 * a running headline, and the SSE log itself. The stages are honest — each
 * lights up only once its marker appears. Partial results are not streamed by
 * the backend, so the log is the live surface until the done event arrives.
 *
 * On failure the stages give way to an error card that surfaces the message
 * (instead of leaving it buried in the log) and offers a way out — retry the
 * same scan when it's safe to replay, and always a New scan.
 */
export function ScanRunning({
  logs,
  status,
  progress,
  projectLabel,
  errorMessage,
  newScanHref,
  onRetry,
  onCancel,
}: {
  logs: string[];
  status: Status;
  progress?: ScanProgress | null;
  projectLabel?: string;
  /** Failure message to surface prominently (falls back to a generic line). */
  errorMessage?: string | null;
  /** Hash for the New scan screen — the always-available recovery CTA. */
  newScanHref?: string;
  /** Re-run the same scan; only provided when the params are safe to replay. */
  onRetry?: () => void;
  /** Stop a running scan (closes the stream; the backend ends the process). */
  onCancel?: () => void;
}) {
  const { t } = useTranslation();
  const failed = status === "error";
  const statuses = stageStatuses(logs, status !== "running");

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          {failed ? t("result.failed") : t("form.running")}
        </h1>
        {projectLabel && (
          <span className="truncate text-sm text-muted-foreground">{projectLabel}</span>
        )}
        {!failed && onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className={cn(buttonVariants({ variant: "outline", size: "sm" }), "ml-auto")}
          >
            <X className="h-4 w-4" aria-hidden />
            {t("run.cancel")}
          </button>
        )}
      </div>

      {failed ? (
        <Card role="alert" className="border-destructive/40 bg-destructive/5">
          <CardContent className="space-y-3 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <TriangleAlert className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
              {t("run.failedTitle")}
            </div>
            <p className="text-sm text-muted-foreground">
              {errorMessage || t("run.failedBody")}
            </p>
            <div className="flex flex-wrap gap-2">
              {onRetry && (
                <button type="button" onClick={onRetry} className={cn(buttonVariants())}>
                  <RotateCcw className="h-4 w-4" aria-hidden />
                  {t("run.retry")}
                </button>
              )}
              {newScanHref && (
                <a
                  href={newScanHref}
                  className={cn(
                    buttonVariants({ variant: onRetry ? "outline" : "default" }),
                  )}
                >
                  <Plus className="h-4 w-4" aria-hidden />
                  {t("shell.newScan")}
                </a>
              )}
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-4">
            <ol className="flex flex-col gap-2">
              {SCAN_STAGES.map((stage, i) => {
                const st = statuses[i];
                const Icon =
                  st === "done" ? CircleCheck : st === "active" ? Loader2 : CircleDashed;
                return (
                  <li key={stage.id} className="flex items-center gap-2.5 text-sm">
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        st === "done" && "text-risk-low",
                        st === "active" && "animate-spin text-brand",
                        st === "pending" && "text-muted-foreground/50",
                      )}
                      aria-hidden
                    />
                    <span className={st === "pending" ? "text-muted-foreground" : "text-foreground"}>
                      {t(stage.labelKey)}
                    </span>
                  </li>
                );
              })}
            </ol>
          </CardContent>
        </Card>
      )}

      <ProgressLog logs={logs} status={status} progress={progress} />
    </div>
  );
}
