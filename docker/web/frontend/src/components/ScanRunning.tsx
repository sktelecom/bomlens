import { CircleCheck, CircleDashed, Loader2 } from "lucide-react";
import { useTranslation } from "react-i18next";

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
 */
export function ScanRunning({
  logs,
  status,
  progress,
  projectLabel,
}: {
  logs: string[];
  status: Status;
  progress?: ScanProgress | null;
  projectLabel?: string;
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
      </div>

      {!failed && (
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
