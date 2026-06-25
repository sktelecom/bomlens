import { ChevronRight } from "lucide-react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import type { ScanProgress } from "@/lib/api";
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
  /**
   * Determinate progress from the backend (e.g. firmware CVE DB download). When
   * present while running, the bar shows the real percentage; otherwise the bar
   * falls back to the log-volume approximation used for ordinary scans.
   */
  progress?: ScanProgress | null;
}

export function ProgressLog({
  logs,
  status,
  collapsible = false,
  progress,
}: Props) {
  const { t } = useTranslation();
  const logBoxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Auto-scroll the log box itself — never scrollIntoView, which would also
    // scroll the page canvas to the bottom on mount.
    const box = logBoxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [logs]);

  // Determinate phases (e.g. the firmware CVE DB download) report a real
  // percent — use it. Otherwise there is no real percentage from the backend, so
  // approximate from log volume while running, then snap to 100% on completion.
  const determinate =
    status === "running" && progress?.phase === "cvedb";
  const value = determinate
    ? Math.min(100, Math.max(0, progress!.percent))
    : status === "running"
      ? Math.min(92, 8 + logs.length * 2)
      : 100;

  const body = (
    <>
      {determinate && (
        <p className="flex items-center justify-between text-xs font-medium text-foreground/70">
          <span>{t("progress.cvedbDownloading")}</span>
          <span>{Math.round(value)}%</span>
        </p>
      )}
      <Progress
        value={value}
        aria-label={t("progress.title")}
        indicatorClassName={cn(
          status === "error" && "bg-destructive",
          status === "done" && "bg-emerald-500",
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
    </>
  );

  if (collapsible) {
    return (
      <Card className="animate-fade-in">
        <details className="group">
          <summary className="flex cursor-pointer list-none items-center gap-2 p-6 text-base font-semibold tracking-tight [&::-webkit-details-marker]:hidden">
            <ChevronRight
              className="h-4 w-4 text-muted-foreground transition-transform duration-fast ease-out-soft group-open:rotate-90"
              aria-hidden
            />
            {t("progress.title")}
          </summary>
          <div className="space-y-3 px-6 pb-6">{body}</div>
        </details>
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
