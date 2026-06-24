import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

export type RunStatus = "running" | "done" | "error";

interface Props {
  logs: string[];
  status: RunStatus;
}

export function ProgressLog({ logs, status }: Props) {
  const { t } = useTranslation();
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // No real percentage from the backend — approximate from log volume while
  // running, then snap to 100% on completion.
  const value = status === "running" ? Math.min(92, 8 + logs.length * 2) : 100;

  return (
    <Card className="animate-fade-in">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t("progress.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <Progress
          value={value}
          aria-label={t("progress.title")}
          indicatorClassName={cn(
            status === "error" && "bg-destructive",
            status === "done" && "bg-emerald-500",
          )}
        />
        <div
          role="log"
          aria-label={t("progress.title")}
          tabIndex={0}
          className="h-72 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
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
          <div ref={endRef} />
        </div>
      </CardContent>
    </Card>
  );
}
