// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Copy, ExternalLink, LifeBuoy } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, buttonVariants } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Disclosure } from "@/components/ui/disclosure";
import { getDiagnostics } from "@/lib/api";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { copyToClipboard, ISSUE_FORM_URL } from "@/lib/diagnostics";
import { useToast } from "@/lib/toast";
import { cn } from "@/lib/utils";

/**
 * A finished scan's summary is fixed, so it is fetched once per scan and kept:
 * moving between result sections remounts the panel, and a second `docker info`
 * behind each remount is not worth it. Only summaries built from a run id are
 * kept (one built from an on-screen error has no id to key on).
 */
const summaryCache = new Map<string, string>();

/**
 * "Report a problem": the diagnostics summary of a finished scan (succeeded or
 * failed), shown in full on screen, with one button that puts exactly that text
 * on the clipboard and a link to the issue form. Nothing is sent anywhere: the
 * user reads it, copies it, and pastes it into the issue themselves.
 *
 * Folded like the run log below it, so a healthy result stays as it was; a
 * failed scan opens it (`defaultOpen`), because that is when it is wanted.
 * The summary is fetched when the panel is first opened, not before.
 *
 * `scanId` is the finished scan's run id. A scan that failed before it had a run
 * folder passes none plus the error already on screen (`errorMessage`), and the
 * server then returns the environment section with that error.
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
  const { toast } = useToast();
  const [opened, setOpened] = useState(defaultOpen);
  const [text, setText] = useState<string | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "failed">("idle");
  const [copyBlocked, setCopyBlocked] = useState(false);

  useEffect(() => {
    if (!opened || IS_STATIC_DEMO) return;
    const cached = scanId ? summaryCache.get(scanId) : undefined;
    if (cached !== undefined) {
      setText(cached);
      setState("ready");
      return;
    }
    let cancelled = false;
    setState("loading");
    setCopyBlocked(false);
    void getDiagnostics(scanId, errorMessage).then((value) => {
      if (cancelled) return;
      if (value !== null && scanId) summaryCache.set(scanId, value);
      setText(value);
      setState(value === null ? "failed" : "ready");
    });
    return () => {
      cancelled = true;
    };
  }, [opened, scanId, errorMessage]);

  // The demo has no server to build a summary; the help menu still links the form.
  if (IS_STATIC_DEMO) return null;

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
    <Card className="animate-fade-in" data-testid="report-problem">
      <Disclosure
        size="md"
        defaultOpen={defaultOpen}
        onToggle={(open) => open && setOpened(true)}
        summaryClassName="p-6 text-base font-semibold tracking-tight"
        summary={
          <span className="flex items-center gap-2">
            <LifeBuoy className="h-4 w-4 text-muted-foreground" aria-hidden />
            {t("report.open")}
          </span>
        }
      >
        <div className="space-y-3 px-6 pb-6">
          <p className="text-sm text-foreground/70">{t("report.intro")}</p>
          {/* Present from the start so a screen reader announces the change. */}
          <div className="sr-only" aria-live="polite">
            {state === "ready" ? t("report.ready") : ""}
          </div>
          {state === "loading" && (
            <p className="text-sm text-foreground/70">{t("report.loading")}</p>
          )}
          {state === "failed" && (
            <p className="text-sm text-foreground/70">{t("report.loadFailed")}</p>
          )}
          {state === "ready" && text !== null && (
            <textarea
              readOnly
              value={text}
              rows={Math.min(18, text.split("\n").length + 1)}
              aria-label={t("report.label")}
              data-testid="report-text"
              className="w-full resize-y rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed text-foreground/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
            />
          )}
          {copyBlocked && (
            <p role="status" className="text-sm text-foreground/70">
              {t("report.copyFailed")}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button type="button" onClick={copy} disabled={state !== "ready"}>
              <Copy className="h-4 w-4" aria-hidden />
              {t("report.copy")}
            </Button>
            <a
              href={ISSUE_FORM_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={cn(buttonVariants({ variant: "outline" }))}
            >
              <ExternalLink className="h-4 w-4" aria-hidden />
              {t("report.openIssue")}
            </a>
          </div>
        </div>
      </Disclosure>
    </Card>
  );
}
