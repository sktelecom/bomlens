import { Plus } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { AppShell } from "./AppShell";
import { NewScan } from "./NewScan";
import { ProgressLog } from "./ProgressLog";
import { ResultSection } from "./ResultSections";
import { Button } from "@/components/ui/button";
import {
  getCapabilities,
  startScan,
  type Capabilities,
  type DoneEvent,
  type ScanParams,
} from "@/lib/api";
import { type SectionId, visibleSectionIds } from "@/lib/nav";
import { deriveScanContext, sectionCounts } from "@/lib/results";

type Status = "idle" | "running" | "done" | "error";

/**
 * The new shell application (behind `?ui=next`). Same scan state machine as the
 * classic app — the form, the SSE live log and the result content are reused
 * verbatim — re-laid-out into the AppShell: results move from tabs to the
 * left-rail sections. Phase 1 target is zero regression in what's shown.
 */
export function NextApp() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<Status>("idle");
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<DoneEvent | null>(null);
  const [projectLabel, setProjectLabel] = useState<string>();
  const [activeSection, setActiveSection] = useState<SectionId>("overview");
  const [capabilities, setCapabilities] = useState<Capabilities>({
    firmware: false,
    docker: true,
  });

  useEffect(() => {
    getCapabilities().then(setCapabilities);
  }, []);

  const scan = useMemo(() => deriveScanContext(result), [result]);
  const counts = useMemo(
    () => (result ? sectionCounts(result) : undefined),
    [result],
  );

  // Keep the active section valid for the current result (e.g. a new scan
  // without a dependency graph must not stay on the Dependencies section).
  useEffect(() => {
    if (!result) return;
    const available = visibleSectionIds(scan);
    if (!available.includes(activeSection)) setActiveSection("overview");
  }, [result, scan, activeSection]);

  const run = (params: ScanParams) => {
    setStatus("running");
    setLogs([]);
    setResult(null);
    setActiveSection("overview");
    setProjectLabel(
      params.version ? `${params.project} · ${params.version}` : params.project,
    );
    startScan(params, {
      onLog: (line) => setLogs((prev) => [...prev, line]),
      onDone: (done) => {
        setResult(done);
        setStatus(done.ok ? "done" : "error");
      },
      onError: (message) => {
        if (message) setLogs((prev) => [...prev, `✖ ${message}`]);
        setStatus((s) => (s === "running" ? "error" : s));
      },
    });
  };

  const newScan = () => {
    setStatus("idle");
    setLogs([]);
    setResult(null);
    setProjectLabel(undefined);
    setActiveSection("overview");
  };

  return (
    <AppShell
      scan={scan}
      activeSection={activeSection}
      onSelectSection={setActiveSection}
      counts={counts}
      showSections={Boolean(result)}
      projectLabel={status === "idle" ? undefined : projectLabel}
      topBarActions={
        status !== "idle" ? (
          <Button type="button" variant="outline" size="sm" onClick={newScan}>
            <Plus className="mr-1.5 h-4 w-4" />
            {t("shell.newScan")}
          </Button>
        ) : undefined
      }
    >
      {status === "idle" ? (
        <div className="mx-auto max-w-5xl px-6 py-8">
          <h1 className="mb-6 text-xl font-semibold tracking-tight text-foreground">
            {t("shell.newScan")}
          </h1>
          <NewScan running={false} capabilities={capabilities} onRun={run} />
        </div>
      ) : (
        <div className="mx-auto max-w-6xl space-y-6 px-6 py-8">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              {result ? t(`nav.${activeSection}`) : t("form.running")}
            </h1>
            {result && (
              <span
                className={
                  result.ok
                    ? "rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-300"
                    : "rounded-full bg-destructive/10 px-2 py-0.5 text-xs font-medium text-destructive"
                }
              >
                {result.ok ? t("result.succeeded") : t("result.failed")}
              </span>
            )}
          </div>

          {result && (
            <ResultSection
              section={activeSection}
              result={result}
              onNavigate={setActiveSection}
            />
          )}

          <ProgressLog logs={logs} status={status} />
        </div>
      )}
    </AppShell>
  );
}
