import { Plus } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { AppShell } from "./AppShell";
import { NewScan } from "./NewScan";
import { ProgressLog } from "./ProgressLog";
import { ResultSection } from "./ResultSections";
import { ScanRunning } from "./ScanRunning";
import { Button } from "@/components/ui/button";
import {
  deleteScan,
  getCapabilities,
  listScans,
  loadScan,
  startScan,
  type Capabilities,
  type DoneEvent,
  type RecentScan,
  type ScanParams,
} from "@/lib/api";
import {
  type RecentScanLink,
  type SectionId,
  visibleSectionIds,
} from "@/lib/nav";
import { deriveScanContext, sectionCounts } from "@/lib/results";

/** Map a stored scan to the Sidebar's Recent link shape. */
function toRecentLink(s: RecentScan): RecentScanLink {
  const sev = s.maxSeverity;
  return {
    id: s.id,
    label: s.version ? `${s.project} · ${s.version}` : s.project,
    topSeverity:
      sev === "CRITICAL" || sev === "HIGH" || sev === "MEDIUM" || sev === "LOW"
        ? sev
        : "NONE",
  };
}

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
  const [recent, setRecent] = useState<RecentScan[]>([]);

  // The live scan's SSE stream. Held so leaving the running view (new scan,
  // opening a past scan) can close it — otherwise a backgrounded scan finishes
  // later and hijacks whatever the user is now looking at.
  const streamRef = useRef<EventSource | null>(null);
  const closeStream = () => {
    streamRef.current?.close();
    streamRef.current = null;
  };

  const refreshRecent = () => listScans().then(setRecent);

  useEffect(() => {
    getCapabilities().then(setCapabilities);
    void refreshRecent();
  }, []);

  // Section navigation drives the browser history so the back button steps
  // through visited sections (the result stays in memory — only the active
  // section is restored from the URL hash).
  const selectSection = useCallback((id: SectionId) => {
    setActiveSection(id);
    window.history.pushState({ section: id }, "", `#${id}`);
  }, []);

  useEffect(() => {
    const onPop = () => {
      const id = window.location.hash.slice(1) as SectionId;
      setActiveSection(id || "overview");
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  // Close the live scan stream if the app unmounts.
  useEffect(() => () => streamRef.current?.close(), []);

  const recentLinks = useMemo(() => recent.map(toRecentLink), [recent]);

  // Re-open a past scan from the Recent list. Abandons any in-flight scan so it
  // can't overwrite the past result we're about to show.
  const openRecent = (id: string) => {
    closeStream();
    void loadScan(id).then((done) => {
      if (!done) return;
      const meta = recent.find((s) => s.id === id);
      setLogs([]);
      setResult(done);
      setStatus(done.ok ? "done" : "error");
      setActiveSection("overview");
      setProjectLabel(
        meta ? (meta.version ? `${meta.project} · ${meta.version}` : meta.project) : undefined,
      );
    });
  };

  // Delete a past scan (its artifacts) and refresh the Recent list.
  const deleteRecent = (id: string) => {
    void deleteScan(id).then(() => void refreshRecent());
  };

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
    closeStream(); // drop any previous stream before starting a new one
    setStatus("running");
    setLogs([]);
    setResult(null);
    setActiveSection("overview");
    setProjectLabel(
      params.version ? `${params.project} · ${params.version}` : params.project,
    );
    streamRef.current = startScan(params, {
      onLog: (line) => setLogs((prev) => [...prev, line]),
      onDone: (done) => {
        streamRef.current = null;
        setResult(done);
        setStatus(done.ok ? "done" : "error");
        void refreshRecent(); // the finished scan is now in history
      },
      onError: (message) => {
        if (message) setLogs((prev) => [...prev, `✖ ${message}`]);
        setStatus((s) => (s === "running" ? "error" : s));
      },
    });
  };

  const newScan = () => {
    closeStream();
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
      onSelectSection={selectSection}
      counts={counts}
      showSections={Boolean(result)}
      recent={recentLinks}
      onSelectRecent={openRecent}
      onDeleteRecent={deleteRecent}
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
      ) : !result ? (
        <div className="mx-auto max-w-5xl px-6 py-8">
          <ScanRunning
            logs={logs}
            status={status === "error" ? "error" : "running"}
            projectLabel={projectLabel}
          />
        </div>
      ) : (
        <div className="mx-auto max-w-6xl space-y-6 px-6 py-8">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              {t(`nav.${activeSection}`)}
            </h1>
            <span
              className={
                result.ok
                  ? "rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-300"
                  : "rounded-full bg-destructive/10 px-2 py-0.5 text-xs font-medium text-destructive"
              }
            >
              {result.ok ? t("result.succeeded") : t("result.failed")}
            </span>
          </div>

          <ResultSection
            section={activeSection}
            result={result}
            onNavigate={setActiveSection}
          />

          {activeSection === "overview" && (
            <ProgressLog logs={logs} status={status} collapsible />
          )}
        </div>
      )}
    </AppShell>
  );
}
