import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { AppShell } from "./AppShell";
import { NewScan } from "./NewScan";
import { ProgressLog } from "./ProgressLog";
import { RecentScans } from "./RecentScans";
import { ResultSection } from "./ResultSections";
import { ScanRunning } from "./ScanRunning";
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
  type ScanProgress,
} from "@/lib/api";
import {
  type RecentScanLink,
  type SectionId,
  visibleSectionIds,
} from "@/lib/nav";
import { homeHash, newHash, parseHash, scanHash } from "@/lib/route";
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

/** Scan-kind label key for the result-header subtitle, keyed by the CycloneDX
 *  root component type (available on re-open, unlike the scan MODE). AI wins,
 *  handled separately; unknown/absent types fall back to a generic SBOM. */
const SCAN_KIND_KEY: Record<string, string> = {
  application: "result.kindSource",
  library: "result.kindSource",
  framework: "result.kindSource",
  firmware: "result.kindFirmware",
  container: "result.kindImage",
  "operating-system": "result.kindRootfs",
  data: "result.kindAnalyze",
};

/**
 * The new shell application (behind `?ui=next`). Same scan state machine as the
 * classic app — the form, the SSE live log and the result content are reused
 * verbatim — re-laid-out into the AppShell: results move from tabs to the
 * left-rail sections.
 *
 * The URL hash is the single source of truth for what's shown:
 *   `#/`                    → the New scan screen (idle),
 *   `#/scan/<id>`           → that scan's Overview,
 *   `#/scan/<id>/<section>` → that scan's section.
 * Every navigation element is a real `<a href="#/…">`, so the browser handles
 * open-in-new-tab; a `hashchange` listener drives the in-app transition.
 */
export function NextApp() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<Status>("idle");
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [result, setResult] = useState<DoneEvent | null>(null);
  const [projectInfo, setProjectInfo] = useState<{
    name: string;
    version?: string;
  }>();
  const [activeSection, setActiveSection] = useState<SectionId>("overview");
  // Which idle screen is shown: Recent scans (home/logo) or New scan (#/new).
  const [homeView, setHomeView] = useState<"recent" | "new">("recent");
  const [capabilities, setCapabilities] = useState<Capabilities>({
    firmware: false,
    docker: true,
  });
  const [recent, setRecent] = useState<RecentScan[]>([]);

  // The scan id currently held in `result` — so the hash router can tell a
  // section change (no reload) from opening a different scan (reload).
  const loadedIdRef = useRef<string | null>(null);
  // The id of an in-flight live scan, so its `done` can set the URL.
  const runningIdRef = useRef<string | null>(null);

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

  // Reset to the idle New scan screen (in-memory state only; the URL is set by
  // the caller — clicking a `#/` anchor — or by the hash router).
  const resetToHome = useCallback(() => {
    closeStream();
    runningIdRef.current = null;
    loadedIdRef.current = null;
    setStatus("idle");
    setLogs([]);
    setResult(null);
    setProjectInfo(undefined);
    setActiveSection("overview");
  }, []);

  // Show a past/finished scan for the given id + section. Loads it if it isn't
  // already the current result; falls back home if its artifacts are gone.
  const showScan = useCallback(
    (id: string, section: SectionId) => {
      // Same scan already loaded → just switch the section (no reload, no flash).
      if (loadedIdRef.current === id) {
        setActiveSection(section);
        return;
      }
      closeStream();
      runningIdRef.current = null;
      void loadScan(id).then((done) => {
        if (parseHash(window.location.hash).kind !== "scan") return; // navigated away
        if (!done) {
          // Artifacts missing (e.g. a live-only scan that was never stored, or a
          // deleted one) — fall back to the New scan screen.
          window.location.hash = homeHash();
          return;
        }
        loadedIdRef.current = id;
        setLogs([]);
        setResult(done);
        setStatus(done.ok ? "done" : "error");
        setActiveSection(section);
        const meta = recent.find((s) => s.id === id);
        setProjectInfo(
          meta
            ? { name: meta.project, version: meta.version || undefined }
            : { name: id },
        );
      });
    },
    [recent],
  );

  // The hash router: parse on mount and on every hashchange. Skip while a live
  // scan is running — that view is owned by the run() state machine, not the URL
  // (there is no id yet), and run()'s done handler sets the URL when it finishes.
  const route = useCallback(() => {
    if (status === "running") return;
    const parsed = parseHash(window.location.hash);
    if (parsed.kind === "recent" || parsed.kind === "new") {
      setHomeView(parsed.kind);
      if (loadedIdRef.current !== null || status !== "idle") resetToHome();
      return;
    }
    showScan(parsed.id, parsed.section);
  }, [status, resetToHome, showScan]);

  useEffect(() => {
    route();
    window.addEventListener("hashchange", route);
    return () => window.removeEventListener("hashchange", route);
  }, [route]);

  // Close the live scan stream if the app unmounts.
  useEffect(() => () => streamRef.current?.close(), []);

  const recentLinks = useMemo(() => recent.map(toRecentLink), [recent]);

  // Delete a past scan (its artifacts) and refresh the Recent list.
  const deleteRecent = (id: string) => {
    void deleteScan(id).then(() => {
      void refreshRecent();
      // If we're viewing the scan we just deleted, drop back to New scan.
      if (loadedIdRef.current === id) window.location.hash = homeHash();
    });
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
    loadedIdRef.current = null;
    runningIdRef.current = null;
    setStatus("running");
    setLogs([]);
    setProgress(null);
    setResult(null);
    setActiveSection("overview");
    setProjectInfo({
      name: params.project,
      version: params.version || undefined,
    });
    streamRef.current = startScan(params, {
      onLog: (line) => setLogs((prev) => [...prev, line]),
      onProgress: (p) => setProgress(p),
      onDone: (done) => {
        streamRef.current = null;
        setResult(done);
        setStatus(done.ok ? "done" : "error");
        void refreshRecent(); // the finished scan is now in history
        // Point the URL at the finished scan so it has a shareable/reopenable
        // address. Prefer the server-provided id (exact artifact prefix).
        const id = done.id;
        if (id) {
          loadedIdRef.current = id;
          runningIdRef.current = null;
          window.history.replaceState(null, "", scanHash(id));
        }
      },
      onError: (message) => {
        if (message) setLogs((prev) => [...prev, `✖ ${message}`]);
        setStatus((s) => (s === "running" ? "error" : s));
      },
    });
  };

  const isHome = status === "idle";

  return (
    <AppShell
      scan={scan}
      activeSection={activeSection}
      activeScanId={loadedIdRef.current}
      counts={counts}
      showSections={Boolean(result)}
      recent={recentLinks}
      onDeleteRecent={deleteRecent}
      homeHref={homeHash()}
      showHomeLink={!(isHome && homeView === "recent")}
      atRecent={isHome && homeView === "recent"}
      project={isHome ? undefined : projectInfo}
    >
      {isHome ? (
        <div className="mx-auto max-w-6xl px-6 py-8">
          {homeView === "recent" ? (
            <RecentScans
              scans={recent}
              newHref={newHash()}
              onDelete={deleteRecent}
            />
          ) : (
            <NewScan running={false} capabilities={capabilities} onRun={run} />
          )}
        </div>
      ) : !result ? (
        <div className="mx-auto max-w-5xl px-6 py-8">
          <ScanRunning
            logs={logs}
            status={status === "error" ? "error" : "running"}
            progress={status === "running" ? progress : null}
            projectLabel={
              projectInfo &&
              (projectInfo.version
                ? `${projectInfo.name} · ${projectInfo.version}`
                : projectInfo.name)
            }
          />
        </div>
      ) : (
        <div className="mx-auto max-w-6xl space-y-6 px-6 py-8">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-semibold tracking-tight text-foreground">
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
            <p className="mt-1.5 text-sm text-muted-foreground">
              {t(
                scan.isAiScan
                  ? "result.kindAi"
                  : (SCAN_KIND_KEY[result.sbom?.componentType ?? ""] ??
                      "result.kindSbom"),
              )}
            </p>
          </div>

          <ResultSection
            section={activeSection}
            result={result}
            scanId={loadedIdRef.current}
          />

          {/* The run log is reference material for the run you just watched.
              A scan re-opened from history has no logs (logs is reset on load),
              so don't show an empty disclosure — only render while running or
              when there is something to show. */}
          {activeSection === "overview" &&
            (status === "running" || logs.length > 0) && (
              <ProgressLog logs={logs} status={status} collapsible />
            )}
        </div>
      )}
    </AppShell>
  );
}
