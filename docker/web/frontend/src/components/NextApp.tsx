import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { AppShell } from "./AppShell";
import { GlobalSearch } from "./GlobalSearch";
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
  type ScanConfig,
  type ScanParams,
  type ScanProgress,
  type Severity,
} from "@/lib/api";
import { type LicenseRiskTier } from "@/lib/licenses";
import {
  type RecentScanLink,
  type SectionId,
  visibleSectionIds,
} from "@/lib/nav";
import { homeHash, newHash, parseHash, scanHash } from "@/lib/route";
import { deriveScanContext, sectionCounts } from "@/lib/results";

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

/** Map a stored scan to the top bar's Recent-menu link shape. */
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
  // The failure message surfaced on the Scan-running screen when a scan can't
  // run (stream/launch error), so it isn't buried in the log.
  const [scanError, setScanError] = useState<string | null>(null);
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
  // A finished scan's config, parked here when the user hits "Re-scan" so the
  // New scan form can seed itself from it. The form reads it once on mount and
  // clears it, so a subsequent plain New scan starts blank.
  const [pendingRescan, setPendingRescan] = useState<ScanConfig | null>(null);
  // A navigation seed: route into a section with a filter pre-applied — a
  // global-search term, or an Overview risk-bar click (severity / license tier).
  // The section's own control re-seeds only when the value changes.
  const [seed, setSeed] = useState<{
    section: SectionId;
    term?: string;
    severity?: Severity;
    tier?: LicenseRiskTier;
  } | null>(null);

  // The scan id currently held in `result` — so the hash router can tell a
  // section change (no reload) from opening a different scan (reload).
  const loadedIdRef = useRef<string | null>(null);
  // The id of an in-flight live scan, so its `done` can set the URL.
  const runningIdRef = useRef<string | null>(null);
  // The params of the last started scan, so a failed run can be retried — but
  // only when they carry no single-use upload token or stashed credential.
  const lastParamsRef = useRef<ScanParams | null>(null);

  // The result-section heading. On a section change we move focus here so
  // keyboard and screen-reader users land on (and hear) the new section instead
  // of being left on the rail link. Skip the first run so we don't grab focus
  // on initial load.
  const headingRef = useRef<HTMLHeadingElement>(null);
  const didMountRef = useRef(false);

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

  // Run the router on mount and on real navigations (hashchange) only — never on
  // a bare status change. Re-running it on status change would, when a scan
  // started from #/new fails (status → error while the hash is still #/new),
  // call resetToHome() and dump the user back to an empty form, hiding the
  // failure. The ref keeps the listener pointed at the latest route().
  const routeRef = useRef(route);
  routeRef.current = route;
  useEffect(() => {
    const onHash = () => routeRef.current();
    onHash();
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Move focus to the section heading when the active section changes, so a
  // keyboard/screen-reader user follows the content instead of staying on the
  // rail link. Skipped on first mount to avoid stealing initial focus.
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    headingRef.current?.focus();
  }, [activeSection]);

  // Close the live scan stream if the app unmounts.
  useEffect(() => () => streamRef.current?.close(), []);

  // Delete a past scan (its artifacts) and refresh the Recent list.
  const deleteRecent = (id: string) => {
    void deleteScan(id).then(() => {
      void refreshRecent();
      // If we're viewing the scan we just deleted, drop back to New scan.
      if (loadedIdRef.current === id) window.location.hash = homeHash();
    });
  };

  const scan = useMemo(() => deriveScanContext(result), [result]);
  const recentLinks = useMemo(() => recent.map(toRecentLink), [recent]);
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
    lastParamsRef.current = params;
    setStatus("running");
    setLogs([]);
    setScanError(null);
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
        if (message) {
          setLogs((prev) => [...prev, `✖ ${message}`]);
          setScanError(message);
        }
        setStatus((s) => (s === "running" ? "error" : s));
      },
    });
  };

  // "Re-scan": park the finished scan's config and open the New scan form so the
  // user can adjust toggles and run it again (not an immediate re-run). The form
  // consumes the parked config once and clears it.
  const handleRescan = (config: ScanConfig) => {
    setPendingRescan(config);
    window.location.hash = newHash();
  };

  // A global-search pick navigates to the section with the term seeded.
  const handleSearchPick = (section: SectionId, term: string) => {
    setSeed({ section, term });
    if (loadedIdRef.current) {
      window.location.hash = scanHash(loadedIdRef.current, section);
    }
  };

  // An Overview risk-bar click routes into the section with that filter applied.
  const handleFilterPick = (
    section: SectionId,
    filter: { severity?: Severity; tier?: LicenseRiskTier },
  ) => {
    setSeed({ section, ...filter });
    if (loadedIdRef.current) {
      window.location.hash = scanHash(loadedIdRef.current, section);
    }
  };

  const isHome = status === "idle";
  // A failed run can be retried as-is only when its params carry no single-use
  // upload token or stashed credential (those are consumed on first use).
  const retryParams = lastParamsRef.current;
  const canRetry = Boolean(
    retryParams &&
      !retryParams.token &&
      !retryParams.cred &&
      !retryParams.scanossCred,
  );

  return (
    <AppShell
      scan={scan}
      activeSection={activeSection}
      activeScanId={loadedIdRef.current}
      recent={recentLinks}
      onDeleteRecent={deleteRecent}
      counts={counts}
      showSections={Boolean(result)}
      homeHref={homeHash()}
      showHomeLink={!(isHome && homeView === "recent")}
      project={isHome ? undefined : projectInfo}
      search={
        result ? <GlobalSearch result={result} onPick={handleSearchPick} /> : undefined
      }
      onRescan={
        result?.scanConfig ? () => handleRescan(result.scanConfig!) : undefined
      }
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
            <NewScan
              running={false}
              capabilities={capabilities}
              onRun={run}
              initialConfig={pendingRescan}
              onConfigConsumed={() => setPendingRescan(null)}
            />
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
            errorMessage={scanError}
            newScanHref={newHash()}
            onRetry={
              canRetry && retryParams ? () => run(retryParams) : undefined
            }
            onCancel={() => {
              closeStream(); // backend ends the process when the stream drops
              resetToHome();
              setHomeView("new");
            }}
          />
        </div>
      ) : (
        <div className="mx-auto max-w-6xl space-y-6 px-6 py-8">
          <div>
            <div className="flex items-center gap-3">
              <h1
                ref={headingRef}
                tabIndex={-1}
                className="text-3xl font-semibold tracking-tight text-foreground focus:outline-none"
              >
                {t(`nav.${activeSection}`)}
              </h1>
              <span
                role="status"
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
            recent={recent}
            searchQuery={
              seed && seed.section === activeSection ? seed.term : undefined
            }
            seedSeverity={
              seed && seed.section === activeSection ? seed.severity : undefined
            }
            seedTier={
              seed && seed.section === activeSection ? seed.tier : undefined
            }
            onPick={handleFilterPick}
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
