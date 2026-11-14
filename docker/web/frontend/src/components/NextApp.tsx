// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Spinner } from "@primer/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { AppShell } from "./AppShell";
import type { NavPlace } from "./Sidebar";
import { DeclareFlow } from "./DeclareFlow";
import { ExternalLookup } from "./ExternalLookup";
import { GlobalSearch } from "./GlobalSearch";
import { NewScan } from "./NewScan";
import { ProgressLog } from "./ProgressLog";
import { RecentScans } from "./RecentScans";
import { ResultHeader } from "./ResultHeader";
import { ResultSection } from "./ResultSections";
import { ReportProblem } from "./ReportProblem";
import { ScanRunning } from "./ScanRunning";
import { ConfirmDialog } from "./ui/dialog";
import {
  deleteScan,
  fileUrl,
  getCapabilities,
  listScans,
  loadScan,
  startScan,
  type Capabilities,
  type DoneEvent,
  type RecentScan,
  type ScanConfig,
  type ScanParams,
  type Severity,
} from "@/lib/api";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { type LicenseRiskTier } from "@/lib/licenses";
import {
  type RecentScanLink,
  type SectionId,
  visibleSectionIds,
} from "@/lib/nav";
import {
  homeHash,
  lookupHash,
  newHash,
  parseHash,
  scanHash,
  type RouteQuery,
} from "@/lib/route";
import { formatNumber } from "@/lib/format";
import { deriveScanContext, sectionCounts } from "@/lib/results";
import { type ProjectName, projectText, scanProjectName } from "@/lib/scanTitle";
import { useToast } from "@/lib/toast";

type Status = "idle" | "running" | "done" | "error";

/** How long opening a scan waits for the scan list before drawing. */
const LIST_WAIT_MS = 3000;

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
 * Label key for the subtitle under the result heading — what was scanned.
 *
 * The saved input comes first: a submitted supplier SBOM usually declares
 * "application" at its root, indistinguishable from a source scan, so reading
 * the component type alone called it Source. Everything else keeps using the
 * component type, which survives a re-open where the scan MODE does not.
 */
/** Sections that are one wide table or tree: they use the whole content width.
 *  Every other section keeps a reading width, left-aligned under the same
 *  header, so the title does not move when the section changes. */
const WIDE_SECTIONS: ReadonlySet<SectionId> = new Set([
  "components",
  "dependencies",
  "sourceTree",
  "vulnerabilities",
  "artifacts",
]);

/** Sections that keep a reading width below 2xl and take the whole content
 *  width from there: the ones with a narrow column beside the main one, and
 *  Models & datasets, whose dataset table and G7 checklist would otherwise
 *  stop two thirds across a wide screen while every other section fills it. */
const TWO_COLUMN_SECTIONS: ReadonlySet<SectionId> = new Set([
  "overview",
  "licenses",
  "conformance",
  "models",
]);

function scanKindKey(isAi: boolean, result: DoneEvent): string {
  if (isAi) return "result.kindAi";
  if (result.scanConfig?.source === "sbom-upload") return "result.kindAnalyze";
  return SCAN_KIND_KEY[result.sbom?.componentType ?? ""] ?? "result.kindSbom";
}

/** Map a stored scan to the top bar's Recent-menu link shape. */
function toRecentLink(s: RecentScan): RecentScanLink {
  const sev = s.maxSeverity;
  return {
    id: s.id,
    label: projectText({ name: s.project, version: s.version || undefined }),
    name: s.project,
    version: s.version || undefined,
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
  const { t, i18n } = useTranslation();
  const { toast } = useToast();
  const [status, setStatus] = useState<Status>("idle");
  const [logs, setLogs] = useState<string[]>([]);
  // The failure message surfaced on the Scan-running screen when a scan can't
  // run (stream/launch error), so it isn't buried in the log.
  const [scanError, setScanError] = useState<string | null>(null);
  // Set alongside scanError when the server could classify the failure (e.g.
  // a git clone that failed because the repo is missing or private): an i18n
  // key for a friendlier headline, with scanError kept as the raw detail.
  const [scanErrorKey, setScanErrorKey] = useState<string | null>(null);
  const [result, setResult] = useState<DoneEvent | null>(null);
  // The project a live scan was started for: it has no id (and so no entry in
  // the scan list) until it finishes.
  const [liveProject, setLiveProject] = useState<ProjectName>();
  // The id of a past scan being fetched, so a deep link shows a loading state
  // rather than the home screen until the scan arrives.
  const [opening, setOpening] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<SectionId>("overview");
  // Mirrored into a ref so the URL writer can read the current section without
  // taking it as a dependency and being rebuilt on every section change.
  const activeSectionRef = useRef(activeSection);
  activeSectionRef.current = activeSection;
  // Which idle screen is shown: Recent scans (home/logo), New scan (#/new) or
  // External lookup (#/lookup).
  const [homeView, setHomeView] = useState<"recent" | "new" | "lookup">("recent");
  const homeViewRef = useRef(homeView);
  homeViewRef.current = homeView;
  const [capabilities, setCapabilities] = useState<Capabilities>({
    firmware: false,
    docker: true,
  });
  // Mirrored so `route()` can read the latest capabilities without taking
  // them as a dependency, for the same reason `activeSectionRef` exists below.
  const capabilitiesRef = useRef(capabilities);
  capabilitiesRef.current = capabilities;
  const [recent, setRecent] = useState<RecentScan[]>([]);
  // The scan a delete button asked to remove, waiting on the confirm dialog.
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  // A finished scan's config, parked here when the user hits "Re-scan" so the
  // New scan form can seed itself from it. The form reads it once on mount and
  // clears it, so a subsequent plain New scan starts blank.
  const [pendingRescan, setPendingRescan] = useState<ScanConfig | null>(null);
  // Field the New scan form should focus when it opens from a re-scan prompt.
  const [pendingFocus, setPendingFocus] = useState<"license" | null>(null);
  // A model described from its declaration: the form's settings wait here while
  // the questions are answered. `saved` is the declaration of a scan being
  // re-run, read when Re-scan was pressed.
  const [declaring, setDeclaring] = useState<{ params: ScanParams; saved?: Promise<unknown> } | null>(null);
  // The declaration read for a Re-scan, as the request itself: the questions
  // wait for it however late it lands, and it is used once. A newer Re-scan
  // replaces it; leaving for another screen drops it.
  const savedDeclarationRef = useRef<Promise<unknown> | undefined>(undefined);
  // The active section's filter and sort state, read from the URL hash. Keeping
  // it here rather than inside each table is what makes a filtered view
  // linkable and lets it survive a reload: the hash is the one source, and a
  // pick routed in from another section is just a hash with a query on it.
  const [sectionQuery, setSectionQuery] = useState<RouteQuery>({});

  // The scan id currently held in `result` — so the hash router can tell a
  // section change (no reload) from opening a different scan (reload).
  const loadedIdRef = useRef<string | null>(null);
  // The id of an in-flight live scan, so its `done` can set the URL.
  const runningIdRef = useRef<string | null>(null);
  // The params of the last started scan, so a failed run can be retried — but
  // only when they carry no single-use upload token or stashed credential.
  const lastParamsRef = useRef<ScanParams | null>(null);

  // On a section change focus moves to the section heading, so keyboard and
  // screen-reader users land on (and hear) the new section instead of being
  // left on the navigation link. Skipped on the first run so the initial load
  // does not grab focus.
  const didMountRef = useRef(false);

  // The live scan's SSE stream. Held so leaving the running view (new scan,
  // opening a past scan) can close it — otherwise a backgrounded scan finishes
  // later and hijacks whatever the user is now looking at.
  const streamRef = useRef<EventSource | null>(null);
  const closeStream = () => {
    streamRef.current?.close();
    streamRef.current = null;
  };

  // The scan list request in flight (or done). Opening a scan waits for it, so
  // the scan is named from the list ("project version") on its first render
  // rather than by its run id.
  const recentLoadRef = useRef<Promise<void> | null>(null);
  // The latest list, for showScan to tell whether it already names a scan.
  const recentRef = useRef<RecentScan[]>([]);
  // True while a list request is on its way, so a second caller joins it.
  const recentPendingRef = useRef(false);
  const refreshRecent = () => {
    recentPendingRef.current = true;
    const load = listScans()
      .then((list) => {
        recentRef.current = list;
        setRecent(list);
      })
      .finally(() => {
        if (recentLoadRef.current === load) recentPendingRef.current = false;
      });
    recentLoadRef.current = load;
    return load;
  };

  useEffect(() => {
    getCapabilities().then((caps) => {
      setCapabilities(caps);
      // setCapabilities only schedules the re-render that would refresh
      // capabilitiesRef; writing it directly here means route(), called on
      // the very next line, already sees the real value instead of the
      // still-stale default from before this render.
      capabilitiesRef.current = caps;
      // A deep-linked `#/lookup` parsed before capabilities arrived cannot
      // yet know whether externalLookup is on, so re-run the router now that
      // it does: a genuinely-off build still bounces home (see route()'s
      // "false, not undefined" check below).
      routeRef.current();
    });
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
    setLiveProject(undefined);
    setOpening(null);
    setActiveSection("overview");
  }, []);

  // Show a past/finished scan for the given id + section. Loads it if it isn't
  // already the current result; falls back home if its artifacts are gone.
  const showScan = useCallback(
    (id: string, section: SectionId) => {
      // Same scan already loaded → just switch the section (no reload, no flash).
      if (loadedIdRef.current === id) {
        // Back to the open scan while another was loading: that load is moot.
        setOpening(null);
        setActiveSection(section);
        return;
      }
      closeStream();
      runningIdRef.current = null;
      setOpening(id);
      // Wait for the scan list so the first render names the scan from it, but
      // not for long: past LIST_WAIT_MS the scan draws with the name from its
      // settings, and the list renames it when it lands.
      // A list that does not have this scan yet (one finished since) is asked
      // again; one that has it is reused.
      // One on its way is joined rather than repeated.
      const known = recentRef.current.some((s) => s.id === id) || recentPendingRef.current;
      const listed = ((known && recentLoadRef.current) || refreshRecent()).catch(() => undefined);
      let timer = 0;
      const listedOrLate = Promise.race([
        listed,
        new Promise<void>((r) => {
          timer = window.setTimeout(r, LIST_WAIT_MS);
        }),
      ]).finally(() => window.clearTimeout(timer));
      void Promise.all([loadScan(id), listedOrLate]).then(([done]) => {
        setOpening((o) => (o === id ? null : o));
        // Navigated away meanwhile, to another screen or to another scan: a
        // late answer for this one must not cover what is now on screen.
        const now = parseHash(window.location.hash);
        if (now.kind !== "scan" || now.id !== id) return;
        if (!done) {
          // Artifacts missing (e.g. a live-only scan that was never stored, or a
          // deleted one). Falling back to the scan list is right, but doing it
          // silently left whoever followed a stale link staring at a list with
          // no idea why: say which scan could not be opened.
          toast(t("recent.scanNotFound", { id }));
          window.location.hash = homeHash();
          return;
        }
        loadedIdRef.current = id;
        setLogs([]);
        setLiveProject(undefined);
        setResult(done);
        setStatus(done.ok ? "done" : "error");
        setActiveSection(section);
      });
    },
    // refreshRecent only reads refs and the state setter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t, toast],
  );

  // Switch to one of the idle home views (Recent or New scan), resetting any
  // loaded/running scan state first. Shared by the hash router (on a `#/` or
  // `#/new` navigation) and by the "New scan" controls below, which must reset
  // the same way even when the hash is already `#/new` and so fires no
  // `hashchange` (see goToNewScan).
  const enterHome = useCallback(
    (kind: "recent" | "new") => {
      // Scan management shows the current list whenever it is entered from
      // another screen. Already on it (the first render, or the router running
      // again once capabilities arrive), the list on hand is current: the mount
      // effect has requested it, and a second request would only repeat it.
      const alreadyThere =
        homeViewRef.current === "recent" && loadedIdRef.current === null && status === "idle";
      if (kind === "recent" && !alreadyThere) void refreshRecent();
      setHomeView(kind);
      setOpening(null);
      // Open questions belong to the form they were started from; any other
      // way into the home screens starts over.
      setDeclaring(null);
      if (kind === "recent") savedDeclarationRef.current = undefined;
      if (loadedIdRef.current !== null || status !== "idle") resetToHome();
    },
    [status, resetToHome],
  );

  // The hash router: parse on mount and on every hashchange. Skip while a live
  // scan is running — that view is owned by the run() state machine, not the URL
  // (there is no id yet), and run()'s done handler sets the URL when it finishes.
  const route = useCallback(() => {
    if (status === "running") return;
    const parsed = parseHash(window.location.hash);
    if (parsed.kind === "recent" || parsed.kind === "new") {
      enterHome(parsed.kind);
      return;
    }
    if (parsed.kind === "lookup") {
      // Only bounce on a definite "off": capabilities start undefined until
      // getCapabilities() resolves, and treating "not yet loaded" the same as
      // "disabled" would drop a deep link raced against that first fetch.
      if (capabilitiesRef.current.externalLookup === false || IS_STATIC_DEMO) {
        window.location.hash = homeHash();
        return;
      }
      setHomeView("lookup");
      setOpening(null);
      setSectionQuery(parsed.query ?? {});
      if (loadedIdRef.current !== null || status !== "idle") resetToHome();
      return;
    }
    setSectionQuery(parsed.query ?? {});
    showScan(parsed.id, parsed.section);
  }, [status, enterHome, showScan]);

  // Explicit "New scan" affordances (TopBar, Sidebar, the failed-scan error
  // card) call this directly instead of relying solely on the `<a href="#/new">`
  // they still carry. A scan started from `#/new` that then fails (no `done`
  // event, so the URL never moved off `#/new`) leaves the hash unchanged when
  // one of these is clicked, so the browser fires no `hashchange` and the
  // router above never re-runs. Resetting state here first makes the click work
  // either way; setting the hash afterwards is a no-op when it's already
  // `#/new` and a normal navigation otherwise (harmless if it re-triggers the
  // router — state is already reset, so that second pass does nothing further).
  const goToNewScan = useCallback(() => {
    savedDeclarationRef.current = undefined;
    enterHome("new");
    if (window.location.hash !== newHash()) window.location.hash = newHash();
  }, [enterHome]);

  // External lookup's top-bar icon (see TopBar.onLookup): the hash router
  // bails out entirely while a scan is running (`route()`'s first line), the
  // same way it does for `#/new` and `#/scan/*` — that guard exists because a
  // live run has no id yet and owns the running-scan view itself. So reaching
  // Lookup mid-run needs the same imperative reset-then-navigate shape
  // goToNewScan uses instead of relying on the plain `<a href>` alone.
  const goToLookup = useCallback(() => {
    setHomeView("lookup");
    if (loadedIdRef.current !== null || status !== "idle") resetToHome();
    if (window.location.hash !== lookupHash()) window.location.hash = lookupHash();
  }, [status, resetToHome]);

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
    // Only a result section's own title: leaving a scan for the New scan form
    // (Re-scan) also resets the section, and that form focuses its own field.
    const heading = document.querySelector<HTMLElement>(".bl-result-title");
    if (!heading) return;
    // A new section starts at its top, whatever the last one was scrolled to;
    // the title's scroll-margin keeps it clear of the sticky top bar.
    window.scrollTo(0, 0);
    heading.tabIndex = -1;
    heading.focus();
  }, [activeSection]);

  // Close the live scan stream if the app unmounts.
  useEffect(() => () => streamRef.current?.close(), []);

  // Deleting a scan removes its output files from disk, and the server keeps no
  // copy — there is nothing to undo afterwards. So the guard goes in front: both
  // delete controls (the Recent table and the top-bar menu) park the id here and
  // the dialog is what actually calls the API.
  const pendingScan = recent.find((s) => s.id === pendingDelete);
  // Name the scan in the prompt so the user sees which one is going. Falls back
  // to the id when the list hasn't caught up with the menu.
  const pendingLabel = pendingScan
    ? [pendingScan.project, pendingScan.version].filter(Boolean).join(" ")
    : (pendingDelete ?? "");

  const confirmDelete = () => {
    const id = pendingDelete;
    setPendingDelete(null);
    if (!id) return;
    void deleteScan(id).then(async (ok) => {
      const stayedOnList = homeViewRef.current === "recent" && loadedIdRef.current === null;
      await refreshRecent().catch(() => undefined);
      if (ok && stayedOnList) {
        // The row that held focus is gone; put it on the list's heading rather
        // than letting it fall to the start of the document.
        const heading = document.querySelector<HTMLElement>("main h1");
        if (heading) {
          heading.tabIndex = -1;
          heading.focus();
        }
      }
      if (!ok) {
        toast(t("recent.deleteFailed"));
        return;
      }
      toast(t("recent.deleted"));
      // If we're viewing the scan we just deleted, drop back to Scan management.
      if (loadedIdRef.current === id) window.location.hash = homeHash();
    });
  };

  const scan = useMemo(() => deriveScanContext(result), [result]);
  const recentLinks = useMemo(() => recent.map(toRecentLink), [recent]);
  const counts = useMemo(
    () => (result ? sectionCounts(result, (n) => formatNumber(n, i18n.language)) : undefined),
    [result, i18n.language],
  );

  // Keep the active section valid for the current result (e.g. a new scan
  // without a dependency graph must not stay on the Dependencies section).
  useEffect(() => {
    if (!result) return;
    const available = visibleSectionIds(scan);
    if (!available.includes(activeSection)) setActiveSection("overview");
  }, [result, scan, activeSection]);

  const run = (params: ScanParams) => {
    // The declaration input has nothing to scan until its questions are
    // answered: open them, and start the scan from there with the uploaded
    // declaration's token.
    if (params.source === "ai-declare" && !params.token) {
      setDeclaring({ params, saved: savedDeclarationRef.current });
      savedDeclarationRef.current = undefined;
      return;
    }
    savedDeclarationRef.current = undefined;
    closeStream(); // drop any previous stream before starting a new one
    loadedIdRef.current = null;
    runningIdRef.current = null;
    lastParamsRef.current = params;
    setOpening(null);
    setStatus("running");
    setLogs([]);
    setScanError(null);
    setScanErrorKey(null);
    setResult(null);
    setActiveSection("overview");
    setLiveProject({
      name: params.project,
      version: params.version || undefined,
    });
    streamRef.current = startScan(params, {
      onLog: (line) => setLogs((prev) => [...prev, line]),
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
      onError: (message, key) => {
        if (message) {
          setLogs((prev) => [...prev, `✖ ${message}`]);
          setScanError(message);
          setScanErrorKey(key ?? null);
        }
        setStatus((s) => (s === "running" ? "error" : s));
      },
    });
  };

  // "Re-scan": park the finished scan's config and open the New scan form so the
  // user can adjust toggles and run it again (not an immediate re-run). The form
  // consumes the parked config once and clears it.
  const handleRescan = (config: ScanConfig, focus?: "license") => {
    setPendingRescan(config);
    setPendingFocus(focus ?? null);
    savedDeclarationRef.current = undefined;
    // A declared model re-runs from its own declaration: read it now, while the
    // scan it belongs to is the one on screen.
    const decl = result?.results.find((f) => f.name.endsWith("_ai-declaration.json"));
    if (config.source === "ai-declare" && decl && loadedIdRef.current) {
      savedDeclarationRef.current = fetch(fileUrl(loadedIdRef.current, decl.name))
        .then((r) => (r.ok ? (r.json() as Promise<unknown>) : undefined))
        .catch(() => undefined);
    }
    window.location.hash = newHash();
  };

  // A global-search pick navigates to the section with the term in the URL, so
  // the view it lands on can be shared or reloaded like any other.
  const handleSearchPick = (section: SectionId, term: string) => {
    if (loadedIdRef.current) {
      window.location.hash = scanHash(loadedIdRef.current, section, { q: term });
    }
  };

  // A GlobalSearch "look it up externally" pick routes to the Lookup screen
  // with the term in the URL; the screen itself makes the request, not this
  // handler, so typing never fires one.
  const handleLookupPick = (term: string) => {
    window.location.hash = lookupHash(term);
  };

  // The Lookup screen ran a query, so reflect it in the URL (replaced, not
  // pushed, same reasoning as handleQueryChange below) so the result is a
  // shareable link without the screen touching the hash itself.
  const handleLookupQueryChange = useCallback((term: string) => {
    const next = lookupHash(term || undefined);
    if (next === window.location.hash) return;
    window.history.replaceState(null, "", next);
  }, []);

  // An Overview risk-bar click, or a name picked out of a result table, routes
  // into the section with that filter applied.
  const handleFilterPick = (
    section: SectionId,
    filter: {
      severity?: Severity;
      tier?: LicenseRiskTier;
      license?: string;
      term?: string;
      version?: string;
    },
  ) => {
    if (!loadedIdRef.current) return;
    const query: Record<string, string> = {};
    if (filter.term) query.q = filter.term;
    if (filter.severity) query.severity = filter.severity;
    if (filter.tier) query.tier = filter.tier;
    if (filter.license) query.license = filter.license;
    // Disambiguates a "View in Dependencies" jump when the same package name
    // resolves to two different versions in the tree (findPathToRef then
    // requires the exact version instead of landing on the first name match).
    if (filter.version) query.version = filter.version;
    window.location.hash = scanHash(loadedIdRef.current, section, query);
  };

  // A section changed its own filters. The hash is replaced rather than pushed:
  // every keystroke in a search box would otherwise become a history entry, and
  // replaceState fires no hashchange, so the router does not re-run and the
  // table keeps the state it just reported.
  const handleQueryChange = useCallback(
    (query: RouteQuery) => {
      const id = loadedIdRef.current;
      if (!id) return;
      const next = scanHash(id, activeSectionRef.current, query);
      if (next === window.location.hash) return;
      window.history.replaceState(null, "", next);
    },
    [],
  );

  const isHome = status === "idle";
  // When the open scan was made, from the scan list (the result payload itself
  // carries no timestamp). Absent until the list has the scan.
  const generatedAt = recent.find((s) => s.id === loadedIdRef.current)?.generatedAt;
  // Every entry point into the Lookup screen (this hash, the top-bar icon,
  // the GlobalSearch row) is gated the same way: the server won't make
  // outbound requests when externalLookup is off, and the static demo has no
  // server to ask at all.
  const lookupEnabled = Boolean(capabilities.externalLookup) && !IS_STATIC_DEMO;
  // A failed run can be retried as-is only when its params carry no single-use
  // upload token or stashed credential (those are consumed on first use).
  const retryParams = lastParamsRef.current;
  const canRetry = Boolean(
    retryParams &&
      !retryParams.token &&
      !retryParams.cred &&
      !retryParams.scanossCred,
  );

  // The scan on screen, by project and version (never its run id when the scan
  // list or its settings can name it). A live scan uses the form's values.
  const loadedId = loadedIdRef.current;
  const projectInfo: ProjectName | undefined = opening
    ? undefined
    : loadedId
      ? scanProjectName(
          loadedId,
          recent,
          result?.scanConfig ??
            (liveProject ? { project: liveProject.name, version: liveProject.version } : null),
        )
      : liveProject;
  // Which navigation entry is the current page.
  const navCurrent: NavPlace =
    opening || result
      ? activeSection
      : !isHome
        ? null
        : homeView === "lookup"
          ? null
          : homeView;
  const onHomeScreen = isHome && !opening && homeView === "recent";

  // The browser tab names the screen, then the scan, then the app.
  const scanLabel = projectText(projectInfo);
  const pageTitle = opening
    ? t("appTitle")
    : result && scanLabel
      ? t("shell.scanPageTitle", { section: t(`nav.${activeSection}`), scan: scanLabel, app: t("appTitle") })
      : !isHome
        ? // A scan is running: its name, or "in progress" when it has none yet.
          t("shell.pageTitle", { page: scanLabel || t("shell.scanRunning"), app: t("appTitle") })
        : t("shell.pageTitle", {
            page:
              homeView === "new"
                ? t("shell.newScan")
                : homeView === "lookup"
                  ? t("nav.lookupTitle")
                  : t("recent.title"),
            app: t("appTitle"),
          });
  useEffect(() => {
    document.title = pageTitle;
  }, [pageTitle]);

  return (
    <AppShell
      scan={scan}
      current={navCurrent}
      activeScanId={opening ? null : loadedId}
      recent={recentLinks}
      onDeleteRecent={setPendingDelete}
      version={capabilities.version}
      counts={opening ? undefined : counts}
      homeHref={homeHash()}
      showHomeLink={!onHomeScreen}
      hideTopBarNewScan={onHomeScreen || (isHome && !opening && homeView === "new")}
      lookupCurrent={isHome && !opening && homeView === "lookup"}
      lookupHref={lookupEnabled ? lookupHash() : undefined}
      onLookup={lookupEnabled ? goToLookup : undefined}
      onNewScan={goToNewScan}
      loadingSections={Boolean(opening) || status === "running"}
      project={isHome && !result ? undefined : projectInfo}
      projectHref={loadedId && !opening ? scanHash(loadedId) : undefined}
      search={
        result && !opening
          ? (width: number) => (
              <GlobalSearch
                result={result}
                width={width}
                onPick={handleSearchPick}
                onLookup={lookupEnabled ? handleLookupPick : undefined}
              />
            )
          : undefined
      }
      onRescan={
        result?.scanConfig && !opening ? () => handleRescan(result.scanConfig!) : undefined
      }
    >
      {opening ? (
        <div
          role="status"
          data-testid="scan-opening"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "var(--base-size-8)",
            color: "var(--fgColor-muted)",
          }}
        >
          <Spinner size="small" srText={null} />
          {t("shell.openingScan")}
        </div>
      ) : isHome ? (
        <div className={homeView === "recent" ? "" : "mx-auto max-w-6xl"}>
          {homeView === "recent" ? (
            <RecentScans
              scans={recent}
              newHref={newHash()}
              onDelete={setPendingDelete}
            />
          ) : homeView === "lookup" ? (
            <ExternalLookup
              initialQuery={sectionQuery.q}
              onQueryChange={handleLookupQueryChange}
            />
          ) : declaring ? (
            <DeclareFlow
              params={declaring.params}
              saved={declaring.saved}
              onCancel={() => setDeclaring(null)}
              onStart={(params) => {
                setDeclaring(null);
                run(params);
              }}
            />
          ) : (
            <NewScan
              running={false}
              capabilities={capabilities}
              onRun={run}
              initialConfig={pendingRescan}
              focusField={pendingFocus}
              onConfigConsumed={() => {
                setPendingRescan(null);
                setPendingFocus(null);
              }}
            />
          )}
        </div>
      ) : !result ? (
        <div className="mx-auto max-w-5xl">
          <ScanRunning
            logs={logs}
            status={status === "error" ? "error" : "running"}
            projectLabel={projectText(projectInfo) || undefined}
            errorMessage={scanError}
            errorKey={scanErrorKey}
            newScanHref={newHash()}
            onNewScan={goToNewScan}
            deepCveEnabled={retryParams?.deepCve}
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
        <div
          className={`space-y-6 ${
            TWO_COLUMN_SECTIONS.has(activeSection)
              ? "[&>*:not(:first-child)]:max-w-6xl 2xl:[&>*:not(:first-child)]:max-w-none"
              : WIDE_SECTIONS.has(activeSection)
                ? ""
                : "[&>*:not(:first-child)]:max-w-6xl"
          }`}
        >
          <ResultHeader
            name={projectInfo?.name}
            version={projectInfo?.version}
            kind={t(scanKindKey(scan.isAiScan, result))}
            generatedAt={generatedAt}
            status={
              !result.ok
                ? "failed"
                : (result.sbom?.pipelineStepsFailed?.length ?? 0) > 0
                  ? "partial"
                  : "ok"
            }
            title={t(`nav.${activeSection}`)}
            projectTitle={activeSection === "overview"}
            components={result.sbom?.components}
          />

          <ResultSection
            section={activeSection}
            result={result}
            scanId={loadedIdRef.current}
            recent={recent}
            generatedAt={generatedAt}
            query={sectionQuery}
            onQueryChange={handleQueryChange}
            onPick={handleFilterPick}
            // An on-demand SPDX export adds an artifact after the scan ended, so
            // fold the refreshed listing into the result every count reads from.
            onResultsChange={(files) =>
              setResult((r) => (r ? { ...r, results: files } : r))
            }
            // Saving an AI declaration also refreshes the SPDX 3.0.1 summary.
            onResultPatch={(patch) => setResult((r) => (r ? { ...r, ...patch } : r))}
            // A service declared after the scan reaches the CycloneDX SBOM
            // only from a new scan; the SPDX 3.0.1 band offers the re-scan.
            onRescan={
              result.scanConfig && !IS_STATIC_DEMO ? () => handleRescan(result.scanConfig!) : undefined
            }
            onRescanWithLicense={
              result.scanConfig && !IS_STATIC_DEMO
                ? () => handleRescan(result.scanConfig!, "license")
                : undefined
            }
          />

          {/* The run log is reference material for the run you just watched.
              A scan re-opened from history has no logs (logs is reset on load),
              so don't show an empty disclosure — only render while running or
              when there is something to show. */}
          {activeSection === "overview" &&
            (status === "running" || logs.length > 0) && (
              <ProgressLog logs={logs} status={status} collapsible />
            )}

          {/* A finished scan, succeeded or failed: the summary to attach to an
              issue, shown in full before anything is copied. */}
          {activeSection === "overview" && (
            <ReportProblem
              key={result.id ?? loadedIdRef.current ?? "none"}
              scanId={result.id ?? loadedIdRef.current}
              errorMessage={scanError}
              defaultOpen={!result.ok}
            />
          )}
        </div>
      )}

      {/* Fixed-position overlay, so it renders the same wherever it sits in the
          tree — kept here to cover both the home and the result screens. */}
      <ConfirmDialog
        open={pendingDelete !== null}
        title={t("recent.confirmDeleteTitle")}
        description={<Trans i18nKey="recent.confirmDeleteBody" values={{ scan: pendingLabel }} components={{ b: <strong className="font-semibold text-foreground" /> }} />}
        confirmLabel={t("recent.delete")}
        destructive
        onConfirm={confirmDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </AppShell>
  );
}
