// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { DownloadIcon, SearchIcon, ShieldCheckIcon, ShieldIcon, UploadIcon } from "@primer/octicons-react";
import { Banner, Button } from "@primer/react";
import { Blankslate, Table } from "@primer/react/experimental";
import { Fragment, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";

import { SortHeader } from "@/components/primer";
import { useDensity } from "@/components/ui/density-toggle";
import {
  exportVex,
  fileUrl,
  importVex,
  type ResultFile,
  type SecuritySummary,
  type Severity,
  type VulnItem,
} from "@/lib/api";
import { receivedIndex, receivedFor, type ReceivedIndex } from "@/lib/vexReceived";
import { csvFilename, downloadCsv, toCsv, vulnCsvRows } from "@/lib/csv";
import { buildQuery, parseQuery, type RouteQuery, scanHash } from "@/lib/route";
import { vulnsFromQuery, vulnsToQuery } from "@/lib/section-query";
import { useToast } from "@/lib/toast";
import { notReachableSummary } from "@/lib/reachability";
import { uncheckedSummary } from "@/lib/unchecked";
import { advisorySummary, vulnAliases } from "@/lib/advisories";
import { useFormatNumber } from "@/lib/format";
import { compareVulns, type VulnSortKey } from "@/lib/vulns";
import { groupByPackage, startsOpen, upgradeBundles } from "@/lib/vulnGroups";
import { applyVulnView, viewCounts, vulnViewFromQuery, vulnViewToQuery } from "@/lib/vulnView";
import { columnFacts, columnOn, readColumnPref, writeColumnPref, type VulnColumnId, type VulnColumnPref } from "@/lib/vulnColumns";
import { openIds } from "@/lib/vulnOpen";
import { IS_STATIC_DEMO } from "@/lib/demo";

import { NotReachableFindings } from "./NotReachableFindings";
import { AdvisoriesWithoutCve } from "./AdvisoriesWithoutCve";
import { UncheckedComponents } from "./UncheckedComponents";
import { KernelNote } from "./vulns/KernelNote";
import { PackageGroupRow } from "./vulns/PackageGroupRow";
import type { Sort } from "./vulns/types";
import { UpgradeBundles } from "./vulns/UpgradeBundles";
import { vexKey, type VexFields } from "./vulns/vexFields";
import { VulnPanel } from "./vulns/VulnPanel";
import { VulnRow } from "./vulns/VulnRow";
import { FilterRow, ViewRow } from "./vulns/VulnToolbar";

/** Where the screen puts its file actions: a slot in the result header. */
export const VULN_ACTIONS_SLOT = "bl-vuln-actions";

interface Props {
  security: SecuritySummary;
  /** The scan's id, so an export says which scan it came from. */
  scanId?: string | null;
  /** Filter, sort and view state from the URL: a shared link, a reload, or a
   *  term or severity routed in from another section. */
  query?: RouteQuery;
  /** Report state back so the URL can carry it; the shell replaces the hash. */
  onQueryChange?: (query: RouteQuery) => void;
  /** Open the Components section filtered to this package. */
  onPickComponent?: (name: string) => void;
  /** Jump into the Dependencies tree, expanded to this package's installed
   *  version: which direct dependency pulled this in, and would upgrading it
   *  actually reach this transitive package? */
  onPickDependency?: (name: string, version?: string) => void;
  /** The refreshed artifact listing after a VEX export, so the header counts
   *  and the Artifacts screen agree with the new file. */
  onResultsChange?: (files: ResultFile[]) => void;
}

/**
 * Vulnerabilities sorted by severity. A preset view, a per-package layout and
 * the row density change how the same rows read; filters, sort, view, layout
 * and the open detail panel live in the URL, the density and the optional
 * columns in browser-local storage. Every row is drawn (no paging): the table
 * grows with the page and its header sticks under the top bar.
 */
export function VulnerabilitiesTable({
  security,
  scanId,
  query: urlState,
  onQueryChange,
  onPickComponent,
  onPickDependency,
  onResultsChange,
}: Props) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const { toast } = useToast();
  const items = useMemo(() => security.vulnerabilities ?? [], [security.vulnerabilities]);
  const [exportingVex, setExportingVex] = useState(false);
  // Local overrides for a verdict just saved this session, so the label and
  // panel reflect it immediately without waiting on a re-fetch of the whole
  // scan. Reset on scanId change so switching scans can't carry one over.
  const [vexOverrides, setVexOverrides] = useState<Record<string, VexFields>>({});
  // The statements from a VEX document imported this session. Once set they
  // stand for the whole received file (the server replaces it on every import),
  // so they win over what the scan payload carried.
  const [imported, setImported] = useState<ReceivedIndex | null>(null);
  const [importing, setImporting] = useState(false);
  const importInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    setVexOverrides({});
    setImported(null);
  }, [scanId]);
  const initial = vulnsFromQuery(urlState);
  const [severityFilter, setSeverityFilter] = useState(initial.severity);
  const [query, setQuery] = useState(initial.term);
  // Default: most severe first, highest CVSS within a severity band.
  const [sort, setSort] = useState<Sort>(initial.sort);
  const initialView = vulnViewFromQuery(urlState);
  const [view, setView] = useState(initialView.view);
  const [layout, setLayout] = useState(initialView.layout);
  const [openId, setOpenId] = useState(urlState?.open ?? "");
  const [density, setDensity] = useDensity();
  const [columnPref, setColumnPref] = useState<VulnColumnPref>(() => readColumnPref());
  // Packages whose open/closed state differs from the default (see startsOpen).
  const [toggledGroups, setToggledGroups] = useState<ReadonlySet<string>>(new Set());

  // The URL is the source; see ComponentsTable for why this compares strings.
  const urlQuery = buildQuery(urlState);
  const appliedRef = useRef(urlQuery);
  useEffect(() => {
    if (appliedRef.current === urlQuery) return;
    appliedRef.current = urlQuery;
    const parsed = parseQuery(urlQuery);
    const next = vulnsFromQuery(parsed);
    const nextView = vulnViewFromQuery(parsed);
    setQuery(next.term);
    setSeverityFilter(next.severity);
    setSort(next.sort);
    setView(nextView.view);
    setLayout(nextView.layout);
    setOpenId(parsed.open ?? "");
  }, [urlQuery]);

  useEffect(() => {
    const next = buildQuery({
      ...vulnsToQuery(query, severityFilter, sort),
      ...vulnViewToQuery(view, layout),
      ...(openId ? { open: openId } : {}),
    });
    if (next === appliedRef.current) return;
    appliedRef.current = next;
    onQueryChange?.(parseQuery(next));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, severityFilter, sort, view, layout, openId]);

  const ids = useMemo(() => openIds(items), [items]);
  const openVuln = openId ? ids.find(openId) : undefined;
  // An `open` id that names no row (a stale link, another scan) is dropped.
  useEffect(() => {
    if (openId && !openVuln) setOpenId("");
  }, [openId, openVuln]);
  // Closing the panel puts focus back on that row's title, or on the table, but
  // only when the panel was actually on screen (a stale `open=` link never was).
  const shownId = useRef("");
  useEffect(() => {
    if (openVuln) shownId.current = openId;
  }, [openVuln, openId]);
  useEffect(() => {
    if (openId) return;
    const was = shownId.current;
    if (!was) return;
    shownId.current = "";
    const timer = setTimeout(() => {
      const el =
        document.querySelector<HTMLElement>(`[data-open-id="${CSS.escape(was)}"]`) ?? document.querySelector<HTMLElement>(".bl-v-table table");
      if (!el) return;
      if (el.tagName === "TABLE") el.tabIndex = -1;
      el.focus();
    }, 50);
    return () => clearTimeout(timer);
  }, [openId]);
  const toggleOpen = useCallback((id: string) => setOpenId((cur) => (cur === id ? "" : id)), []);

  // The file actions live in the result header when it has a slot for them.
  const [actionsHost, setActionsHost] = useState<HTMLElement | null>(null);
  // Looked up after every render, so a host that was replaced is found again.
  useLayoutEffect(() => {
    const host = document.getElementById(VULN_ACTIONS_SLOT);
    if (host !== actionsHost) setActionsHost(host);
  });

  const facts = useMemo(() => columnFacts(items), [items]);
  // A sort in the URL (a shared link) that names a column shows that column.
  const showEpss = columnOn("epss", facts, columnPref) || (facts.epssRows > 0 && sort.key === "epss");
  const showNvd = columnOn("nvd", facts, columnPref) || (facts.nvdRows > 0 && sort.key === "nvdSeverity");
  const setColumn = (id: VulnColumnId, on: boolean) =>
    setColumnPref((p) => {
      const next = { ...p, [id]: on };
      writeColumnPref(next);
      return next;
    });

  // Exports what the table is showing: this filter, this sort, this order.
  const exportCsv = () => {
    const headers = [
      t("result.csvCve"),
      t("result.csvSeverity"),
      t("result.csvPackage"),
      t("result.csvInstalled"),
      t("result.csvFixed"),
      t("result.csvCvss"),
      t("result.csvEpss"),
      t("result.csvKev"),
      t("result.csvTitle"),
    ];
    downloadCsv(
      csvFilename(scanId ?? "scan", "vulnerabilities", new Date().toISOString().slice(0, 10)),
      toCsv(vulnCsvRows(visible, headers)),
    );
  };

  // The export button appears only once at least one judgement exists, either
  // loaded with the scan or saved this session.
  const hasVex =
    !IS_STATIC_DEMO &&
    ((security.vexCount ?? 0) > 0 || items.some((v) => Boolean(vexOverrides[vexKey(v)]?.state ?? v.vexState)));
  const runVexExport = async () => {
    if (!scanId || exportingVex) return;
    setExportingVex(true);
    const res = await exportVex(scanId);
    setExportingVex(false);
    if (!res) {
      toast(t("result.vexExportFailed"));
      return;
    }
    onResultsChange?.(res.results);
    // Hand the file over straight away, as the SPDX export does.
    const a = document.createElement("a");
    a.href = fileUrl(scanId, res.name);
    a.download = res.name;
    a.click();
    toast(res.skipped > 0 ? t("result.vexExportPartial", { skipped: res.skipped }) : t("result.downloadStarted"));
  };

  const runVexImport = async (file: File) => {
    if (!scanId || importing) return;
    // A VEX document is a few hundred KB at most; the server refuses more than
    // 4 MB, so say so before sending it.
    if (file.size > 4 * 1024 * 1024) {
      toast(t("result.vexImportTooLarge"));
      return;
    }
    setImporting(true);
    const out = await importVex(scanId, await file.text());
    setImporting(false);
    if (!out.ok) {
      if (out.status === 409) {
        toast(t("result.vexImportMismatch", { vex: out.vexProduct ?? "?", scan: out.scanProduct ?? "?" }));
      } else if (out.status === 413) {
        toast(t("result.vexImportTooLarge"));
      } else if (out.status === 422) {
        toast(t("result.vexImportNoMatch"));
      } else if (out.status === 400) {
        toast(t("result.vexImportInvalid"));
      } else {
        toast(t("result.vexImportFailed"));
      }
      return;
    }
    setImported(receivedIndex(out.statements, out.source));
    onResultsChange?.(out.results);
    toast(t("result.vexImported", { imported: out.imported, unmatched: out.unmatched }));
  };

  const sorted = useMemo(() => [...items].sort((a, b) => compareVulns(a, b, sort.key, sort.dir)), [items, sort]);
  // Which single upgrade per package resolves the most CVEs, worst severity
  // first. Built from every row, not the filtered ones: the bundle is a fact
  // about the scan.
  const bundles = useMemo(() => upgradeBundles(groupByPackage(items)), [items]);
  const counts = useMemo(() => viewCounts(items), [items]);
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return applyVulnView(sorted, view).filter((v) => {
      if (severityFilter && v.severity !== severityFilter) return false;
      if (needle && !`${v.id} ${vulnAliases(v).join(" ")} ${v.pkg} ${v.title}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [sorted, view, severityFilter, query]);
  const groups = useMemo(() => (layout === "package" ? groupByPackage(visible) : []), [layout, visible]);
  const onSort = (key: VulnSortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" }));

  if (security.TOTAL === 0 || items.length === 0) {
    // A failed engine run also yields zero rows: say so instead of implying a
    // clean result (scanError mirrors the report's ScanError marker).
    if (security.scanError) {
      return (
        <div className="bl-box bl-v-state" data-testid="engine-failed">
          <Blankslate>
            <Blankslate.Visual>
              <ShieldIcon size={24} />
            </Blankslate.Visual>
            <Blankslate.Heading as="h2">{t("result.securityScanFailed")}</Blankslate.Heading>
            <Blankslate.Description>
              <span className="bl-mono bl-breakall">{security.scanError}</span>
            </Blankslate.Description>
          </Blankslate>
        </div>
      );
    }
    // Zero findings over a partial inventory is not a clean result: say how
    // many components no check reached instead of "No vulnerabilities found".
    // Findings judged not reachable are not counted either, but they are shown.
    const unchecked = uncheckedSummary(security);
    if (unchecked || notReachableSummary(security)) {
      return (
        <div className="bl-stack">
          <UncheckedComponents security={security} />
          <NotReachableFindings security={security} />
          <p className="bl-muted bl-flat">{t(unchecked ? "result.noVulnsInChecked" : "result.noReachableVulns")}</p>
          <AdvisoriesWithoutCve security={security} />
        </div>
      );
    }
    // Advisories with no CVE are not findings, so the empty state stands; the
    // list follows it rather than being dropped.
    const hasAdvisories = Boolean(advisorySummary(security));
    return (
      <div className="bl-stack">
        <div className="bl-box bl-v-state" data-testid="no-vulnerabilities">
          <Blankslate>
            <Blankslate.Visual>
              <ShieldCheckIcon size={24} />
            </Blankslate.Visual>
            <Blankslate.Heading as="h2">{t("result.noVulns")}</Blankslate.Heading>
            <Blankslate.Description>{t("result.noVulnsHint")}</Blankslate.Description>
            {!hasAdvisories && scanId && (
              <Blankslate.SecondaryAction href={scanHash(scanId, "components")}>{t("result.noVulnsAction")}</Blankslate.SecondaryAction>
            )}
          </Blankslate>
        </div>
        <AdvisoriesWithoutCve security={security} />
      </div>
    );
  }

  const q = query.trim().toLowerCase();
  const filtering = Boolean(q || severityFilter || view !== "all");
  const compact = density === "compact";
  const cols = ["auto", "auto", ...(showEpss ? ["auto"] : []), ...(showNvd ? ["auto"] : []), "minmax(360px, 1fr)", "minmax(96px, 168px)"].join(" ");
  const truncated = items.length < security.TOTAL;

  const row = (v: VulnItem, inGroup: boolean) => {
    const id = ids.idOf(v);
    return (
      <VulnRow
        key={id}
        vuln={v}
        openId={id}
        isOpen={openId === id}
        onToggle={toggleOpen}
        showEpss={showEpss}
        showNvd={showNvd}
        inGroup={inGroup}
        override={vexOverrides[vexKey(v)]}
        imported={imported}
      />
    );
  };

  const chips = [
    // "Critical and High with a fix" is a refinement of the Critical and High
    // segment, opened from the Overview; removing it falls back to that segment.
    ...(view === "fixable-severe"
      ? [{ key: "fs", label: t("result.vulnViewFixableSevere"), onRemove: () => setView("critical-high") }]
      : []),
    ...(query ? [{ key: "q", label: `"${query}"`, onRemove: () => setQuery("") }] : []),
    ...(severityFilter
      ? [{ key: "sev", label: `${t("result.colSeverity")}: ${t(`severity.${severityFilter}`)}`, onRemove: () => setSeverityFilter("") }]
      : []),
  ];

  const actions: ReactNode = (
    <>
      {scanId && !IS_STATIC_DEMO && (
        <>
          {/* sr-only, not hidden: the native input keeps its label and keyboard
              behaviour. The button below opens it, so it is left out of the tab
              order to avoid a second stop. */}
          <input
            ref={importInput}
            type="file"
            accept=".json,application/json"
            className="bl-visually-hidden"
            tabIndex={-1}
            aria-label={t("result.vexImport")}
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = "";
              if (file) void runVexImport(file);
            }}
          />
          <Button leadingVisual={UploadIcon} disabled={importing} onClick={() => importInput.current?.click()}>
            {importing ? t("result.vexImporting") : t("result.vexImport")}
          </Button>
        </>
      )}
      {scanId && hasVex && (
        <Button leadingVisual={DownloadIcon} disabled={exportingVex} onClick={runVexExport}>
          {exportingVex ? t("result.vexExporting") : t("result.vexExport")}
        </Button>
      )}
      <Button leadingVisual={DownloadIcon} disabled={visible.length === 0} onClick={exportCsv}>
        {t("result.exportCsv")}
      </Button>
    </>
  );

  return (
    <div className="bl-stack bl-v">
      {actionsHost ? createPortal(actions, actionsHost) : <div className="bl-inline bl-wrap">{actions}</div>}
      {security.scanError && (
        // Findings exist (e.g. merged from a sidecar engine) but the primary
        // engine failed: the list below is incomplete, not the full picture.
        <Banner
          variant="critical"
          title={t("result.securityScanPartial")}
          description={<span className="bl-mono bl-breakall">{security.scanError}</span>}
        />
      )}
      {truncated && (
        <Banner
          variant="info"
          data-testid="vuln-truncated"
          title={t("result.vulnTruncatedTitle")}
          description={t("result.vulnTruncated", { listed: fmt(items.length), total: fmt(security.TOTAL) })}
        />
      )}
      {security.kernelCount ? <KernelNote count={security.kernelCount} /> : null}
      <UncheckedComponents security={security} />
      <NotReachableFindings security={security} />
      {layout === "list" && (
        <UpgradeBundles bundles={bundles} onPick={setQuery} onByPackage={() => setLayout("package")} />
      )}
      <div>
        <ViewRow
          view={view}
          counts={counts}
          onView={setView}
          layout={layout}
          onLayout={setLayout}
          density={density}
          onDensity={setDensity}
          columns={[
            ...(facts.epssRows > 0
              ? [
                  {
                    id: "epss",
                    label: t("result.colEpss"),
                    checked: showEpss,
                    onToggle: () => setColumn("epss", !showEpss),
                    detail: t("result.vulnColumnRows", { shown: fmt(facts.epssRows), total: fmt(facts.rows) }),
                  },
                ]
              : []),
            ...(facts.nvdRows > 0
              ? [
                  {
                    id: "nvd",
                    label: t("result.colNvdSeverity"),
                    checked: showNvd,
                    onToggle: () => setColumn("nvd", !showNvd),
                    detail: t("result.vulnColumnRows", { shown: fmt(facts.nvdRows), total: fmt(facts.rows) }),
                  },
                ]
              : []),
          ]}
        />
        <FilterRow
          security={security}
          term={query}
          onTerm={setQuery}
          severity={severityFilter}
          onSeverity={(s: Severity) => setSeverityFilter((f) => (f === s ? "" : s))}
          chips={chips}
          onClear={() => {
            setQuery("");
            setSeverityFilter("");
            setView("all");
          }}
          shown={filtering ? t("result.vulnShown", { shown: visible.length, total: items.length }) : undefined}
        />
        {visible.length === 0 ? (
          <div className="bl-box bl-v-state" data-testid="vuln-no-match">
            <Blankslate>
              <Blankslate.Visual>
                <SearchIcon size={24} />
              </Blankslate.Visual>
              <Blankslate.Heading as="h2">{t("result.noMatch")}</Blankslate.Heading>
            </Blankslate>
          </div>
        ) : (
          <Table.Container className={`bl-v-table${compact ? " bl-v-compact" : ""}`}>
            <div className="bl-v-scroll">
              <Table aria-label={t("nav.vulnerabilities")} gridTemplateColumns={cols} cellPadding={compact ? "condensed" : "normal"}>
                <Table.Head>
                  <Table.Row>
                    <SortHeader label={t("result.colSeverity")} active={sort.key === "severity"} dir={sort.dir} onSort={() => onSort("severity")} />
                    <SortHeader label={t("result.vulnCvss")} active={sort.key === "cvss"} dir={sort.dir} onSort={() => onSort("cvss")} align="end" />
                    {showEpss && (
                      <SortHeader label={t("result.colEpss")} active={sort.key === "epss"} dir={sort.dir} onSort={() => onSort("epss")} align="end" />
                    )}
                    {showNvd && (
                      <SortHeader
                        label={t("result.colNvdSeverity")}
                        active={sort.key === "nvdSeverity"}
                        dir={sort.dir}
                        onSort={() => onSort("nvdSeverity")}
                      />
                    )}
                    <Table.Header>{t("result.colVulnerability")}</Table.Header>
                    <Table.Header>{t("result.colFixed")}</Table.Header>
                  </Table.Row>
                </Table.Head>
                <Table.Body>
                  {layout === "package"
                    ? groups.map((g, gi) => {
                        // One package on screen is shown open; toggling flips it.
                        const open = startsOpen(gi, groups.length) !== toggledGroups.has(g.key);
                        return (
                          <Fragment key={g.key}>
                            <PackageGroupRow
                              group={g}
                              isOpen={open}
                              onToggle={() =>
                                setToggledGroups((prev) => {
                                  const next = new Set(prev);
                                  if (!next.delete(g.key)) next.add(g.key);
                                  return next;
                                })
                              }
                            />
                            {open && g.vulns.map((v) => row(v, true))}
                          </Fragment>
                        );
                      })
                    : visible.map((v) => row(v, false))}
                </Table.Body>
              </Table>
            </div>
          </Table.Container>
        )}
      </div>
      <AdvisoriesWithoutCve security={security} />
      {openVuln && (
        <VulnPanel
          vuln={openVuln}
          scanId={scanId}
          vex={vexOverrides[vexKey(openVuln)] ?? { state: openVuln.vexState, detail: openVuln.vexDetail, updatedAt: openVuln.vexUpdatedAt }}
          received={imported ? receivedFor(imported, openVuln) : openVuln.vexReceived}
          onVexSaved={(saved) => setVexOverrides((prev) => ({ ...prev, [vexKey(openVuln)]: saved }))}
          onClose={() => setOpenId("")}
          onPickComponent={onPickComponent}
          onPickDependency={onPickDependency}
        />
      )}
    </div>
  );
}
