// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Download, ShieldCheck, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useDensity } from "@/components/ui/density-toggle";
import { EmptyState, ErrorState } from "@/components/ui/state";
import {
  exportVex,
  fileUrl,
  importVex,
  type ResultFile,
  type SecuritySummary,
  type Severity,
} from "@/lib/api";
import { receivedIndex, type ReceivedIndex } from "@/lib/vexReceived";
import { csvFilename, downloadCsv, toCsv, vulnCsvRows } from "@/lib/csv";
import { buildQuery, parseQuery, type RouteQuery, scanHash } from "@/lib/route";
import { vulnsFromQuery, vulnsToQuery } from "@/lib/section-query";
import { useToast } from "@/lib/toast";
import { notReachableSummary } from "@/lib/reachability";
import { uncheckedSummary } from "@/lib/unchecked";
import { advisorySummary, vulnAliases } from "@/lib/advisories";
import { densityClass } from "@/lib/tableDensity";
import { compareVulns, type VulnSortKey } from "@/lib/vulns";
import { groupByPackage, startsOpen, upgradeBundles } from "@/lib/vulnGroups";
import {
  applyVulnView,
  viewCounts,
  vulnViewFromQuery,
  vulnViewToQuery,
} from "@/lib/vulnView";
import { cn } from "@/lib/utils";
import { IS_STATIC_DEMO } from "@/lib/demo";

import { NotReachableFindings } from "./NotReachableFindings";
import { AdvisoriesWithoutCve } from "./AdvisoriesWithoutCve";
import { CoverageNotice } from "@/components/ui/coverage-notice";
import { SeverityBar } from "./SeverityBar";
import { UncheckedComponents } from "./UncheckedComponents";
import { PackageGroupRow } from "./vulns/PackageGroupRow";
import { SortableTh, type Sort } from "./vulns/SortableTh";
import { UpgradeBundles } from "./vulns/UpgradeBundles";
import { vexKey, type VexFields } from "./vulns/VulnDetail";
import { BASE_COLUMNS, VulnRow } from "./vulns/VulnRow";
import { VulnViewBar } from "./vulns/VulnViewBar";

interface Props {
  security: SecuritySummary;
  /** The scan's id, so an export says which scan it came from. */
  scanId?: string | null;
  /** Filter and sort state from the URL — a shared link, a reload, or a term
   *  or severity routed in from another section. */
  query?: RouteQuery;
  /** Report state back so the URL can carry it; the shell replaces the hash. */
  onQueryChange?: (query: RouteQuery) => void;
  /** Open the Components section filtered to this package — the other half of
   *  the investigation loop (what does this CVE's package ship under?). */
  onPickComponent?: (name: string) => void;
  /** Jump into the Dependencies tree, expanded to this package's installed
   *  version. Answers "which direct dependency pulled this in, and would
   *  upgrading it actually reach this transitive package?" without hand-
   *  expanding a tree that can run to hundreds of branches. */
  onPickDependency?: (name: string, version?: string) => void;
  /** The refreshed artifact listing after a VEX export, so the header counts
   *  and the Artifacts screen agree with the new file. */
  onResultsChange?: (files: ResultFile[]) => void;
}

/**
 * Vulnerabilities sorted by severity. Each row expands in place to show the
 * CVSS score, description and reference links already present in the Trivy
 * report, with no extra fetch and no side panel. A preset view and a
 * per-package layout change how the same rows read and live in the URL like the
 * filters; the row density lives in browser-local storage.
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
  const { toast } = useToast();
  const items = security.vulnerabilities ?? [];
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [exportingVex, setExportingVex] = useState(false);
  // Local overrides for a verdict just saved this session, so the badge and
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
  const [density, setDensity] = useDensity();
  // Packages whose open/closed state differs from the default (closed, except
  // when only one package is on screen).
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
  }, [urlQuery]);

  useEffect(() => {
    const next = buildQuery({
      ...vulnsToQuery(query, severityFilter, sort),
      ...vulnViewToQuery(view, layout),
    });
    if (next === appliedRef.current) return;
    appliedRef.current = next;
    onQueryChange?.(parseQuery(next));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, severityFilter, sort, view, layout]);

  // EPSS column appears only when the report was enriched (online run).
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
    ((security.vexCount ?? 0) > 0 ||
      items.some((v) => Boolean(vexOverrides[vexKey(v)]?.state ?? v.vexState)));
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
    toast(
      res.skipped > 0
        ? t("result.vexExportPartial", { skipped: res.skipped })
        : t("result.downloadStarted"),
    );
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
        toast(
          t("result.vexImportMismatch", {
            vex: out.vexProduct ?? "?",
            scan: out.scanProduct ?? "?",
          }),
        );
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

  const anyEpss = useMemo(() => items.some((v) => typeof v.epss === "number"), [items]);
  // NVD's own severity rating is a distinct axis from the adopted `severity`
  // above and only shows up when the report carries it — same opt-in pattern
  // as the EPSS column.
  const anyNvdSeverity = useMemo(() => items.some((v) => !!v.nvdSeverity), [items]);

  const sorted = useMemo(
    () => [...items].sort((a, b) => compareVulns(a, b, sort.key, sort.dir)),
    [items, sort],
  );
  // Which single upgrade per package resolves the most CVEs, worst severity
  // first. Answers "what should I fix first" before the reader has to notice
  // the pattern by comparing Fixed-column values across separate rows. Built
  // from every row, not the filtered ones: the bundle is a fact about the scan.
  const bundles = useMemo(() => upgradeBundles(groupByPackage(items)), [items]);
  const counts = useMemo(() => viewCounts(items), [items]);
  const onSort = (key: VulnSortKey) =>
    setSort((s) =>
      s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" },
    );

  if (security.TOTAL === 0 || items.length === 0) {
    // A failed engine run also yields zero rows — say so instead of implying
    // a clean result (scanError mirrors the report's ScanError marker).
    if (security.scanError) {
      return (
        <ErrorState>
          <span>{t("result.securityScanFailed")}</span>
          <span className="max-w-xl break-all font-mono text-label">{security.scanError}</span>
        </ErrorState>
      );
    }
    // Zero findings over a partial inventory is not a clean result: say how
    // many components no check reached instead of "No vulnerabilities found".
    // Findings judged not reachable are not counted either, but they are shown.
    const unchecked = uncheckedSummary(security);
    if (unchecked || notReachableSummary(security)) {
      return (
        <div className="space-y-3">
          <UncheckedComponents security={security} />
          <NotReachableFindings security={security} />
          <p className="text-body-sm text-muted-foreground">
            {t(unchecked ? "result.noVulnsInChecked" : "result.noReachableVulns")}
          </p>
          <AdvisoriesWithoutCve security={security} />
        </div>
      );
    }
    // Advisories with no CVE are not findings, so the empty state stands; the
    // list follows it rather than being dropped.
    if (advisorySummary(security)) {
      return (
        <div className="space-y-3">
          <EmptyState icon={ShieldCheck} hint={t("result.noVulnsHint")}>
            {t("result.noVulns")}
          </EmptyState>
          <AdvisoriesWithoutCve security={security} />
        </div>
      );
    }
    return (
      <EmptyState
        icon={ShieldCheck}
        hint={t("result.noVulnsHint")}
        action={
          scanId ? (
            <a
              href={scanHash(scanId, "components")}
              className="rounded text-label text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
            >
              {t("result.noVulnsAction")}
            </a>
          ) : undefined
        }
      >
        {t("result.noVulns")}
      </EmptyState>
    );
  }

  const q = query.trim().toLowerCase();
  const visible = applyVulnView(sorted, view).filter((v) => {
    if (severityFilter && v.severity !== severityFilter) return false;
    if (q && !`${v.id} ${vulnAliases(v).join(" ")} ${v.pkg} ${v.title}`.toLowerCase().includes(q)) return false;
    return true;
  });
  const optionalColumns = (anyEpss ? 1 : 0) + (anyNvdSeverity ? 1 : 0);
  const groups = layout === "package" ? groupByPackage(visible) : [];
  const visibleIndex = new Map(visible.map((v, i) => [v, i] as const));
  const rowKeyOf = (v: (typeof visible)[number]) =>
    `${v.id}-${v.purl || v.pkg}-${visibleIndex.get(v)}`;

  const renderRow = (v: (typeof visible)[number]) => {
    // The visible index alone already makes this unique for React; purl
    // (falling back to pkg name) is used instead of pkg so the key identifies
    // the same component as the grouping/join keys elsewhere.
    const key = rowKeyOf(v);
    const isOpen = openKey === key;
    return (
      <VulnRow
        key={key}
        vuln={v}
        isOpen={isOpen}
        onToggle={() => setOpenKey(isOpen ? null : key)}
        anyEpss={anyEpss}
        anyNvdSeverity={anyNvdSeverity}
        scanId={scanId}
        override={vexOverrides[vexKey(v)]}
        imported={imported}
        onPickComponent={onPickComponent}
        onPickDependency={onPickDependency}
        onVexSaved={(saved) => setVexOverrides((prev) => ({ ...prev, [vexKey(v)]: saved }))}
      />
    );
  };

  return (
    <div className="space-y-4">
      {security.scanError && (
        // Findings exist (e.g. merged from a sidecar engine) but the primary
        // engine failed — the list below is incomplete, not the full picture.
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-label text-destructive">
          {t("result.securityScanPartial")}{" "}
          <span className="break-all font-mono">{security.scanError}</span>
        </p>
      )}
      <SeverityBar
        security={security}
        selected={severityFilter as Severity | ""}
        onSelect={(s) => setSeverityFilter((f) => (f === s ? "" : s))}
      />
      {security.kernelCount ? (
        // Kernel advisories are reported but kept out of the figures above. An
        // old kernel carries thousands, nearly all for subsystems the image
        // never compiled in, and the SBOM cannot tell which — so counting them
        // here would bury the findings this screen exists to show.
        <CoverageNotice testId="kernel-advisories-notice">
          {t("result.kernelAdvisories", { count: security.kernelCount })}
        </CoverageNotice>
      ) : null}
      <UncheckedComponents security={security} />
      <NotReachableFindings security={security} />
      <UpgradeBundles bundles={bundles} onPick={setQuery} />
      <VulnViewBar
        view={view}
        counts={counts}
        onView={setView}
        layout={layout}
        onLayout={setLayout}
        density={density}
        onDensity={setDensity}
      />
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("result.vulnSearchPlaceholder")}
          className="h-9 max-w-xs"
          aria-label={t("result.vulnSearchPlaceholder")}
        />
        {(q || severityFilter || view !== "all") && (
          <span className="text-label tabular-nums text-muted-foreground">
            {t("result.vulnShown", { shown: visible.length, total: items.length })}
          </span>
        )}
        <div className="ml-auto flex shrink-0 gap-2">
          {scanId && !IS_STATIC_DEMO && (
            <>
              {/* sr-only, not hidden: the native input keeps its label and
                  keyboard behavior, as in FileDropzone. The button below opens it,
                  so it is left out of the tab order to avoid a second stop. */}
              <input
                ref={importInput}
                type="file"
                accept=".json,application/json"
                className="sr-only"
                tabIndex={-1}
                aria-label={t("result.vexImport")}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  e.target.value = "";
                  if (file) void runVexImport(file);
                }}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={importing}
                onClick={() => importInput.current?.click()}
              >
                <Upload className="mr-1.5 h-3.5 w-3.5" aria-hidden />
                {importing ? t("result.vexImporting") : t("result.vexImport")}
              </Button>
            </>
          )}
          {scanId && hasVex && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={exportingVex}
              onClick={runVexExport}
            >
              <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden />
              {exportingVex ? t("result.vexExporting") : t("result.vexExport")}
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={visible.length === 0}
            onClick={exportCsv}
          >
            <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden />
            {t("result.exportCsv")}
          </Button>
        </div>
      </div>
      <div className="max-h-[44rem] resize-y overflow-auto rounded-md border">
        <table className={cn("w-full text-left text-label", densityClass(density))}>
        <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
          <tr className="border-b">
            <SortableTh label={t("result.colSeverity")} sortKey="severity" sort={sort} onSort={onSort} />
            <SortableTh label={t("result.vulnCvss")} sortKey="cvss" sort={sort} onSort={onSort} />
            {anyEpss && (
              <SortableTh label={t("result.colEpss")} sortKey="epss" sort={sort} onSort={onSort} />
            )}
            {anyNvdSeverity && (
              <SortableTh
                label={t("result.colNvdSeverity")}
                sortKey="nvdSeverity"
                sort={sort}
                onSort={onSort}
              />
            )}
            <th className="whitespace-nowrap px-3 py-2 font-medium">{t("result.colCve")}</th>
            <th className="whitespace-nowrap px-3 py-2 font-medium">{t("result.colPackage")}</th>
            <th className="whitespace-nowrap px-3 py-2 font-medium">{t("result.colInstalled")}</th>
            <th className="whitespace-nowrap px-3 py-2 font-medium">{t("result.colFixed")}</th>
          </tr>
        </thead>
        <tbody>
          {layout === "package"
            ? groups.map((g, gi) => {
                // One package on screen is shown open; toggling flips it.
                const open = startsOpen(gi, groups.length) !== toggledGroups.has(g.key);
                return (
                  <Fragment key={g.key}>
                    <PackageGroupRow
                      group={g}
                      isOpen={open}
                      colSpan={BASE_COLUMNS + optionalColumns}
                      onToggle={() =>
                        setToggledGroups((prev) => {
                          const next = new Set(prev);
                          if (!next.delete(g.key)) next.add(g.key);
                          return next;
                        })
                      }
                    />
                    {open && g.vulns.map(renderRow)}
                  </Fragment>
                );
              })
            : visible.map(renderRow)}
        </tbody>
      </table>
      </div>
      <AdvisoriesWithoutCve security={security} />
    </div>
  );
}
