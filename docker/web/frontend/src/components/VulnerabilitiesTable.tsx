// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronRight,
  Download,
  ExternalLink,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorState } from "@/components/ui/state";
import { type SecuritySummary, type Severity, type VulnItem } from "@/lib/api";
import { csvFilename, downloadCsv, toCsv, vulnCsvRows } from "@/lib/csv";
import { buildQuery, parseQuery, type RouteQuery, scanHash } from "@/lib/route";
import { vulnsFromQuery, vulnsToQuery } from "@/lib/section-query";
import { compareVulns, type SortDir, type VulnSortKey } from "@/lib/vulns";
import { cn } from "@/lib/utils";

import { SeverityBar } from "./SeverityBar";

const TONE: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

// Vendor/advisory disposition badge, shown beside the severity badge. `fixed`
// reads as resolved (success); the still-open dispositions read as a caution
// (medium); dispositions that are informational rather than actionable stay
// neutral (info) — same three-tier logic as the severity/EOL/outdated badges
// elsewhere in this table.
const STATUS_TONE: Record<string, "success" | "medium" | "info"> = {
  fixed: "success",
  affected: "medium",
  will_not_fix: "medium",
  end_of_life: "medium",
  fix_deferred: "info",
  under_investigation: "info",
};

const STATUS_LABEL_KEY: Record<string, string> = {
  fixed: "result.statusFixed",
  affected: "result.statusAffected",
  will_not_fix: "result.statusWillNotFix",
  end_of_life: "result.statusEndOfLife",
  fix_deferred: "result.statusFixDeferred",
  under_investigation: "result.statusUnderInvestigation",
};

const STATUS_HINT_KEY: Record<string, string> = {
  fixed: "result.statusFixedHint",
  affected: "result.statusAffectedHint",
  will_not_fix: "result.statusWillNotFixHint",
  end_of_life: "result.statusEndOfLifeHint",
  fix_deferred: "result.statusFixDeferredHint",
  under_investigation: "result.statusUnderInvestigationHint",
};

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
}

type Sort = { key: VulnSortKey; dir: SortDir };

/** Sortable column header for the Severity / CVSS columns. */
function SortableTh({
  label,
  sortKey,
  sort,
  onSort,
  className,
}: {
  label: string;
  sortKey: VulnSortKey;
  sort: Sort;
  onSort: (key: VulnSortKey) => void;
  className?: string;
}) {
  const active = sort.key === sortKey;
  const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    // Same reason as the components table: a Korean header splits between any
    // two characters, so a narrow column stacked it vertically.
    <th
      className={cn("whitespace-nowrap px-3 py-2 font-medium", className)}
      aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        {label}
        <Icon
          className={cn("h-3 w-3", active ? "text-foreground" : "text-muted-foreground/60")}
          aria-hidden
        />
      </button>
    </th>
  );
}

/** Primary advisory URL first, then references, de-duplicated. */
function vulnLinks(v: VulnItem): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const u of [v.url, ...(v.refs ?? [])]) {
    if (u && !seen.has(u)) {
      seen.add(u);
      out.push(u);
    }
  }
  return out;
}

/** Human-readable publish date; falls back to the raw string if it doesn't parse. */
function formatPublishedDate(iso: string, locale: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(locale, { dateStyle: "medium" });
}

/** Expanded detail for one CVE — CVSS, description and reference links. */
function VulnDetail({
  vuln,
  links,
  onPickComponent,
}: {
  vuln: VulnItem;
  links: string[];
  onPickComponent?: (name: string) => void;
}) {
  const { t, i18n } = useTranslation();
  if (
    vuln.cvss == null &&
    !vuln.description &&
    links.length === 0 &&
    !vuln.publishedDate
  ) {
    return <p className="text-muted-foreground">{t("result.vulnNoDetail")}</p>;
  }
  return (
    <div className="space-y-3">
      {vuln.cvss != null && (
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="font-medium">{t("result.vulnCvss")}</span>
          <span className="tabular-nums">{vuln.cvss}</span>
          {vuln.cvssVector ? (
            <span className="font-mono text-xs text-muted-foreground">
              {vuln.cvssVector}
            </span>
          ) : null}
        </div>
      )}
      {vuln.publishedDate && (
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="font-medium">{t("result.vulnPublished")}</span>
          <span className="tabular-nums text-muted-foreground">
            {formatPublishedDate(vuln.publishedDate, i18n.language)}
          </span>
        </div>
      )}
      {vuln.description ? (
        <div className="space-y-1">
          <div className="font-medium">{t("result.vulnDescription")}</div>
          <p className="max-w-3xl leading-relaxed text-muted-foreground">
            {vuln.description}
          </p>
        </div>
      ) : null}
      {links.length > 0 ? (
        <div className="space-y-1">
          <div className="font-medium">{t("result.vulnReferences")}</div>
          <ul className="space-y-0.5">
            {links.map((href) => (
              <li key={href}>
                <a
                  href={href}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 break-all text-primary underline-offset-2 hover:underline"
                >
                  <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                  {href}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {/* Back to the package this CVE is against, in the component inventory.
          It lives in the expanded detail because the row itself is the toggle
          control, and a control nested in a control is not announced reliably. */}
      {onPickComponent && vuln.pkg ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onPickComponent(vuln.pkg);
          }}
          className="rounded text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {t("result.viewInComponents", { name: vuln.pkg })}
        </button>
      ) : null}
    </div>
  );
}

/**
 * Vulnerabilities sorted by severity. Each row expands in place to show the
 * CVSS score, description and reference links already present in the Trivy
 * report — no extra fetch, no side panel.
 */
export function VulnerabilitiesTable({
  security,
  scanId,
  query: urlState,
  onQueryChange,
  onPickComponent,
}: Props) {
  const { t } = useTranslation();
  const items = security.vulnerabilities ?? [];
  const [openKey, setOpenKey] = useState<string | null>(null);
  const initial = vulnsFromQuery(urlState);
  const [severityFilter, setSeverityFilter] = useState(initial.severity);
  const [query, setQuery] = useState(initial.term);
  // Default: most severe first, highest CVSS within a severity band.
  const [sort, setSort] = useState<Sort>(initial.sort);

  // The URL is the source; see ComponentsTable for why this compares strings.
  const urlQuery = buildQuery(urlState);
  const appliedRef = useRef(urlQuery);
  useEffect(() => {
    if (appliedRef.current === urlQuery) return;
    appliedRef.current = urlQuery;
    const next = vulnsFromQuery(parseQuery(urlQuery));
    setQuery(next.term);
    setSeverityFilter(next.severity);
    setSort(next.sort);
  }, [urlQuery]);

  useEffect(() => {
    const next = buildQuery(vulnsToQuery(query, severityFilter, sort));
    if (next === appliedRef.current) return;
    appliedRef.current = next;
    onQueryChange?.(parseQuery(next));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, severityFilter, sort]);

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

  const anyEpss = useMemo(() => items.some((v) => typeof v.epss === "number"), [items]);
  // NVD's own severity rating is a distinct axis from the adopted `severity`
  // above and only shows up when the report carries it — same opt-in pattern
  // as the EPSS column.
  const anyNvdSeverity = useMemo(() => items.some((v) => !!v.nvdSeverity), [items]);

  const sorted = useMemo(
    () => [...items].sort((a, b) => compareVulns(a, b, sort.key, sort.dir)),
    [items, sort],
  );
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
          <span className="max-w-xl break-all font-mono text-xs">{security.scanError}</span>
        </ErrorState>
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
              className="rounded text-xs text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
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
  const visible = sorted.filter((v) => {
    if (severityFilter && v.severity !== severityFilter) return false;
    if (q && !`${v.id} ${v.pkg} ${v.title}`.toLowerCase().includes(q)) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {security.scanError && (
        // Findings exist (e.g. merged from a sidecar engine) but the primary
        // engine failed — the list below is incomplete, not the full picture.
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
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
        <p className="rounded-md border border-brand/30 bg-brand/5 px-3 py-2 text-xs text-muted-foreground">
          {t("result.kernelAdvisories", { count: security.kernelCount })}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("result.vulnSearchPlaceholder")}
          className="h-9 max-w-xs"
          aria-label={t("result.vulnSearchPlaceholder")}
        />
        {(q || severityFilter) && (
          <span className="text-xs tabular-nums text-muted-foreground">
            {t("result.vulnShown", { shown: visible.length, total: items.length })}
          </span>
        )}
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="ml-auto shrink-0"
          disabled={visible.length === 0}
          onClick={exportCsv}
        >
          <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden />
          {t("result.exportCsv")}
        </Button>
      </div>
      <div className="max-h-[44rem] resize-y overflow-auto rounded-md border">
        <table className="w-full text-left text-xs">
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
          {visible.map((v, i) => {
            const key = `${v.id}-${v.pkg}-${i}`;
            const isOpen = openKey === key;
            const links = vulnLinks(v);
            const hasDetail =
              v.cvss != null ||
              !!v.description ||
              links.length > 0 ||
              !!v.publishedDate;
            const toggle = () => setOpenKey(isOpen ? null : key);
            return (
              <Fragment key={key}>
                <tr
                  className={cn(
                    "border-b align-top last:border-0 hover:bg-accent/50",
                    hasDetail && "cursor-pointer",
                  )}
                  {...(hasDetail
                    ? {
                        role: "button",
                        tabIndex: 0,
                        "aria-expanded": isOpen,
                        "aria-label": t("result.vulnRowToggle"),
                        onClick: toggle,
                        onKeyDown: (e: React.KeyboardEvent) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            toggle();
                          }
                        },
                      }
                    : {})}
                >
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1.5">
                      {hasDetail ? (
                        <ChevronRight
                          className={cn(
                            "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
                            isOpen && "rotate-90",
                          )}
                          aria-hidden
                        />
                      ) : (
                        <span className="w-3.5 shrink-0" />
                      )}
                      <Badge tone={TONE[v.severity] ?? "info"}>
                        {t(`severity.${v.severity}`)}
                      </Badge>
                      {v.status && (
                        <Badge
                          tone={STATUS_TONE[v.status] ?? "info"}
                          title={
                            STATUS_HINT_KEY[v.status]
                              ? t(STATUS_HINT_KEY[v.status])
                              : undefined
                          }
                        >
                          {STATUS_LABEL_KEY[v.status] ? t(STATUS_LABEL_KEY[v.status]) : v.status}
                        </Badge>
                      )}
                      {v.kev && (
                        <Badge tone="critical" title={t("result.kevHint")}>
                          {t("result.kevBadge")}
                        </Badge>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2 font-mono tabular-nums">
                    {v.cvss != null ? (
                      v.cvss
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  {anyEpss && (
                    <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground">
                      {typeof v.epss === "number" ? `${(v.epss * 100).toFixed(1)}%` : "—"}
                    </td>
                  )}
                  {anyNvdSeverity && (
                    <td className="px-3 py-2">
                      {v.nvdSeverity ? (
                        <Badge tone={TONE[v.nvdSeverity] ?? "info"}>
                          {t(`severity.${v.nvdSeverity}`)}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                  )}
                  <td className="px-3 py-2">
                    <span className="font-mono">{v.id}</span>
                    {v.title ? (
                      <div className="mt-0.5 max-w-md text-muted-foreground">
                        {v.title}
                      </div>
                    ) : null}
                  </td>
                  <td className="px-3 py-2 font-mono">{v.pkg}</td>
                  <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground">
                    {v.installed || "—"}
                  </td>
                  {/* Fixed version carries the success foreground, which is set
                      to the darker green on light surfaces: the lighter one
                      measures 3.77 there, under the 4.5 minimum. */}
                  <td className="px-3 py-2 font-mono tabular-nums">
                    {v.fixed ? (
                      <span className="text-success">
                        {v.fixed}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr className="border-b last:border-0">
                    <td
                      colSpan={6 + (anyEpss ? 1 : 0) + (anyNvdSeverity ? 1 : 0)}
                      className="bg-muted/30 px-3 py-3"
                    >
                      <VulnDetail
                        vuln={v}
                        links={links}
                        onPickComponent={onPickComponent}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
      </div>
    </div>
  );
}
