// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ArrowDown, ArrowUp, ArrowUpDown, Download, Package, Search, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CheckMenu, type CheckMenuItem } from "@/components/ui/check-menu";
import { Select } from "@/components/ui/select";
import { EmptyState } from "@/components/ui/state";
import type { ComponentItem, Severity } from "@/lib/api";
import {
  type ComponentFilters,
  type ComponentSortKey,
  EMPTY_FILTERS,
  licenseBadges,
  selectComponents,
  type SortDir,
} from "@/lib/components";
import { componentCsvRows, csvFilename, downloadCsv, toCsv } from "@/lib/csv";
import { licenseNeedsDecision } from "@/lib/licenses";
import {
  COMPONENT_COLUMNS,
  COMPONENT_VIEW_KEY,
  readHidden,
  toggleHidden,
  writeHidden,
} from "@/lib/tableView";
import { buildQuery, parseQuery, type RouteQuery } from "@/lib/route";
import { componentsFromQuery, componentsToQuery } from "@/lib/section-query";
import { cn } from "@/lib/utils";

interface Props {
  items: ComponentItem[];
  total: number;
  truncated?: boolean;
  /** The scan's id, so an export says which scan it came from. */
  scanId?: string | null;
  /** Filter and sort state from the URL — what a shared link or a reload
   *  restores, and what a global-search term or a picked license arrives as. */
  query?: RouteQuery;
  /** Report state back so the URL can carry it; the shell replaces the hash. */
  onQueryChange?: (query: RouteQuery) => void;
  /** Open the Vulnerabilities section filtered to this component — the other
   *  half of the investigation loop (which CVEs does this row stand for?). */
  onPickVulns?: (name: string) => void;
}

type Sort = { key: ComponentSortKey; dir: SortDir };

/** Rows are rendered in chunks of this size, one <tbody> per chunk. Chunks far
 *  from the viewport are recycled into a single spacer row of their measured
 *  height, so a large SBOM scrolls the full list while the DOM stays small.
 *  Row heights may vary (wrapping license badges, the expanded detail row), so
 *  spacers use per-chunk measurements, not a global fixed row height. */
const CHUNK = 100;
/** Height estimate for a chunk that has never been rendered (single-line row). */
const ROW_ESTIMATE = 37;
/** Chunks live from the start, before the observer has seen anything. */
const INITIAL_LIVE: ReadonlySet<number> = new Set([0, 1, 2]);

const SEV_TONE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

/** Distinct, sorted, non-empty values. */
function distinct(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: "base" }),
  );
}

function SortHeader({
  label,
  sortKey,
  sort,
  onSort,
  className,
}: {
  label: string;
  sortKey: ComponentSortKey;
  sort: Sort | null;
  onSort: (key: ComponentSortKey) => void;
  className?: string;
}) {
  const active = sort?.key === sortKey;
  const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    // whitespace-nowrap: CJK text breaks between any two characters, so a
    // two-character Korean header in a narrow column split down the middle.
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

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        "rounded-md border px-2.5 py-1 text-xs font-medium transition-colors duration-fast ease-out-soft",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
        active
          ? "border-brand/40 bg-brand/10 text-foreground"
          : "border-border text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

/** Searchable, sortable, filterable table of detected SBOM components, with
 *  decision-first Scope and Risk columns (shown when the scan carries that data). */
export function ComponentsTable({ items, total, truncated, scanId, query, onQueryChange, onPickVulns }: Props) {
  const { t } = useTranslation();
  const [filters, setFilters] = useState<ComponentFilters>(
    () => componentsFromQuery(query).filters,
  );
  const [sort, setSort] = useState<Sort | null>(() => componentsFromQuery(query).sort);

  // The URL is the source: a link opened elsewhere, a reload, or a term routed
  // in from global search all arrive here. Compared as a serialised string so
  // that a re-render with an equal-but-new object does not reset the table
  // under the user's fingers.
  const urlQuery = buildQuery(query);
  const appliedRef = useRef(urlQuery);
  useEffect(() => {
    if (appliedRef.current === urlQuery) return;
    appliedRef.current = urlQuery;
    const next = componentsFromQuery(parseQuery(urlQuery));
    setFilters(next.filters);
    setSort(next.sort);
  }, [urlQuery]);

  // Report the other way: the user's own filtering goes back out to the URL.
  useEffect(() => {
    const next = buildQuery(componentsToQuery(filters, sort));
    if (next === appliedRef.current) return;
    appliedRef.current = next;
    onQueryChange?.(parseQuery(next));
    // onQueryChange is a stable shell callback; re-running on its identity
    // would fire on every parent render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, sort]);
  const [openKey, setOpenKey] = useState<string | null>(null);
  // Which columns the reader has hidden, read once from browser-local storage
  // (the same place the theme and language live — no account, nothing sent).
  const [hiddenCols, setHiddenCols] = useState<string[]>(() =>
    readHidden(COMPONENT_VIEW_KEY, COMPONENT_COLUMNS.map((c) => c.id)),
  );
  // Chunk recycling state: which chunks render real rows, and the measured
  // pixel height of chunks currently recycled into spacers.
  const [liveChunks, setLiveChunks] = useState<ReadonlySet<number>>(INITIAL_LIVE);
  const chunkHeights = useRef(new Map<number, number>());
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const types = useMemo(() => distinct(items.map((c) => c.type)), [items]);
  const licenses = useMemo(() => distinct(items.flatMap((c) => c.licenses)), [items]);

  // Adaptive columns/filters: only offer what the scan actually produced.
  const anyScope = useMemo(() => items.some((c) => c.scope), [items]);
  const anyVulns = useMemo(() => items.some((c) => c.vulnCount), [items]);
  const anyVendored = useMemo(() => items.some((c) => c.vendored), [items]);
  const anyEol = useMemo(() => items.some((c) => c.eol === "true"), [items]);
  const anyOutdated = useMemo(() => items.some((c) => c.outdated === "true"), [items]);
  const anyLicenseUnclear = useMemo(
    () => items.some((c) => licenseNeedsDecision(c.licenses)),
    [items],
  );

  const filtered = useMemo(
    () => selectComponents(items, filters, sort),
    [items, filters, sort],
  );

  // Exports what the table is showing: this filter, this sort, this order.
  const exportCsv = () => {
    const headers = [
      t("result.csvName"),
      t("result.csvVersion"),
      t("result.csvType"),
      t("result.csvLicenses"),
      t("result.csvScope"),
      t("result.csvVulnCount"),
      t("result.csvMaxSeverity"),
      t("result.csvPurl"),
    ];
    downloadCsv(
      csvFilename(scanId ?? "scan", "components", new Date().toISOString().slice(0, 10)),
      toCsv(componentCsvRows(filtered, headers)),
    );
  };

  // A new visible set invalidates every measurement and starts from the top.
  useEffect(() => {
    setLiveChunks(INITIAL_LIVE);
    chunkHeights.current.clear();
  }, [filters, sort, items]);

  // One observer over the per-chunk <tbody> elements (stable nodes — React
  // keeps them keyed by chunk index across live/spacer swaps). A chunk near
  // the viewport goes live; one leaving it is measured, then recycled.
  const chunkCount = Math.ceil(filtered.length / CHUNK);
  useEffect(() => {
    const root = scrollRef.current;
    if (!root) return;
    const io = new IntersectionObserver(
      (entries) => {
        setLiveChunks((prev) => {
          const next = new Set(prev);
          for (const e of entries) {
            const idx = Number((e.target as HTMLElement).dataset.chunk);
            if (Number.isNaN(idx)) continue;
            if (e.isIntersecting) {
              next.add(idx);
            } else {
              if (prev.has(idx)) {
                chunkHeights.current.set(idx, e.boundingClientRect.height);
              }
              next.delete(idx);
            }
          }
          return next;
        });
      },
      { root, rootMargin: "600px 0px" },
    );
    for (const el of root.querySelectorAll("tbody[data-chunk]")) io.observe(el);
    return () => io.disconnect();
  }, [chunkCount]);

  if (total === 0) {
    return (
      <EmptyState icon={Package} hint={t("result.componentsEmptyHint")}>
        {t("result.componentsEmpty")}
      </EmptyState>
    );
  }

  const onSort = (key: ComponentSortKey) =>
    setSort((s) =>
      s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" },
    );
  const patch = (p: Partial<ComponentFilters>) => setFilters((f) => ({ ...f, ...p }));

  // Which optional columns this scan can offer at all, and which of those the
  // reader has hidden. A column the scan has no data for is not offered, so the
  // menu never lists a column that would come up empty.
  const columnAvailable: Record<string, boolean> = {
    version: true,
    type: true,
    scope: anyScope,
    risk: anyVulns,
    license: true,
  };
  const shows = (id: string) => columnAvailable[id] && !hiddenCols.includes(id);
  const showVersion = shows("version");
  const showType = shows("type");
  const showScope = shows("scope");
  const showRisk = shows("risk");
  const showLicense = shows("license");
  const colCount =
    1 + [showVersion, showType, showScope, showRisk, showLicense].filter(Boolean).length;

  const toggleColumn = (id: string) => {
    setHiddenCols((prev) => {
      const next = toggleHidden(prev, id);
      writeHidden(COMPONENT_VIEW_KEY, next);
      return next;
    });
  };

  // The toggles that used to sit in a row of chips, as one menu. Only the ones
  // this scan has data for appear.
  const filterItems: CheckMenuItem[] = [
    anyVulns && {
      id: "hasVulns",
      label: t("result.filterHasVulns"),
      checked: filters.hasVulns,
      onToggle: () => patch({ hasVulns: !filters.hasVulns }),
    },
    anyScope && {
      id: "directOnly",
      label: t("result.filterDirectOnly"),
      checked: filters.directOnly,
      onToggle: () => patch({ directOnly: !filters.directOnly }),
    },
    anyVendored && {
      id: "needsReview",
      label: t("result.filterNeedsReview"),
      checked: filters.needsReview,
      onToggle: () => patch({ needsReview: !filters.needsReview }),
    },
    anyEol && {
      id: "eolOnly",
      label: t("result.filterEol"),
      checked: filters.eolOnly,
      onToggle: () => patch({ eolOnly: !filters.eolOnly }),
    },
    anyOutdated && {
      id: "outdatedOnly",
      label: t("result.filterOutdated"),
      checked: filters.outdatedOnly,
      onToggle: () => patch({ outdatedOnly: !filters.outdatedOnly }),
    },
    // Offered only when there is something to narrow to: on a tree whose licences
    // all resolved, the filter would return the whole table and say nothing.
    anyLicenseUnclear && {
      id: "licenseUnclear",
      label: t("result.filterLicenseUnclear"),
      checked: filters.licenseUnclear,
      onToggle: () => patch({ licenseUnclear: !filters.licenseUnclear }),
    },
  ].filter(Boolean) as CheckMenuItem[];

  const columnItems: CheckMenuItem[] = COMPONENT_COLUMNS.filter(
    (c) => columnAvailable[c.id],
  ).map((c) => ({
    id: c.id,
    label: t(c.labelKey),
    checked: !hiddenCols.includes(c.id),
    onToggle: () => toggleColumn(c.id),
  }));

  // The active toggles, as removable chips. They appear only once something is
  // on, so an unfiltered table carries no row of controls it is not using.
  const activeChips = filterItems.filter((i) => i.checked);

  // Row keys are purl-or-name based (stable across chunk boundaries); the
  // chunk holding the expanded row is pinned live so it can never be recycled
  // out from under the open detail panel.
  const rowKey = (c: ComponentItem, gi: number) => c.purl || `${c.name}-${gi}`;
  const openChunk =
    openKey === null
      ? -1
      : Math.floor(filtered.findIndex((c, gi) => rowKey(c, gi) === openKey) / CHUNK);
  const chunks: ComponentItem[][] = [];
  for (let i = 0; i < filtered.length; i += CHUNK) chunks.push(filtered.slice(i, i + CHUNK));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[10rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={filters.query}
            onChange={(e) => patch({ query: e.target.value })}
            placeholder={t("result.componentsSearch")}
            className="pl-8"
          />
        </div>
        {types.length > 1 && (
          <Select
            value={filters.type}
            onChange={(e) => patch({ type: e.target.value })}
            aria-label={t("result.allTypes")}
            // Capped so a long option value cannot push the toolbar onto a
            // second line; the native select still shows the full text open.
            className="max-w-40"
          >
            <option value="">{t("result.allTypes")}</option>
            {types.map((ty) => (
              <option key={ty} value={ty}>
                {ty}
              </option>
            ))}
          </Select>
        )}
        {/* Also shown for a single license when one is selected — a filter
            routed in from the Licenses section must stay clearable. */}
        {(licenses.length > 1 || filters.license) && (
          <Select
            value={filters.license}
            onChange={(e) => patch({ license: e.target.value })}
            aria-label={t("result.allLicenses")}
            className="max-w-44"
          >
            <option value="">{t("result.allLicenses")}</option>
            {licenses.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </Select>
        )}
        {filterItems.length > 0 && (
          <CheckMenu label={t("result.filters")} items={filterItems} />
        )}
        <CheckMenu label={t("result.columns")} items={columnItems} />
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="shrink-0"
          disabled={filtered.length === 0}
          onClick={exportCsv}
        >
          <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden />
          {t("result.exportCsv")}
        </Button>
        {/* The count closes the toolbar rather than starting a line of its own,
            which is what made the controls read as four stacked rows. */}
        <div className="ml-auto text-xs text-muted-foreground">
          {t("result.componentsCount", { shown: filtered.length, total })}
          {/* "list truncated" left the reader guessing how much they were
              looking at. items.length is what the server sent for this scan. */}
          {truncated ? ` · ${t("result.truncated", { count: items.length })}` : ""}
        </div>
      </div>

      {activeChips.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {activeChips.map((chip) => (
            <FilterChip key={chip.id} active onClick={chip.onToggle}>
              {chip.label}
              <X className="ml-1 h-3 w-3" aria-hidden />
            </FilterChip>
          ))}
          <button
            type="button"
            onClick={() =>
              patch({
                hasVulns: false,
                directOnly: false,
                needsReview: false,
                eolOnly: false,
                outdatedOnly: false,
                licenseUnclear: false,
              })
            }
            className="rounded text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          >
            {t("result.clearFilters")}
          </button>
        </div>
      )}

      <div ref={scrollRef} className="max-h-[44rem] resize-y overflow-auto rounded-md border">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
            <tr className="border-b">
              {/* The name column is pinned: reading the columns on the right of a
                  wide table used to lose track of which component the row was.
                  Its background must be opaque — the pinned cell slides over the
                  others, and the header's translucent tint would show them
                  through. z-30 keeps it above both the sticky header (z-10) and
                  the pinned body cells (z-10). */}
              <SortHeader
                label={t("result.colName")}
                sortKey="name"
                sort={sort}
                onSort={onSort}
                className="sticky left-0 z-30 bg-muted"
              />
              {showVersion && (
                <SortHeader label={t("result.colVersion")} sortKey="version" sort={sort} onSort={onSort} className="min-w-24" />
              )}
              {showType && (
                <SortHeader label={t("result.colType")} sortKey="type" sort={sort} onSort={onSort} className="min-w-24" />
              )}
              {showScope && (
                <SortHeader label={t("result.colScope")} sortKey="scope" sort={sort} onSort={onSort} className="min-w-20" />
              )}
              {showRisk && (
                <SortHeader label={t("result.colRisk")} sortKey="risk" sort={sort} onSort={onSort} className="min-w-24" />
              )}
              {showLicense && (
                <th className="whitespace-nowrap px-3 py-2 font-medium">{t("result.colLicense")}</th>
              )}
            </tr>
          </thead>
          {chunks.map((chunkItems, ci) =>
            liveChunks.has(ci) || ci === openChunk ? (
              <tbody key={ci} data-chunk={ci}>
            {chunkItems.map((c, i) => {
              const key = rowKey(c, ci * CHUNK + i);
              const isOpen = openKey === key;
              const toggle = () => setOpenKey(isOpen ? null : key);
              const lic = licenseBadges(c.licenses);
              return (
              <Fragment key={key}>
              {/* role="button" makes aria-expanded valid here (it is not allowed
                  on a plain table row) and, with tabIndex + the key handler,
                  keeps the expandable row reachable by keyboard. */}
              <tr
                className="group cursor-pointer border-b last:border-0 hover:bg-accent/50"
                role="button"
                tabIndex={0}
                aria-expanded={isOpen}
                aria-label={t("result.componentRowToggle")}
                onClick={toggle}
                onKeyDown={(e: React.KeyboardEvent) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    toggle();
                  }
                }}
              >
                {/* Pinned like its header. The row tint is painted per-cell here
                    (group-hover) because a pinned cell needs its own opaque
                    background and would otherwise stay unhighlighted. */}
                <td className="sticky left-0 z-10 max-w-80 bg-background px-3 py-2 group-hover:bg-accent/50">
                  <div className="flex items-center gap-2">
                    <Package className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    <span
                      className="truncate font-mono"
                      title={`${c.group ? `${c.group} / ` : ""}${c.name}`}
                    >
                      {c.group ? `${c.group} / ` : ""}
                      {c.name}
                    </span>
                    {c.vendored && (
                      <Badge
                        variant="muted"
                        title={
                          c.matchConfidence
                            ? `${t("result.vendoredBadgeHint")} (${t("result.vendoredMatch", { pct: c.matchConfidence })})`
                            : t("result.vendoredBadgeHint")
                        }
                      >
                        {t("result.vendoredBadge")}
                      </Badge>
                    )}
                    {/* Leads the badges: a package to remove outranks anything
                        that is merely out of date or vulnerable. */}
                    {c.malicious && (
                      <Badge
                        tone="critical"
                        title={
                          c.maliciousId
                            ? `${t("result.maliciousBadgeHint")} (${c.maliciousId}${c.maliciousSource ? `, ${c.maliciousSource}` : ""})`
                            : t("result.maliciousBadgeHint")
                        }
                      >
                        {t("result.maliciousBadge")}
                      </Badge>
                    )}
                    {c.eol === "true" && (
                      <Badge tone="high" title={t("result.eolBadgeHint")}>
                        {t("result.eolBadge")}
                        {c.eolDate ? ` · ${t("result.eolSince", { date: c.eolDate })}` : ""}
                      </Badge>
                    )}
                    {/* Weaker emphasis than EOL: a supported component that simply
                        has a newer patch available. Muted, not warning-toned. */}
                    {c.outdated === "true" && (
                      <Badge variant="muted" title={t("result.outdatedBadgeHint")}>
                        {t("result.outdatedBadge")}
                        {c.latestVersion
                          ? ` · ${t("result.outdatedLatest", { version: c.latestVersion })}`
                          : ""}
                      </Badge>
                    )}
                  </div>
                </td>
                {/* A presence-only row has no version by construction, so an
                    em dash here would read as a gap in the data rather than as
                    the finding it is: the component is there, the version is
                    not recoverable, and no advisory lookup applies to it. */}
                {showVersion && (
                <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-muted-foreground">
                  {c.version || (c.presenceOnly ? (
                    <span
                      className="font-sans text-xs"
                      title={t("result.presenceOnlyHint")}
                    >
                      {t("result.presenceOnlyVersion")}
                    </span>
                  ) : "—")}
                </td>
                )}
                {showType && (
                <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">{c.type || "—"}</td>
                )}
                {showScope && (
                  <td className="whitespace-nowrap px-3 py-2">
                    {c.scope ? (
                      <span
                        className={
                          c.scope === "direct"
                            ? "font-medium text-foreground"
                            : "text-muted-foreground"
                        }
                      >
                        {t(c.scope === "direct" ? "result.scopeDirect" : "result.scopeTransitive")}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                )}
                {showRisk && (
                  <td className="whitespace-nowrap px-3 py-2">
                    {c.maxSeverity ? (
                      <Badge tone={SEV_TONE[c.maxSeverity]}>
                        {t(`severity.${c.maxSeverity}`)}
                        {c.vulnCount ? ` · ${c.vulnCount}` : ""}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                )}
                {/* Badges past the limit fold into a count so a component with a
                    dozen licenses does not stand three rows tall. The expanded
                    row below lists them all. */}
                {showLicense && (
                <td className="whitespace-nowrap px-3 py-2">
                  {c.licenses.length ? (
                    <div className="flex items-center gap-1">
                      {lic.shown.map((l, j) => (
                        <Badge key={j} variant="muted">
                          {l}
                        </Badge>
                      ))}
                      {lic.hidden > 0 && (
                        <span
                          className="text-muted-foreground"
                          title={c.licenses.join(", ")}
                        >
                          {t("result.licenseMore", { count: lic.hidden })}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">{t("result.licenseNone")}</span>
                  )}
                </td>
                )}
              </tr>
              {isOpen && (
                <tr className="border-b last:border-0">
                  <td colSpan={colCount} className="bg-muted/30 px-3 py-3">
                    <dl className="grid grid-cols-[max-content,1fr] gap-x-4 gap-y-1.5 text-xs">
                      {c.purl ? (
                        <>
                          <dt className="font-medium text-muted-foreground">purl</dt>
                          <dd className="break-all font-mono">{c.purl}</dd>
                        </>
                      ) : null}
                      {c.source ? (
                        <>
                          <dt className="font-medium text-muted-foreground">{t("result.colSource")}</dt>
                          <dd>
                            <a
                              href={c.source}
                              target="_blank"
                              rel="noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="break-all text-primary underline-offset-2 hover:underline"
                            >
                              {c.source}
                            </a>
                          </dd>
                        </>
                      ) : null}
                      {c.copyright ? (
                        <>
                          <dt className="font-medium text-muted-foreground">{t("result.colCopyright")}</dt>
                          <dd className="break-words">{c.copyright}</dd>
                        </>
                      ) : null}
                      {c.licenses.length > 0 ? (
                        <>
                          <dt className="font-medium text-muted-foreground">{t("result.colLicense")}</dt>
                          <dd>{c.licenses.join(", ")}</dd>
                        </>
                      ) : null}
                      {c.eol === "true" ? (
                        <>
                          <dt className="font-medium text-muted-foreground">{t("result.colEol")}</dt>
                          <dd>
                            {t("result.eolBadge")}
                            {c.eolDate ? ` (${c.eolDate})` : ""}
                          </dd>
                        </>
                      ) : null}
                      {c.outdated === "true" ? (
                        <>
                          <dt className="font-medium text-muted-foreground">{t("result.colCurrency")}</dt>
                          <dd>
                            {c.latestVersion
                              ? t("result.outdatedLatest", { version: c.latestVersion })
                              : t("result.outdatedBadge")}
                            {typeof c.releasesBehind === "number"
                              ? ` · ${t("result.outdatedReleasesBehind", { count: c.releasesBehind })}`
                              : ""}
                            {c.lastReleased
                              ? ` · ${t("result.outdatedLastReleased", { date: c.lastReleased })}`
                              : ""}
                          </dd>
                        </>
                      ) : null}
                      {c.vulnCount ? (
                        <>
                          <dt className="font-medium text-muted-foreground">{t("nav.vulnerabilities")}</dt>
                          <dd className="flex flex-wrap items-baseline gap-2">
                            <span>
                              {c.maxSeverity ? `${t(`severity.${c.maxSeverity}`)} · ` : ""}
                              {c.vulnCount}
                            </span>
                            {/* Into the CVEs behind this row. It sits in the
                                expanded detail rather than on the risk badge
                                because the row itself is the toggle control,
                                and a control inside a control is not announced
                                reliably. */}
                            {onPickVulns && (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onPickVulns(c.name);
                                }}
                                className="rounded text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                              >
                                {t("result.viewInVulns", { name: c.name })}
                              </button>
                            )}
                          </dd>
                        </>
                      ) : null}
                    </dl>
                  </td>
                </tr>
              )}
              </Fragment>
              );
            })}
              </tbody>
            ) : (
              // Recycled chunk: one spacer row holding the chunk's measured
              // height (or an estimate before its first paint), so the
              // scrollbar geometry stays correct without the row DOM.
              <tbody key={ci} data-chunk={ci} aria-hidden>
                <tr>
                  <td
                    colSpan={colCount}
                    style={{
                      height:
                        chunkHeights.current.get(ci) ??
                        chunkItems.length * ROW_ESTIMATE,
                      padding: 0,
                    }}
                  />
                </tr>
              </tbody>
            ),
          )}
          {filtered.length === 0 && (
            <tbody>
              <tr>
                <td colSpan={colCount} className="px-3 py-6 text-center text-muted-foreground">
                  {t("result.noMatch")}
                </td>
              </tr>
            </tbody>
          )}
        </table>
      </div>
    </div>
  );
}
