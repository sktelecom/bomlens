// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { DownloadIcon, PackageIcon, SearchIcon } from "@primer/octicons-react";
import { Button, TextInput } from "@primer/react";
import { Blankslate, Table } from "@primer/react/experimental";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { ActiveFilters, FilterMenu, SortHeader } from "@/components/primer";
import { useDensity } from "@/components/ui/density-toggle";
import type { ComponentItem } from "@/lib/api";
import {
  type ComponentFilters,
  type ComponentSortKey,
  selectComponents,
  type SortDir,
} from "@/lib/components";
import { componentCsvRows, csvFilename, downloadCsv, toCsv } from "@/lib/csv";
import { licenseNeedsDecision } from "@/lib/licenses";
import { buildQuery, parseQuery, type RouteQuery } from "@/lib/route";
import { componentsFromQuery, componentsToQuery } from "@/lib/section-query";
import type { Density } from "@/lib/tableDensity";
import {
  COMPONENT_COLUMNS,
  COMPONENT_VIEW_KEY,
  defaultStore,
  readHidden,
  toggleHidden,
  writeHidden,
} from "@/lib/tableView";

import { ChunkedBody } from "./components-table/ChunkedBody";
import { ComponentRow, type ShownColumns } from "./components-table/ComponentRow";
import { type CheckItem, CheckMenu, ViewMenu } from "./components-table/menus";
import "./components-table/components-table.css";

interface Props {
  items: ComponentItem[];
  total: number;
  truncated?: boolean;
  /** The scan's id, so an export says which scan it came from. */
  scanId?: string | null;
  /** Filter and sort state from the URL: what a shared link or a reload
   *  restores, and what a global-search term or a picked license arrives as. */
  query?: RouteQuery;
  /** Report state back so the URL can carry it; the shell replaces the hash. */
  onQueryChange?: (query: RouteQuery) => void;
  /** Open the Vulnerabilities section filtered to this component: the other
   *  half of the investigation loop (which CVEs does this row stand for?). */
  onPickVulns?: (name: string) => void;
  /** Jump into the Dependencies tree, expanded to this component's version:
   *  which direct dependency pulled it in. */
  onPickDependency?: (name: string, version?: string) => void;
}

type Sort = { key: ComponentSortKey; dir: SortDir };

/** Distinct, sorted, non-empty values. */
function distinct(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: "base" }),
  );
}

/** Measured on the Primer rows (1280px, lists of firmware files and image packages: 41.3 to 41.8 and
 *  32.3 to 32.9 px per row, borders included). Only the estimate for a chunk not yet seen; a seen chunk
 *  keeps its measured height. */
const ESTIMATED_ROW_PX: Record<Density, number> = { compact: 33, comfortable: 42 };

/** Set once the reader shows the Type column of a single-type scan. */
const TYPE_SHOWN_KEY = "sbom.components.typeShown";
function readTypeShown(): boolean {
  try {
    return defaultStore()?.getItem(TYPE_SHOWN_KEY) === "1";
  } catch {
    return false;
  }
}
function writeTypeShown(on: boolean): void {
  try {
    defaultStore()?.setItem(TYPE_SHOWN_KEY, on ? "1" : "0");
  } catch {
    // Blocked storage: the choice lasts for the session.
  }
}

const COLUMN_IDS = COMPONENT_COLUMNS.map((c) => c.id);

/** Searchable, sortable, filterable table of detected SBOM components, with
 *  decision-first Scope and Risk columns (shown when the scan carries that data). */
export function ComponentsTable({
  items,
  total,
  truncated,
  scanId,
  query,
  onQueryChange,
  onPickVulns,
  onPickDependency,
}: Props) {
  const { t } = useTranslation();
  const [filters, setFilters] = useState<ComponentFilters>(() => componentsFromQuery(query).filters);
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
  const [density, setDensity] = useDensity();
  // Only what the reader chose is stored. A column with one value says nothing per row, so Type
  // is also hidden at render time when every component has the same type, until the reader
  // shows it (remembered by a flag of its own, not by the hidden list).
  const [hiddenCols, setHiddenCols] = useState<string[]>(() => readHidden(COMPONENT_VIEW_KEY, COLUMN_IDS));
  const [typeShown, setTypeShown] = useState<boolean>(readTypeShown);
  const singleType = useMemo(() => new Set(items.map((c) => c.type)).size === 1, [items]);
  const effectiveHidden = useMemo(
    () => (singleType && !typeShown && !hiddenCols.includes("type") ? [...hiddenCols, "type"] : hiddenCols),
    [singleType, typeShown, hiddenCols],
  );
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const types = useMemo(() => distinct(items.map((c) => c.type)), [items]);
  const licenses = useMemo(() => distinct(items.flatMap((c) => c.licenses)), [items]);
  const typeCounts = useMemo(() => countBy(items, (c) => [c.type]), [items]);
  const licenseCounts = useMemo(() => countBy(items, (c) => c.licenses), [items]);

  // Adaptive columns and filters: only offer what the scan actually produced.
  const avail = useMemo(
    () => ({
      scope: items.some((c) => c.scope),
      vulns: items.some((c) => c.vulnCount),
      vendored: items.some((c) => c.vendored),
      eol: items.some((c) => c.eol === "true"),
      outdated: items.some((c) => c.outdated === "true"),
      licenseUnclear: items.some((c) => licenseNeedsDecision(c.licenses)),
    }),
    [items],
  );

  // Which optional columns this scan can offer at all, and which of those the
  // reader has hidden. A column the scan has no data for is not offered, so the
  // menu never lists a column that would come up empty.
  const available: Record<string, boolean> = useMemo(
    () => ({ version: true, type: true, scope: avail.scope, risk: avail.vulns, license: true }),
    [avail],
  );
  const shown: ShownColumns = useMemo(() => {
    const shows = (id: string) => available[id] && !effectiveHidden.includes(id);
    return {
      version: shows("version"),
      type: shows("type"),
      scope: shows("scope"),
      risk: shows("risk"),
      license: shows("license"),
    };
  }, [available, effectiveHidden]);

  const rows = useMemo(() => selectComponents(items, filters, sort), [items, filters, sort]);

  const onToggle = useCallback((key: string) => setOpenKey((k) => (k === key ? null : key)), []);
  const rowKey = (c: ComponentItem, i: number) => c.purl || `${c.name}-${i}`;
  const openIndex = useMemo(
    () => (openKey === null ? -1 : rows.findIndex((c, i) => (c.purl || `${c.name}-${i}`) === openKey)),
    [rows, openKey],
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
      toCsv(componentCsvRows(rows, headers)),
    );
  };

  if (total === 0) {
    return (
      <div className="bl-box bl-comp-gap" data-testid="components-empty">
        <Blankslate spacious>
          <Blankslate.Visual>
            <PackageIcon size={24} />
          </Blankslate.Visual>
          <Blankslate.Heading as="h2">{t("result.componentsEmpty")}</Blankslate.Heading>
          <Blankslate.Description>{t("result.componentsEmptyHint")}</Blankslate.Description>
        </Blankslate>
      </div>
    );
  }

  const patch = (p: Partial<ComponentFilters>) => setFilters((f) => ({ ...f, ...p }));
  const onSort = (key: ComponentSortKey) =>
    setSort((s) => (s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));

  // The name keeps at least 20rem and takes whatever the others leave.
  const cols = [
    "minmax(min(20rem, 100%), 1fr)",
    // A long version wraps; every other column is as wide as its content, so a word is never split.
    ...(shown.version ? ["fit-content(14rem)"] : []),
    ...(shown.type ? ["max-content"] : []),
    ...(shown.scope ? ["max-content"] : []),
    ...(shown.risk ? ["max-content"] : []),
    ...(shown.license ? ["max-content"] : []),
  ].join(" ");

  const flag = (id: keyof ComponentFilters, label: string, on: boolean): CheckItem | false =>
    on && {
      id,
      label,
      checked: Boolean(filters[id]),
      onToggle: () => patch({ [id]: !filters[id] } as Partial<ComponentFilters>),
    };
  // The toggles, as one menu. Only the ones this scan has data for appear.
  const filterItems = [
    flag("hasVulns", t("result.filterHasVulns"), avail.vulns),
    flag("directOnly", t("result.filterDirectOnly"), avail.scope),
    flag("needsReview", t("result.filterNeedsReview"), avail.vendored),
    flag("eolOnly", t("result.filterEol"), avail.eol),
    flag("outdatedOnly", t("result.filterOutdated"), avail.outdated),
    // Offered only when there is something to narrow to: on a tree whose licences
    // all resolved, the filter would return the whole table and say nothing.
    flag("licenseUnclear", t("result.filterLicenseUnclear"), avail.licenseUnclear),
  ].filter(Boolean) as CheckItem[];

  const columnItems: CheckItem[] = COMPONENT_COLUMNS.filter((c) => available[c.id]).map((c) => ({
    id: c.id,
    label: t(c.labelKey),
    checked: !effectiveHidden.includes(c.id),
    onToggle: () => {
      const showing = effectiveHidden.includes(c.id);
      const next = showing ? hiddenCols.filter((h) => h !== c.id) : toggleHidden(hiddenCols, c.id);
      setHiddenCols(next);
      writeHidden(COMPONENT_VIEW_KEY, next);
      if (c.id === "type") {
        setTypeShown(showing);
        writeTypeShown(showing);
      }
    },
  }));

  // The active filters as removable chips; they appear only once something is on.
  const chips = [
    ...(filters.query ? [{ key: "q", label: `"${filters.query}"`, onRemove: () => patch({ query: "" }) }] : []),
    ...(filters.type
      ? [{ key: "type", label: `${t("result.colType")}: ${filters.type}`, onRemove: () => patch({ type: "" }) }]
      : []),
    ...(filters.license
      ? [{ key: "license", label: `${t("result.colLicense")}: ${filters.license}`, onRemove: () => patch({ license: "" }) }]
      : []),
    ...filterItems.filter((i) => i.checked).map((i) => ({ key: i.id, label: i.label, onRemove: i.onToggle })),
  ];

  const sortHeader = (key: ComponentSortKey, label: string) => (
    <SortHeader label={label} active={sort?.key === key} dir={sort?.dir ?? "asc"} onSort={() => onSort(key)} />
  );

  return (
    <div className="bl-comp bl-comp-gap">
      <div className="bl-filterbar">
        <TextInput
          block
          type="search"
          leadingVisual={SearchIcon}
          value={filters.query}
          onChange={(e) => patch({ query: e.target.value })}
          placeholder={t("result.componentsSearch")}
          aria-label={t("result.componentsSearch")}
          className="bl-comp-search"
        />
        {types.length > 1 && (
          <FilterMenu
            name={t("result.colType")}
            allLabel={t("result.allTypes")}
            value={filters.type}
            onChange={(v) => patch({ type: v })}
            options={types.map((ty) => ({ value: ty, text: ty, count: typeCounts.get(ty) ?? 0 }))}
          />
        )}
        {/* Also shown for a single license when one is selected: a filter routed
            in from the Licenses section must stay clearable. */}
        {(licenses.length > 1 || filters.license) && (
          <FilterMenu
            name={t("result.colLicense")}
            allLabel={t("result.allLicenses")}
            value={filters.license}
            onChange={(v) => patch({ license: v })}
            options={licenses.map((l) => ({ value: l, text: l, count: licenseCounts.get(l) ?? 0 }))}
          />
        )}
        {filterItems.length > 0 && <CheckMenu name={t("result.filters")} items={filterItems} />}
        <ViewMenu density={density} onDensity={setDensity} columns={columnItems} />
        <span className="bl-grow" />
        <Button leadingVisual={DownloadIcon} disabled={rows.length === 0} onClick={exportCsv}>
          {t("result.exportCsv")}
        </Button>
      </div>
      <ActiveFilters
        chips={chips}
        onClear={() =>
          patch({
            query: "",
            type: "",
            license: "",
            hasVulns: false,
            directOnly: false,
            needsReview: false,
            eolOnly: false,
            outdatedOnly: false,
            licenseUnclear: false,
          })
        }
        summary={
          chips.length > 0 || truncated ? (
            <>
              {t("result.componentsCount", { shown: rows.length, total })}
              {truncated ? ` · ${t("result.truncated", { count: items.length })}` : ""}
            </>
          ) : undefined
        }
      />
      {rows.length === 0 ? (
        <div className="bl-box">
          <Blankslate>
            <Blankslate.Visual>
              <SearchIcon size={24} />
            </Blankslate.Visual>
            <Blankslate.Heading as="h2">{t("result.noMatch")}</Blankslate.Heading>
          </Blankslate>
        </div>
      ) : (
        <Table.Container className="bl-comp-table">
          <div className="bl-comp-scroll" ref={scrollRef} data-density={density}>
            <Table
              aria-label={t("nav.components")}
              gridTemplateColumns={cols}
              cellPadding={density === "compact" ? "condensed" : "normal"}
            >
              <Table.Head>
                <Table.Row>
                  {sortHeader("name", t("result.colName"))}
                  {shown.version && sortHeader("version", t("result.colVersion"))}
                  {shown.type && sortHeader("type", t("result.colType"))}
                  {shown.scope && sortHeader("scope", t("result.colScope"))}
                  {shown.risk && sortHeader("risk", t("result.colRisk"))}
                  {shown.license && <Table.Header>{t("result.colLicense")}</Table.Header>}
                </Table.Row>
              </Table.Head>
              <ChunkedBody
                rows={rows}
                observeRoot={scrollRef}
                openIndex={openIndex}
                rowHeight={ESTIMATED_ROW_PX[density]}
                resetKey={rows}
                render={(c, i) => {
                  const key = rowKey(c, i);
                  return (
                    <ComponentRow
                      key={key}
                      item={c}
                      rowKey={key}
                      index={i}
                      isOpen={openKey === key}
                      onToggle={onToggle}
                      shown={shown}
                      scanId={scanId}
                      eolFilter={filters.eolOnly}
                      outdatedFilter={filters.outdatedOnly}
                      onPickVulns={onPickVulns}
                      onPickDependency={onPickDependency}
                    />
                  );
                }}
              />
            </Table>
          </div>
        </Table.Container>
      )}
    </div>
  );
}

/** How many items carry each value (an item with several values counts once for each). */
function countBy(items: ComponentItem[], valuesOf: (c: ComponentItem) => string[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const c of items) for (const v of new Set(valuesOf(c))) out.set(v, (out.get(v) ?? 0) + 1);
  return out;
}
