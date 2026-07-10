import { Fragment, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { ArrowDown, ArrowUp, ArrowUpDown, Package, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import { EmptyState } from "@/components/ui/state";
import type { ComponentItem, Severity } from "@/lib/api";
import {
  type ComponentFilters,
  type ComponentSortKey,
  EMPTY_FILTERS,
  selectComponents,
  type SortDir,
} from "@/lib/components";
import { cn } from "@/lib/utils";

interface Props {
  items: ComponentItem[];
  total: number;
  truncated?: boolean;
  /** Search term seeded from global search; applied to the name/license filter. */
  initialQuery?: string;
}

type Sort = { key: ComponentSortKey; dir: SortDir };

/** How many rows to render at once; "Show more" reveals the next batch. Sorting
 *  and filtering run over the full set — only the DOM is capped (large SBOMs). */
const RENDER_STEP = 200;

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
    <th
      className={cn("px-3 py-2 font-medium", className)}
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
export function ComponentsTable({ items, total, truncated, initialQuery }: Props) {
  const { t } = useTranslation();
  const [filters, setFilters] = useState<ComponentFilters>(() => ({
    ...EMPTY_FILTERS,
    query: initialQuery ?? "",
  }));
  // Re-seed the search when global search routes in a new term.
  useEffect(() => {
    if (initialQuery !== undefined) {
      setFilters((f) => ({ ...f, query: initialQuery }));
    }
  }, [initialQuery]);
  const [sort, setSort] = useState<Sort | null>(null);
  const [limit, setLimit] = useState(RENDER_STEP);
  const [openKey, setOpenKey] = useState<string | null>(null);

  const types = useMemo(() => distinct(items.map((c) => c.type)), [items]);
  const licenses = useMemo(() => distinct(items.flatMap((c) => c.licenses)), [items]);

  // Adaptive columns/filters: only offer what the scan actually produced.
  const anyScope = useMemo(() => items.some((c) => c.scope), [items]);
  const anyVulns = useMemo(() => items.some((c) => c.vulnCount), [items]);
  const anyVendored = useMemo(() => items.some((c) => c.vendored), [items]);
  const anyEol = useMemo(() => items.some((c) => c.eol === "true"), [items]);
  const anyOutdated = useMemo(() => items.some((c) => c.outdated === "true"), [items]);

  const filtered = useMemo(
    () => selectComponents(items, filters, sort),
    [items, filters, sort],
  );

  // Reveal from the top again whenever the visible set changes.
  useEffect(() => setLimit(RENDER_STEP), [filters, sort]);

  if (total === 0) {
    return <EmptyState icon={Package}>{t("result.componentsEmpty")}</EmptyState>;
  }

  const onSort = (key: ComponentSortKey) =>
    setSort((s) =>
      s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" },
    );
  const patch = (p: Partial<ComponentFilters>) => setFilters((f) => ({ ...f, ...p }));

  const visible = filtered.slice(0, limit);
  const colCount = 4 + (anyScope ? 1 : 0) + (anyVulns ? 1 : 0);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[12rem] flex-1">
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
          >
            <option value="">{t("result.allTypes")}</option>
            {types.map((ty) => (
              <option key={ty} value={ty}>
                {ty}
              </option>
            ))}
          </Select>
        )}
        {licenses.length > 1 && (
          <Select
            value={filters.license}
            onChange={(e) => patch({ license: e.target.value })}
            aria-label={t("result.allLicenses")}
          >
            <option value="">{t("result.allLicenses")}</option>
            {licenses.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </Select>
        )}
      </div>

      {(anyVulns || anyScope || anyVendored || anyEol || anyOutdated) && (
        <div className="flex flex-wrap items-center gap-2">
          {anyVulns && (
            <FilterChip
              active={filters.hasVulns}
              onClick={() => patch({ hasVulns: !filters.hasVulns })}
            >
              {t("result.filterHasVulns")}
            </FilterChip>
          )}
          {anyScope && (
            <FilterChip
              active={filters.directOnly}
              onClick={() => patch({ directOnly: !filters.directOnly })}
            >
              {t("result.filterDirectOnly")}
            </FilterChip>
          )}
          {anyVendored && (
            <FilterChip
              active={filters.needsReview}
              onClick={() => patch({ needsReview: !filters.needsReview })}
            >
              {t("result.filterNeedsReview")}
            </FilterChip>
          )}
          {anyEol && (
            <FilterChip
              active={filters.eolOnly}
              onClick={() => patch({ eolOnly: !filters.eolOnly })}
            >
              {t("result.filterEol")}
            </FilterChip>
          )}
          {anyOutdated && (
            <FilterChip
              active={filters.outdatedOnly}
              onClick={() => patch({ outdatedOnly: !filters.outdatedOnly })}
            >
              {t("result.filterOutdated")}
            </FilterChip>
          )}
        </div>
      )}

      <div className="text-xs text-muted-foreground">
        {t("result.componentsCount", { shown: filtered.length, total })}
        {truncated ? ` · ${t("result.truncated")}` : ""}
      </div>

      <div className="max-h-[44rem] min-h-[16rem] resize-y overflow-auto rounded-md border">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
            <tr className="border-b">
              <SortHeader label={t("result.colName")} sortKey="name" sort={sort} onSort={onSort} />
              <SortHeader label={t("result.colVersion")} sortKey="version" sort={sort} onSort={onSort} />
              <SortHeader label={t("result.colType")} sortKey="type" sort={sort} onSort={onSort} />
              {anyScope && (
                <SortHeader label={t("result.colScope")} sortKey="scope" sort={sort} onSort={onSort} />
              )}
              {anyVulns && (
                <SortHeader label={t("result.colRisk")} sortKey="risk" sort={sort} onSort={onSort} />
              )}
              <th className="px-3 py-2 font-medium">{t("result.colLicense")}</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((c, i) => {
              const key = c.purl || `${c.name}-${i}`;
              const isOpen = openKey === key;
              const toggle = () => setOpenKey(isOpen ? null : key);
              return (
              <Fragment key={key}>
              {/* role="button" makes aria-expanded valid here (it is not allowed
                  on a plain table row) and, with tabIndex + the key handler,
                  keeps the expandable row reachable by keyboard. */}
              <tr
                className="cursor-pointer border-b last:border-0 hover:bg-accent/50"
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
                <td className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <Package className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    <span className="font-mono">
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
                <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground">
                  {c.version || "—"}
                </td>
                <td className="px-3 py-2 text-muted-foreground">{c.type || "—"}</td>
                {anyScope && (
                  <td className="px-3 py-2">
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
                {anyVulns && (
                  <td className="px-3 py-2">
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
                <td className="px-3 py-2">
                  {c.licenses.length ? (
                    <div className="flex flex-wrap gap-1">
                      {c.licenses.map((l, j) => (
                        <Badge key={j} variant="muted">
                          {l}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">{t("result.licenseNone")}</span>
                  )}
                </td>
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
                          <dd>
                            {c.maxSeverity ? `${t(`severity.${c.maxSeverity}`)} · ` : ""}
                            {c.vulnCount}
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
            {filtered.length === 0 && (
              <tr>
                <td colSpan={colCount} className="px-3 py-6 text-center text-muted-foreground">
                  {t("result.noMatch")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {filtered.length > limit && (
        <button
          type="button"
          onClick={() => setLimit((n) => n + RENDER_STEP)}
          className={cn(
            "w-full rounded-md border border-dashed py-2 text-xs font-medium text-muted-foreground",
            "transition-colors duration-fast ease-out-soft hover:bg-muted hover:text-foreground",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
          )}
        >
          {t("result.showMore", {
            count: Math.min(RENDER_STEP, filtered.length - limit),
          })}
        </button>
      )}
    </div>
  );
}
