import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { ArrowDown, ArrowUp, ArrowUpDown, Package, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/state";
import type { ComponentItem } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Props {
  items: ComponentItem[];
  total: number;
  truncated?: boolean;
}

type SortKey = "name" | "version" | "type";
type Sort = { key: SortKey; dir: "asc" | "desc" };

const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

/** Distinct, sorted, non-empty values. */
function distinct(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: "base" }),
  );
}

function sortValue(c: ComponentItem, key: SortKey): string {
  if (key === "name") return `${c.group} ${c.name}`.trim();
  return c[key] || "";
}

function SortHeader({
  label,
  sortKey,
  sort,
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  sort: Sort | null;
  onSort: (key: SortKey) => void;
}) {
  const active = sort?.key === sortKey;
  const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <th
      className="px-3 py-2 font-medium"
      aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        {label}
        <Icon
          className={cn(
            "h-3 w-3",
            active ? "text-foreground" : "text-muted-foreground/60",
          )}
          aria-hidden
        />
      </button>
    </th>
  );
}

/** Searchable, sortable, filterable table of detected SBOM components. */
export function ComponentsTable({ items, total, truncated }: Props) {
  const { t } = useTranslation();
  const [q, setQ] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [licenseFilter, setLicenseFilter] = useState("");
  const [sort, setSort] = useState<Sort | null>(null);

  const types = useMemo(() => distinct(items.map((c) => c.type)), [items]);
  const licenses = useMemo(
    () => distinct(items.flatMap((c) => c.licenses)),
    [items],
  );

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let rows = items;
    if (needle) {
      rows = rows.filter((c) =>
        `${c.name} ${c.group} ${c.version} ${c.type} ${c.licenses.join(" ")}`
          .toLowerCase()
          .includes(needle),
      );
    }
    if (typeFilter) rows = rows.filter((c) => c.type === typeFilter);
    if (licenseFilter)
      rows = rows.filter((c) => c.licenses.includes(licenseFilter));
    if (sort) {
      const factor = sort.dir === "asc" ? 1 : -1;
      rows = [...rows].sort(
        (a, b) =>
          factor *
          sortValue(a, sort.key).localeCompare(sortValue(b, sort.key), undefined, {
            numeric: true,
            sensitivity: "base",
          }),
      );
    }
    return rows;
  }, [items, q, typeFilter, licenseFilter, sort]);

  if (total === 0) {
    return <EmptyState icon={Package}>{t("result.componentsEmpty")}</EmptyState>;
  }

  const onSort = (key: SortKey) =>
    setSort((s) =>
      s?.key === key
        ? { key, dir: s.dir === "asc" ? "desc" : "asc" }
        : { key, dir: "asc" },
    );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[12rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t("result.componentsSearch")}
            className="pl-8"
          />
        </div>
        {types.length > 1 && (
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className={SELECT_CLASS}
            aria-label={t("result.allTypes")}
          >
            <option value="">{t("result.allTypes")}</option>
            {types.map((ty) => (
              <option key={ty} value={ty}>
                {ty}
              </option>
            ))}
          </select>
        )}
        {licenses.length > 1 && (
          <select
            value={licenseFilter}
            onChange={(e) => setLicenseFilter(e.target.value)}
            className={SELECT_CLASS}
            aria-label={t("result.allLicenses")}
          >
            <option value="">{t("result.allLicenses")}</option>
            {licenses.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        )}
      </div>

      <div className="text-xs text-muted-foreground">
        {t("result.componentsCount", { shown: filtered.length, total })}
        {truncated ? ` · ${t("result.truncated")}` : ""}
      </div>

      <div className="max-h-[28rem] overflow-auto rounded-md border">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
            <tr className="border-b">
              <SortHeader
                label={t("result.colName")}
                sortKey="name"
                sort={sort}
                onSort={onSort}
              />
              <SortHeader
                label={t("result.colVersion")}
                sortKey="version"
                sort={sort}
                onSort={onSort}
              />
              <SortHeader
                label={t("result.colType")}
                sortKey="type"
                sort={sort}
                onSort={onSort}
              />
              <th className="px-3 py-2 font-medium">{t("result.colLicense")}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((c, i) => (
              <tr
                key={c.purl || `${c.name}-${i}`}
                className="border-b last:border-0 hover:bg-accent/50"
              >
                <td className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <Package className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    <span className="font-mono">
                      {c.group ? `${c.group} / ` : ""}
                      {c.name}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground">
                  {c.version || "—"}
                </td>
                <td className="px-3 py-2 text-muted-foreground">{c.type || "—"}</td>
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
                    <span className="text-muted-foreground">
                      {t("result.licenseNone")}
                    </span>
                  )}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td
                  colSpan={4}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  {t("result.noMatch")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
