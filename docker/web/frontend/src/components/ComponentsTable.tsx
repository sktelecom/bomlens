import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Package, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import type { ComponentItem } from "@/lib/api";

interface Props {
  items: ComponentItem[];
  total: number;
  truncated?: boolean;
}

/** Searchable, scrollable table of detected SBOM components. */
export function ComponentsTable({ items, total, truncated }: Props) {
  const { t } = useTranslation();
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((c) =>
      `${c.name} ${c.group} ${c.version} ${c.type} ${c.licenses.join(" ")}`
        .toLowerCase()
        .includes(needle),
    );
  }, [items, q]);

  if (total === 0) {
    return (
      <p className="text-sm text-muted-foreground">{t("result.componentsEmpty")}</p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={t("result.componentsSearch")}
          className="pl-8"
        />
      </div>

      <div className="text-xs text-muted-foreground">
        {t("result.componentsCount", { shown: filtered.length, total })}
        {truncated ? ` · ${t("result.truncated")}` : ""}
      </div>

      <div className="max-h-[28rem] overflow-auto rounded-md border">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
            <tr className="border-b">
              <th className="px-3 py-2 font-medium">{t("result.colName")}</th>
              <th className="px-3 py-2 font-medium">{t("result.colVersion")}</th>
              <th className="px-3 py-2 font-medium">{t("result.colType")}</th>
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
