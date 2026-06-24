import { Fragment, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/state";
import { type SecuritySummary, type Severity, type VulnItem } from "@/lib/api";
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

interface Props {
  security: SecuritySummary;
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

/** Expanded detail for one CVE — CVSS, description and reference links. */
function VulnDetail({ vuln, links }: { vuln: VulnItem; links: string[] }) {
  const { t } = useTranslation();
  if (vuln.cvss == null && !vuln.description && links.length === 0) {
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
    </div>
  );
}

/**
 * Vulnerabilities sorted by severity. Each row expands in place to show the
 * CVSS score, description and reference links already present in the Trivy
 * report — no extra fetch, no side panel.
 */
export function VulnerabilitiesTable({ security }: Props) {
  const { t } = useTranslation();
  const items = security.vulnerabilities ?? [];
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("");
  // Default: most severe first, highest CVSS within a severity band.
  const [sort, setSort] = useState<Sort>({ key: "severity", dir: "desc" });

  // EPSS column appears only when the report was enriched (online run).
  const anyEpss = useMemo(() => items.some((v) => typeof v.epss === "number"), [items]);

  const sorted = useMemo(
    () => [...items].sort((a, b) => compareVulns(a, b, sort.key, sort.dir)),
    [items, sort],
  );
  const onSort = (key: VulnSortKey) =>
    setSort((s) =>
      s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" },
    );

  if (security.TOTAL === 0 || items.length === 0) {
    return <EmptyState icon={ShieldCheck}>{t("result.noVulns")}</EmptyState>;
  }

  const visible = severityFilter
    ? sorted.filter((v) => v.severity === severityFilter)
    : sorted;

  return (
    <div className="space-y-4">
      <SeverityBar
        security={security}
        selected={severityFilter as Severity | ""}
        onSelect={(s) => setSeverityFilter((f) => (f === s ? "" : s))}
      />
      <div className="max-h-[28rem] overflow-auto rounded-md border">
        <table className="w-full text-left text-xs">
        <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
          <tr className="border-b">
            <SortableTh label={t("result.colSeverity")} sortKey="severity" sort={sort} onSort={onSort} />
            <SortableTh label={t("result.vulnCvss")} sortKey="cvss" sort={sort} onSort={onSort} />
            {anyEpss && (
              <SortableTh label={t("result.colEpss")} sortKey="epss" sort={sort} onSort={onSort} />
            )}
            <th className="px-3 py-2 font-medium">{t("result.colCve")}</th>
            <th className="px-3 py-2 font-medium">{t("result.colPackage")}</th>
            <th className="px-3 py-2 font-medium">{t("result.colInstalled")}</th>
            <th className="px-3 py-2 font-medium">{t("result.colFixed")}</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((v, i) => {
            const key = `${v.id}-${v.pkg}-${i}`;
            const isOpen = openKey === key;
            const links = vulnLinks(v);
            const hasDetail =
              v.cvss != null || !!v.description || links.length > 0;
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
                  <td className="px-3 py-2 font-mono tabular-nums">
                    {v.fixed ? (
                      <span className="text-emerald-600 dark:text-emerald-400">
                        {v.fixed}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr className="border-b last:border-0">
                    <td colSpan={anyEpss ? 7 : 6} className="bg-muted/30 px-3 py-3">
                      <VulnDetail vuln={v} links={links} />
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
