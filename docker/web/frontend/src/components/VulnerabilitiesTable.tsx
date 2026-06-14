import { Fragment, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronRight, ExternalLink, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/state";
import { SEVERITY_ORDER, type SecuritySummary, type VulnItem } from "@/lib/api";
import { cn } from "@/lib/utils";

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

  const sorted = useMemo(() => {
    const rank = (s: string) => {
      const i = SEVERITY_ORDER.indexOf(s as (typeof SEVERITY_ORDER)[number]);
      return i === -1 ? SEVERITY_ORDER.length : i;
    };
    return [...items].sort((a, b) => rank(a.severity) - rank(b.severity));
  }, [items]);

  if (security.TOTAL === 0 || items.length === 0) {
    return <EmptyState icon={ShieldCheck}>{t("result.noVulns")}</EmptyState>;
  }

  return (
    <div className="max-h-[28rem] overflow-auto rounded-md border">
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
          <tr className="border-b">
            <th className="px-3 py-2 font-medium">{t("result.colSeverity")}</th>
            <th className="px-3 py-2 font-medium">{t("result.colCve")}</th>
            <th className="px-3 py-2 font-medium">{t("result.colPackage")}</th>
            <th className="px-3 py-2 font-medium">{t("result.colInstalled")}</th>
            <th className="px-3 py-2 font-medium">{t("result.colFixed")}</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((v, i) => {
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
                    </div>
                  </td>
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
                    <td colSpan={5} className="bg-muted/30 px-3 py-3">
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
  );
}
