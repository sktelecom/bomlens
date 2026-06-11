import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_ORDER, type SecuritySummary } from "@/lib/api";

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

/** Scrollable table of detected vulnerabilities, sorted by severity. */
export function VulnerabilitiesTable({ security }: Props) {
  const { t } = useTranslation();
  const items = security.vulnerabilities ?? [];

  const sorted = useMemo(() => {
    const rank = (s: string) => {
      const i = SEVERITY_ORDER.indexOf(s as (typeof SEVERITY_ORDER)[number]);
      return i === -1 ? SEVERITY_ORDER.length : i;
    };
    return [...items].sort((a, b) => rank(a.severity) - rank(b.severity));
  }, [items]);

  if (security.TOTAL === 0 || items.length === 0) {
    return <p className="text-sm text-muted-foreground">{t("result.noVulns")}</p>;
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
          {sorted.map((v, i) => (
            <tr
              key={`${v.id}-${v.pkg}-${i}`}
              className="border-b align-top last:border-0 hover:bg-accent/50"
            >
              <td className="px-3 py-2">
                <Badge tone={TONE[v.severity] ?? "info"}>
                  {t(`severity.${v.severity}`)}
                </Badge>
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
          ))}
        </tbody>
      </table>
    </div>
  );
}
