import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { SEVERITY_ORDER, type SecuritySummary, type Severity } from "@/lib/api";

const TONE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

const BAR: Record<Severity, string> = {
  CRITICAL: "bg-risk-critical",
  HIGH: "bg-risk-high",
  MEDIUM: "bg-risk-medium",
  LOW: "bg-risk-low",
  UNKNOWN: "bg-risk-info",
};

export function SeverityBar({ security }: { security: SecuritySummary }) {
  const { t } = useTranslation();
  const total = security.TOTAL;

  return (
    <div className="space-y-3">
      <div className="text-sm font-medium">{t("result.severityTitle")}</div>
      {total === 0 ? (
        <p className="text-sm text-muted-foreground">{t("result.noVulns")}</p>
      ) : (
        <>
          <div
            className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted"
            role="img"
            aria-label={t("result.severityTitle")}
          >
            {SEVERITY_ORDER.map((s) =>
              security[s] > 0 ? (
                <div
                  key={s}
                  className={BAR[s]}
                  style={{ width: `${(security[s] / total) * 100}%` }}
                  title={`${t(`severity.${s}`)}: ${security[s]}`}
                />
              ) : null,
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SEVERITY_ORDER.map((s) => (
              <Badge key={s} tone={TONE[s]}>
                {t(`severity.${s}`)} {security[s]}
              </Badge>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
