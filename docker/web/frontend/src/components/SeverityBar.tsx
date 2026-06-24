import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { SEVERITY_ORDER, type SecuritySummary, type Severity } from "@/lib/api";
import { cn } from "@/lib/utils";

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

interface Props {
  security: SecuritySummary;
  /**
   * When set, the bar segments and legend badges become filter controls: the
   * caller owns `selected` and `onSelect` toggles it (re-selecting clears).
   * Omit for a static read-out (e.g. the Overview).
   */
  selected?: Severity | "";
  onSelect?: (s: Severity) => void;
}

export function SeverityBar({ security, selected = "", onSelect }: Props) {
  const { t } = useTranslation();
  const total = security.TOTAL;
  const interactive = Boolean(onSelect);

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-sm font-medium">{t("result.severityTitle")}</span>
        {interactive && total > 0 && (
          <span className="text-xs text-muted-foreground">{t("result.severityFilterHint")}</span>
        )}
      </div>
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
                  className={cn(
                    BAR[s],
                    "transition-opacity duration-fast ease-out-soft",
                    // Dim the non-selected bands while a filter is active.
                    selected && selected !== s && "opacity-30",
                  )}
                  style={{ width: `${(security[s] / total) * 100}%` }}
                  title={`${t(`severity.${s}`)}: ${security[s]}`}
                />
              ) : null,
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SEVERITY_ORDER.map((s) => {
              const badge = (
                <Badge tone={TONE[s]}>
                  {t(`severity.${s}`)} {security[s]}
                </Badge>
              );
              if (!interactive) return <span key={s}>{badge}</span>;
              const isSel = selected === s;
              return (
                <button
                  key={s}
                  type="button"
                  disabled={security[s] === 0}
                  aria-pressed={isSel}
                  onClick={() => onSelect?.(s)}
                  className={cn(
                    "rounded-full transition duration-fast ease-out-soft",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                    security[s] === 0
                      ? "cursor-not-allowed opacity-40"
                      : "cursor-pointer hover:opacity-80",
                    isSel && "ring-2 ring-foreground ring-offset-1",
                    Boolean(selected) && !isSel && "opacity-60",
                  )}
                >
                  {badge}
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
