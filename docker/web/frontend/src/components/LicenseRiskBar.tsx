import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import type { ComponentItem } from "@/lib/api";
import {
  LICENSE_TIER_ORDER,
  type LicenseRiskTier,
  licenseRiskSummary,
} from "@/lib/licenses";
import { cn } from "@/lib/utils";

const TONE: Record<
  LicenseRiskTier,
  "critical" | "high" | "medium" | "low" | "info"
> = {
  "network-copyleft": "critical",
  "strong-copyleft": "high",
  "weak-copyleft": "medium",
  "review-needed": "medium",
  uncategorized: "info",
  permissive: "low",
};

// Bar segment fill. review-needed uses amber so it reads apart from weak's gold
// when both are present (the existing review card is amber too).
const BAR: Record<LicenseRiskTier, string> = {
  "network-copyleft": "bg-risk-critical",
  "strong-copyleft": "bg-risk-high",
  "weak-copyleft": "bg-risk-medium",
  "review-needed": "bg-amber-500",
  uncategorized: "bg-risk-info",
  permissive: "bg-risk-low",
};

const LABEL: Record<LicenseRiskTier, string> = {
  "network-copyleft": "licenses.tier.networkCopyleft",
  "strong-copyleft": "licenses.tier.strongCopyleft",
  "weak-copyleft": "licenses.tier.weakCopyleft",
  "review-needed": "licenses.tier.reviewNeeded",
  uncategorized: "licenses.tier.uncategorized",
  permissive: "licenses.tier.permissive",
};

interface Props {
  components: ComponentItem[];
  /**
   * When set, the bar segments and legend badges become filter controls: the
   * caller owns `selected` and `onSelect` toggles it (re-selecting clears).
   * Omit for a static read-out (e.g. the Overview).
   */
  selected?: LicenseRiskTier | "";
  onSelect?: (tier: LicenseRiskTier) => void;
}

/**
 * License classification axis, mirroring SeverityBar: a proportional stacked bar
 * over per-tier badges, graded by copyleft strength. An unknown license shows as
 * `uncategorized`, never folded into permissive — so the bar never overstates how
 * safe the bill of materials is. With `onSelect`, clicking a tier filters.
 */
export function LicenseRiskBar({
  components,
  selected = "",
  onSelect,
}: Props) {
  const { t } = useTranslation();
  const summary = useMemo(() => licenseRiskSummary(components), [components]);
  const total = summary.TOTAL;
  const interactive = Boolean(onSelect);

  if (total === 0) return null;

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-sm font-medium">{t("result.licenseClassTitle")}</span>
        {interactive && (
          <span className="text-xs text-muted-foreground">
            {t("result.licenseClassFilterHint")}
          </span>
        )}
      </div>
      <div
        className="flex h-2.5 w-full origin-left animate-grow-x overflow-hidden rounded-full bg-muted"
        role={interactive ? "group" : "img"}
        aria-label={t("result.licenseClassTitle")}
      >
        {LICENSE_TIER_ORDER.map((tier) => {
          if (summary[tier] === 0) return null;
          const segClass = cn(
            BAR[tier],
            "h-full transition-[opacity,filter] duration-fast ease-out-soft",
            selected && selected !== tier && "opacity-30",
          );
          const segStyle = { width: `${(summary[tier] / total) * 100}%` };
          const segTitle = `${t(LABEL[tier])}: ${summary[tier]}`;
          if (!interactive) {
            return <div key={tier} className={segClass} style={segStyle} title={segTitle} />;
          }
          return (
            <button
              key={tier}
              type="button"
              aria-pressed={selected === tier}
              aria-label={`${t(LABEL[tier])} ${summary[tier]}`}
              onClick={() => onSelect?.(tier)}
              className={cn(
                segClass,
                "cursor-pointer hover:brightness-110",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              )}
              style={segStyle}
              title={segTitle}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {LICENSE_TIER_ORDER.map((tier) => {
          if (summary[tier] === 0) return null;
          const badge = (
            <Badge tone={TONE[tier]}>
              {t(LABEL[tier])} {summary[tier]}
            </Badge>
          );
          if (!interactive) return <span key={tier}>{badge}</span>;
          const isSel = selected === tier;
          return (
            <button
              key={tier}
              type="button"
              aria-pressed={isSel}
              onClick={() => onSelect?.(tier)}
              className={cn(
                "rounded-full transition duration-fast ease-out-soft",
                "cursor-pointer hover:opacity-80",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                isSel && "ring-2 ring-foreground ring-offset-1",
                Boolean(selected) && !isSel && "opacity-60",
              )}
            >
              {badge}
            </button>
          );
        })}
      </div>
    </div>
  );
}
