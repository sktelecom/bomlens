import { Scale } from "lucide-react";
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

/** i18n key per tier, for anywhere that names a tier outside this bar. */
export const TIER_LABEL = LABEL;

/**
 * Fill for a tier behind text — the distribution list draws its label on top of
 * the bar, so these are the translucent counterparts of BAR above. Same hues, so
 * one colour language covers both charts.
 *
 * Permissive and uncategorized stay neutral: tinting every row would leave
 * nothing standing out, and neither one is a finding.
 */
export const TIER_FILL: Record<LicenseRiskTier, string> = {
  "network-copyleft": "bg-risk-critical/30",
  "strong-copyleft": "bg-risk-high/30",
  "weak-copyleft": "bg-risk-medium/30",
  "review-needed": "bg-amber-500/25",
  uncategorized: "bg-muted-foreground/20",
  permissive: "bg-muted-foreground/20",
};

/** Tiers that carry an obligation worth a second look, so they get a badge. */
export const TIER_FLAGGED: ReadonlySet<LicenseRiskTier> = new Set([
  "network-copyleft",
  "strong-copyleft",
  "weak-copyleft",
  "review-needed",
]);

/**
 * The marker beside a flagged license in the distribution list. It exists so the
 * tint is not the only thing saying "this one has obligations" — colour alone
 * fails anyone who cannot separate these hues, and a translucent fill is easy to
 * miss regardless. Names its tier, so hovering or reading it aloud is specific.
 */
export function TierBadge({ tier }: { tier: LicenseRiskTier }) {
  const { t } = useTranslation();
  const label = t(TIER_LABEL[tier]);
  return (
    <span title={label} className="flex shrink-0 items-center">
      <Scale className="h-3.5 w-3.5 text-muted-foreground" role="img" aria-label={label} />
    </span>
  );
}

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
