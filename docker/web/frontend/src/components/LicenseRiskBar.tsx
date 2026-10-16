// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Marker, TIER_SHAPE } from "@/components/ui/marker";
import { SELECTED_OUTLINE, UNSELECTED_OUTLINE } from "@/components/ui/selectable";
import type { ComponentItem } from "@/lib/api";
import {
  LICENSE_TIER_ORDER,
  type LicenseRiskTier,
  licenseRiskSummary,
} from "@/lib/licenses";
import { cn } from "@/lib/utils";
import { useFormatNumber } from "@/lib/format";

/** Licence tiers use the category palette, never the severity roles: an
 *  obligation is not a vulnerability, and two bars side by side on the Overview
 *  must not read on one scale. Review-needed and uncategorized are not findings. */
const TONE: Record<
  LicenseRiskTier,
  "catNetwork" | "catStrong" | "catWeak" | "catReview" | "catPermissive" | "info"
> = {
  "network-copyleft": "catNetwork",
  "strong-copyleft": "catStrong",
  "weak-copyleft": "catWeak",
  "review-needed": "catReview",
  uncategorized: "info",
  permissive: "catPermissive",
};

// Bar segment fill, one category colour per tier.
const BAR: Record<LicenseRiskTier, string> = {
  "network-copyleft": "bg-cat-network-emphasis",
  "strong-copyleft": "bg-cat-strong-emphasis",
  "weak-copyleft": "bg-cat-weak-emphasis",
  "review-needed": "bg-cat-review-emphasis",
  uncategorized: "bg-role-neutral-emphasis",
  permissive: "bg-cat-permissive-emphasis",
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

const HINT: Record<LicenseRiskTier, string> = {
  "network-copyleft": "licenses.tierHint.networkCopyleft",
  "strong-copyleft": "licenses.tierHint.strongCopyleft",
  "weak-copyleft": "licenses.tierHint.weakCopyleft",
  "review-needed": "licenses.tierHint.reviewNeeded",
  uncategorized: "licenses.tierHint.uncategorized",
  permissive: "licenses.tierHint.permissive",
};

/**
 * Plain-words meaning of a tier plus the shared "guidance, not legal advice"
 * note, in the current UI language. The class names themselves stay English in
 * both languages, so this text is what makes them readable.
 */
export function useTierHint(): (tier: LicenseRiskTier) => string {
  const { t } = useTranslation();
  return (tier) => `${t(HINT[tier])} ${t("licenses.tierHintNote")}`;
}

/**
 * Fill for a row in the distribution list: the tier's category colour at a low
 * alpha, so the row says which tier it is without the loud fill of the bar.
 * Permissive and uncategorized stay neutral: neither is a finding, and tinting
 * every row would leave nothing standing out. The tier is also named by the
 * marker shape and its tooltip, so the tint is never the only signal.
 */
export const TIER_FILL: Record<LicenseRiskTier, string> = {
  "network-copyleft": "bg-cat-network-emphasis/20",
  "strong-copyleft": "bg-cat-strong-emphasis/20",
  "weak-copyleft": "bg-cat-weak-emphasis/20",
  "review-needed": "bg-cat-review-emphasis/20",
  uncategorized: "bg-muted-foreground/20",
  permissive: "bg-muted-foreground/20",
};

/** Label colour per tier, the fg shade of its category (AA on card and page). */
const TIER_TEXT: Record<LicenseRiskTier, string> = {
  "network-copyleft": "text-cat-network-fg",
  "strong-copyleft": "text-cat-strong-fg",
  "weak-copyleft": "text-cat-weak-fg",
  "review-needed": "text-cat-review-fg",
  uncategorized: "text-role-neutral-fg",
  permissive: "text-cat-permissive-fg",
};

/**
 * The marker beside a license in the distribution list: a shape of its own per
 * tier, in the tier's category colour. It exists so the tint is not the only
 * thing saying which class a row belongs to; hue alone fails anyone who cannot
 * separate it, and a translucent fill is easy to miss regardless. Names its
 * tier, so hovering or reading it aloud is specific.
 */
export function TierBadge({ tier }: { tier: LicenseRiskTier }) {
  const { t } = useTranslation();
  const tierHint = useTierHint();
  const label = t(TIER_LABEL[tier]);
  return (
    <span
      title={`${label}. ${tierHint(tier)}`}
      role="img"
      aria-label={label}
      className="flex shrink-0 items-center"
    >
      <Marker shape={TIER_SHAPE[tier]} className={TIER_TEXT[tier]} />
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
  const fmt = useFormatNumber();
  const tierHint = useTierHint();
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
          const segTitle = `${t(LABEL[tier])}: ${fmt(summary[tier])}. ${tierHint(tier)}`;
          if (!interactive) {
            return <div key={tier} className={segClass} style={segStyle} title={segTitle} />;
          }
          return (
            <button
              key={tier}
              type="button"
              aria-pressed={selected === tier}
              aria-label={`${t(LABEL[tier])} ${fmt(summary[tier])}`}
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
            <Badge tone={TONE[tier]} mark={TIER_SHAPE[tier]} title={tierHint(tier)}>
              {t(LABEL[tier])} {fmt(summary[tier])}
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
                "rounded-full border border-transparent transition-colors duration-fast ease-out-soft",
                "cursor-pointer hover:opacity-80",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                // Rest-state border so this reads as pressable next to identical-
                // looking but inert badges elsewhere (see SeverityBar's own for
                // why this is a real `border`, not a low-contrast `ring`).
                isSel ? SELECTED_OUTLINE : UNSELECTED_OUTLINE,
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
