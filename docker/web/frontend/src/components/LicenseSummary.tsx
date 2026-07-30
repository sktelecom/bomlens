// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { BarList, type BarDatum } from "@/components/ui/barlist";
import type { ComponentItem } from "@/lib/api";
import { licenseGroups, licenseRiskTier } from "@/lib/licenses";

import { TIER_FILL, TIER_FLAGGED, TierBadge } from "./LicenseRiskBar";

/** Rows shown before the "+N more" line, when the caller asks for a short list. */
const TOP = 8;

/**
 * License distribution: how many components declare each license, as
 * proportional bars so the permissive bulk vs. the long tail reads at a glance.
 * Reuses the SBOM component data already shown in the Components section — no
 * extra computation beyond grouping.
 *
 * The Licenses section shows the full list and makes each row a link into the
 * Components table filtered to that license; a caller that only wants a preview
 * passes `limit`.
 */
export function LicenseSummary({
  components,
  limit,
  onPickLicense,
}: {
  components: ComponentItem[];
  /** Show at most this many licenses, with a "+N more" line. Omit for all. */
  limit?: number;
  /** Open the Components table filtered to this license id. Rows stay inert
   *  when absent — and the unlicensed bucket always does, since the Components
   *  license filter selects an id and has no "none" option. */
  onPickLicense?: (license: string) => void;
}) {
  const { t } = useTranslation();
  const { groups, unlicensed } = useMemo(
    () => licenseGroups(components),
    [components],
  );

  if (components.length === 0) return null;

  const shown = limit === undefined ? groups : groups.slice(0, limit);
  const more = groups.length - shown.length;
  // Scale every bar to the busiest license so proportions stay comparable even
  // when the unlicensed bucket isn't the largest.
  const max = Math.max(1, groups[0]?.count ?? 0, unlicensed);

  // Same tier colouring as the Licenses section, so a bar means the same thing
  // in both places.
  const items: BarDatum[] = shown.map((g) => {
    const tier = licenseRiskTier(g.name);
    return {
      key: g.name,
      label: g.name,
      value: g.count,
      fill: TIER_FILL[tier],
      badge: TIER_FLAGGED.has(tier) ? <TierBadge tier={tier} /> : undefined,
    };
  });
  if (unlicensed > 0) {
    items.push({
      key: "__none__",
      label: t("result.licenseNone"),
      value: unlicensed,
      inert: true,
    });
  }

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-sm font-medium">
          {t("result.licenseSummaryTitle")}{" "}
          {groups.length > 0 && (
            <span className="tabular-nums text-muted-foreground">{groups.length}</span>
          )}
        </span>
        {onPickLicense && (
          <span className="text-xs text-muted-foreground">
            {t("result.licenseRowHint")}
          </span>
        )}
      </div>
      <BarList
        items={items}
        max={max}
        ariaLabel={t("result.licenseSummaryTitle")}
        onActivate={onPickLicense}
        activateHint={onPickLicense ? t("result.licenseRowHint") : undefined}
      />
      {more > 0 && (
        <div className="text-xs text-muted-foreground">
          {t("result.licenseMore", { count: more })}
        </div>
      )}
    </div>
  );
}
