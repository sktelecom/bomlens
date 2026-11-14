// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "@primer/react";
import { useTranslation } from "react-i18next";

import { LicenseTierMark, tierFill, TIER_LABEL_KEY } from "@/components/primer";
import type { ComponentItem } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { LICENSE_TIER_ORDER, type LicenseRiskTier, licenseRiskSummary } from "@/lib/licenses";

import { useTierHint } from "./tierHint";

/**
 * The classification bar and its legend. Both are filter toggles (aria-pressed;
 * choosing the chosen class again clears it). The bar always shows the whole
 * scan's proportions: filtering it by its own choice would erase what was
 * picked, so a chosen class dims the others instead.
 */
export function TierBar({
  components,
  selected,
  shownCount,
  onSelect,
  onClear,
}: {
  components: ComponentItem[];
  selected: LicenseRiskTier | "";
  /** How many components the screen shows under the chosen class. */
  shownCount: number;
  onSelect: (tier: LicenseRiskTier) => void;
  onClear: () => void;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const hint = useTierHint();
  const summary = licenseRiskSummary(components);
  const total = summary.TOTAL;
  if (total === 0) return null;
  const present = LICENSE_TIER_ORDER.filter((tier) => summary[tier] > 0);
  return (
    <section className="bl-box" aria-labelledby="lic-class" data-testid="license-classes">
      <div className="bl-box-head">
        <h2 id="lic-class">{t("result.licenseClassTitle")}</h2>
        <span className="bl-muted bl-small bl-box-head-end">{t("result.licenseClassFilterHint")}</span>
      </div>
      <div className="bl-box-body">
        <div className="bl-ovbar bl-ovbar-lic bl-lic-bar" role="group" aria-label={t("result.licenseClassTitle")}>
          {present.map((tier) => (
            <button
              key={tier}
              type="button"
              aria-pressed={selected === tier}
              aria-label={`${t(TIER_LABEL_KEY[tier])} ${fmt(summary[tier])}`}
              title={`${t(TIER_LABEL_KEY[tier])}: ${fmt(summary[tier])}. ${hint(tier)}`}
              data-dim={selected && selected !== tier ? "" : undefined}
              onClick={() => onSelect(tier)}
              style={{ flex: summary[tier] / total, background: tierFill(tier) }}
            />
          ))}
        </div>
        <div className="bl-tierlegend">
          {present.map((tier) => (
            <button
              key={tier}
              type="button"
              className="bl-tierchip"
              aria-pressed={selected === tier}
              title={hint(tier)}
              onClick={() => onSelect(tier)}
            >
              <LicenseTierMark tier={tier} />
              {t(TIER_LABEL_KEY[tier])}
              <span className="bl-muted bl-num">{fmt(summary[tier])}</span>
            </button>
          ))}
        </div>
        {/* Always mounted so a screen reader hears the change; empty (and so
            without height) while no class is chosen. */}
        <p className="bl-muted bl-small bl-flat bl-lic-note" aria-live="polite" data-testid="license-tier-note">
          {selected && (
            <>
              {summary[selected] > 0
                ? t("licenses.tierFiltered", { tier: t(TIER_LABEL_KEY[selected]), count: shownCount })
                : t("licenses.tierEmpty", { tier: t(TIER_LABEL_KEY[selected]) })}{" "}
              <Link as="button" onClick={onClear} className="bl-lic-clear">
                {t("result.clearFilters")}
              </Link>
            </>
          )}
        </p>
      </div>
    </section>
  );
}
