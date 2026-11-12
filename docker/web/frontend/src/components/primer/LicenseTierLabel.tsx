// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Label } from "@primer/react";
import { useTranslation } from "react-i18next";

import { Marker } from "@/components/ui/marker";
import type { LicenseRiskTier } from "@/lib/licenses";

import { TIER_LABEL_KEY, tierBorder, tierFg, tierShape } from "./display";

/**
 * A licence tier as a Primer Label in the tier's display colour, with the
 * tier's own marker shape and its name.
 */
export function LicenseTierLabel({ tier, size }: { tier: LicenseRiskTier; size?: "small" | "large" }) {
  const { t } = useTranslation();
  return (
    <Label size={size} data-tier={tier} style={{ color: tierFg(tier), borderColor: tierBorder(tier) }}>
      <Marker shape={tierShape(tier)} className="mr-1" />
      {t(TIER_LABEL_KEY[tier])}
    </Label>
  );
}

/** The tier's marker on its own, in the tier colour (for legends and bars). */
export function LicenseTierMark({ tier }: { tier: LicenseRiskTier }) {
  return (
    <span className="inline-flex" style={{ color: tierFg(tier) }}>
      <Marker shape={tierShape(tier)} />
    </span>
  );
}
