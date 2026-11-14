// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Label } from "@primer/react";
import { useTranslation } from "react-i18next";

import { Marker } from "@/components/ui/marker";
import { formatNumber } from "@/lib/format";

import { severityFg, severityLabelKey, severityLabelVariant, severityShape } from "./display";

/**
 * A CVSS grade as a Primer Label: shape marker plus the word, never colour
 * alone. `count` appends a grouped number ("High 12").
 */
export function SeverityLabel({
  severity,
  count,
  size,
  quiet,
}: {
  severity: string | null | undefined;
  count?: number;
  size?: "small" | "large";
  /** Danger only for Critical; the other grades are a neutral Label with the grade's text colour (for dense lists). */
  quiet?: boolean;
}) {
  const { t, i18n } = useTranslation();
  return (
    <Label
      variant={quiet && severity !== "CRITICAL" ? "secondary" : severityLabelVariant(severity)}
      size={size}
      data-severity={severity ?? "UNKNOWN"}
      style={quiet && severity !== "CRITICAL" ? { color: severityFg(severity) } : undefined}
    >
      <Marker shape={severityShape(severity)} className="mr-1" />
      {t(severityLabelKey(severity))}
      {count !== undefined && <span className="ml-1 tabular-nums">{formatNumber(count, i18n.language)}</span>}
    </Label>
  );
}
