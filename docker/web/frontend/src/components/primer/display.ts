// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * How BomLens-only values are drawn with Primer: the severity Label, the
 * licence tier colour and the package coordinate. Pure data so the mapping is
 * unit tested; the components in this folder only render it.
 *
 * Every colour is a Primer variable (or an index.css token behind one), never a
 * literal. Low and unknown severities are neutral (`secondary`), so a Low
 * finding never reads as the navy accent.
 */
import type { LabelColorOptions } from "@primer/react";

import { SEVERITY_SHAPE, TIER_SHAPE, type MarkerShape } from "@/components/ui/marker";
import type { LicenseRiskTier } from "@/lib/licenses";
import { severityTone } from "@/lib/severity";

/** Primer Label variant per CVSS grade. Anything unmapped is neutral. */
export const SEVERITY_LABEL_VARIANT: Readonly<Record<string, LabelColorOptions>> = {
  CRITICAL: "danger",
  HIGH: "severe",
  MEDIUM: "attention",
  LOW: "secondary",
  UNKNOWN: "secondary",
  NONE: "secondary",
};

export function severityLabelVariant(severity: string | null | undefined): LabelColorOptions {
  return SEVERITY_LABEL_VARIANT[severity ?? ""] ?? "secondary";
}

/** The shape that carries the grade next to its word (colour is never alone). */
export function severityShape(severity: string | null | undefined): MarkerShape {
  return SEVERITY_SHAPE[severityTone(severity)];
}

/** Bar and chart fill per grade. Low and unknown stay neutral. */
export const SEVERITY_FILL: Readonly<Record<string, string>> = {
  CRITICAL: "var(--bgColor-danger-emphasis)",
  HIGH: "var(--bgColor-severe-emphasis)",
  MEDIUM: "var(--bgColor-attention-emphasis)",
  LOW: "var(--display-gray-bgColor-emphasis)",
  UNKNOWN: "var(--borderColor-default)",
  NONE: "var(--borderColor-default)",
};

export function severityFill(severity: string | null | undefined): string {
  return SEVERITY_FILL[severity ?? ""] ?? SEVERITY_FILL.UNKNOWN;
}

/** The i18n key of a grade's word (`severity.CRITICAL` ...). */
export function severityLabelKey(severity: string | null | undefined): string {
  const s = severity && severity in SEVERITY_LABEL_VARIANT ? severity : "UNKNOWN";
  return `severity.${s}`;
}

/**
 * Licence tier colours from Primer's display palette. None of them is the
 * accent or a severity hue, so a licence never reads as a finding.
 */
export const TIER_DISPLAY_COLOR: Readonly<Record<LicenseRiskTier, string>> = {
  "network-copyleft": "pink",
  "strong-copyleft": "purple",
  "weak-copyleft": "olive",
  "review-needed": "brown",
  uncategorized: "gray",
  permissive: "teal",
};

/** The i18n key of a tier's name. */
export const TIER_LABEL_KEY: Readonly<Record<LicenseRiskTier, string>> = {
  "network-copyleft": "licenses.tier.networkCopyleft",
  "strong-copyleft": "licenses.tier.strongCopyleft",
  "weak-copyleft": "licenses.tier.weakCopyleft",
  "review-needed": "licenses.tier.reviewNeeded",
  uncategorized: "licenses.tier.uncategorized",
  permissive: "licenses.tier.permissive",
};

/** Text and marker colour of a tier. */
export const tierFg = (tier: LicenseRiskTier) => `var(--display-${TIER_DISPLAY_COLOR[tier]}-fgColor)`;
/** Bar fill of a tier. */
export const tierFill = (tier: LicenseRiskTier) =>
  `var(--display-${TIER_DISPLAY_COLOR[tier]}-bgColor-emphasis)`;
/** Outline of a tier Label. */
export const tierBorder = (tier: LicenseRiskTier) =>
  `var(--display-${TIER_DISPLAY_COLOR[tier]}-borderColor-emphasis)`;

export function tierShape(tier: LicenseRiskTier): MarkerShape {
  return TIER_SHAPE[tier];
}

/** The one separator between a package's group (or namespace) and its name. */
export const PACKAGE_SEPARATOR = " / ";

export interface PackageCoordinateParts {
  group?: string;
  name: string;
}

/** "org.springframework / spring-core", or the bare name when there is no group. */
export function packageCoordinateText({ group, name }: PackageCoordinateParts): string {
  return group ? `${group}${PACKAGE_SEPARATOR}${name}` : name;
}

/**
 * Split a "group:name" label (Maven style, as the scanner writes it) at the last
 * colon. A label without a colon is a bare name.
 */
export function splitPackage(label: string): PackageCoordinateParts {
  const i = label.lastIndexOf(":");
  if (i <= 0 || i === label.length - 1) return { name: label };
  return { group: label.slice(0, i), name: label.slice(i + 1) };
}
