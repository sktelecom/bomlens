// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

import type { LicenseRiskTier } from "@/lib/licenses";

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
 * note, in the current UI language. The class names stay English in both
 * languages, so this text is what makes them readable.
 */
export function useTierHint(): (tier: LicenseRiskTier) => string {
  const { t } = useTranslation();
  return (tier) => `${t(HINT[tier])} ${t("licenses.tierHintNote")}`;
}
