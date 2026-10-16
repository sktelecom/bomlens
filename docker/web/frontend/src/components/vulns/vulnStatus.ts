// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { VexState } from "@/lib/api";

// Vendor/advisory disposition badge, shown beside the severity badge. `fixed`
// only says a fixed version is published, not that the installed one is fixed,
// so it stays informational; green is kept for VEX states that declare a
// resolution (VEX_TONE below). The still-open dispositions read as a caution
// (medium); dispositions that are informational rather than actionable stay
// neutral (info) — same three-tier logic as the severity/EOL/outdated badges
// elsewhere in this table.
export const STATUS_TONE: Record<string, "success" | "medium" | "info"> = {
  fixed: "info",
  affected: "medium",
  will_not_fix: "medium",
  end_of_life: "medium",
  fix_deferred: "info",
  under_investigation: "info",
};

export const STATUS_LABEL_KEY: Record<string, string> = {
  fixed: "result.statusFixed",
  affected: "result.statusAffected",
  will_not_fix: "result.statusWillNotFix",
  end_of_life: "result.statusEndOfLife",
  fix_deferred: "result.statusFixDeferred",
  under_investigation: "result.statusUnderInvestigation",
};

export const STATUS_HINT_KEY: Record<string, string> = {
  fixed: "result.statusFixedHint",
  affected: "result.statusAffectedHint",
  will_not_fix: "result.statusWillNotFixHint",
  end_of_life: "result.statusEndOfLifeHint",
  fix_deferred: "result.statusFixDeferredHint",
  under_investigation: "result.statusUnderInvestigationHint",
};

// The supplier's own judgement (POST /vex-verdict), badged separately from
// STATUS_TONE above (the vendor/advisory's own disposition) with its own
// "Judgement: …" wording so the two are never mistaken for one axis.
export const VEX_TONE: Record<VexState, "success" | "medium" | "info"> = {
  fixed: "success",
  not_affected: "success",
  affected: "medium",
  under_investigation: "info",
};

export const VEX_LABEL_KEY: Record<VexState, string> = {
  affected: "result.vexStateAffected",
  not_affected: "result.vexStateNotAffected",
  fixed: "result.vexStateFixed",
  under_investigation: "result.vexStateUnderInvestigation",
};
