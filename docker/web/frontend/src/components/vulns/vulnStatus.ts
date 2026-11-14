// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { VexState } from "@/lib/api";

// Vendor/advisory disposition: the words for a status and for the supplier's own
// judgement. They are shown as labels beside a vulnerability (see cells.tsx);
// the supplier's judgement is labelled "Judgement: ..." so the two are never
// mistaken for one axis.
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

export const VEX_LABEL_KEY: Record<VexState, string> = {
  affected: "result.vexStateAffected",
  not_affected: "result.vexStateNotAffected",
  fixed: "result.vexStateFixed",
  under_investigation: "result.vexStateUnderInvestigation",
};
