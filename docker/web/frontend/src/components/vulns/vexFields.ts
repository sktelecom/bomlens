// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { VexState, VulnItem } from "@/lib/api";

/** Primary advisory URL first, then references, de-duplicated. */
export function vulnLinks(v: VulnItem): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const u of [v.url, ...(v.refs ?? [])]) {
    if (u && !seen.has(u)) {
      seen.add(u);
      out.push(u);
    }
  }
  return out;
}

/** A row's own saved fields, or a not-yet-persisted local edit overriding
 *  them (set right after a successful save, before the next full reload). */
export interface VexFields {
  state?: VexState;
  detail?: string;
  updatedAt?: string;
}

/** Same identity a saved verdict is keyed by: purl when the row has one,
 *  otherwise pkg+installed (matching the server's own purl-then-fallback
 *  join in security_summary/_vex_verdict_index). */
export function vexKey(v: VulnItem): string {
  return `${v.purl || `${v.pkg}@${v.installed}`}::${v.id}`;
}
