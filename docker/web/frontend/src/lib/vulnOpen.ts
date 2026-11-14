// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The id the URL carries for the vulnerability whose detail panel is open
 * (`open=` in the hash). The CVE id alone when it is unique in the report;
 * otherwise the id plus the package, plus the installed version, plus a counter
 * until every row has its own. Built once per report, so a link keeps pointing
 * at the same row.
 */
import type { VulnItem } from "./api";

export interface OpenIds {
  /** The open id of a row. */
  idOf: (v: VulnItem) => string;
  /** The row an open id names, if any. */
  find: (id: string) => VulnItem | undefined;
}

export function openIds(items: readonly VulnItem[]): OpenIds {
  const count = new Map<string, number>();
  for (const v of items) count.set(v.id, (count.get(v.id) ?? 0) + 1);
  const byItem = new Map<VulnItem, string>();
  const byId = new Map<string, VulnItem>();
  const take = (v: VulnItem, id: string): boolean => {
    if (byId.has(id)) return false;
    byId.set(id, v);
    byItem.set(v, id);
    return true;
  };
  for (const v of items) {
    if ((count.get(v.id) ?? 0) <= 1) {
      take(v, v.id);
      continue;
    }
    const withPkg = `${v.id}:${v.pkg}`;
    if (take(v, withPkg) || take(v, `${withPkg}@${v.installed}`)) continue;
    let n = 2;
    while (!take(v, `${withPkg}@${v.installed}#${n}`)) n += 1;
  }
  return { idOf: (v) => byItem.get(v) ?? v.id, find: (id) => byId.get(id) };
}
