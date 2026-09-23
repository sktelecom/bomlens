// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Joining a supplier's received VEX statements onto vulnerability rows in the
 * browser, right after an import, before the scan is fetched again. The rule is
 * the server's (`_received_for_row` in docker/web/server.py) and the two have
 * to stay the same.
 */
import type { VexReceived, VexReceivedStatement, VulnItem } from "./api";

/** purl without qualifiers or subpath, lowercased: the server's own join key. */
export function normPurl(purl: string): string {
  return purl.split("?")[0].split("#")[0].trim().toLowerCase();
}

/** Received statements, indexed the way the server joins them to a row. */
export interface ReceivedIndex {
  byPurl: Map<string, VexReceived>;
  /** By name and installed version; `hasPurl` marks a statement recorded with a
   *  purl, which a row that has its own purl must not pick up by name alone. */
  byNv: Map<string, { received: VexReceived; hasPurl: boolean }>;
  /** Product-level statements, by CVE. */
  byCve: Map<string, VexReceived>;
}

export function receivedIndex(statements: VexReceivedStatement[], source: string | null): ReceivedIndex {
  const idx: ReceivedIndex = { byPurl: new Map(), byNv: new Map(), byCve: new Map() };
  for (const s of statements) {
    const received: VexReceived = {
      state: s.state,
      detail: s.detail,
      justification: s.justification,
      source: source ?? undefined,
    };
    if (s.scope === "product") {
      idx.byCve.set(s.cve, received);
      continue;
    }
    if (s.purl) idx.byPurl.set(`${normPurl(s.purl)}::${s.cve}`, received);
    if (s.pkg) {
      idx.byNv.set(`${s.pkg.toLowerCase()}@${s.installed ?? ""}::${s.cve}`, {
        received,
        hasPurl: Boolean(s.purl),
      });
    }
  }
  return idx;
}

/** Same rule as the server's _received_for_row: a row with a purl matches on the
 *  purl (or a purl-less statement by name), a row without one matches by name and
 *  version, and a product-level statement covers what neither did. */
export function receivedFor(idx: ReceivedIndex, v: VulnItem): VexReceived | undefined {
  const nv = idx.byNv.get(`${v.pkg.toLowerCase()}@${v.installed}::${v.id}`);
  let hit: VexReceived | undefined;
  if (v.purl) {
    hit = idx.byPurl.get(`${normPurl(v.purl)}::${v.id}`) ?? (nv && !nv.hasPurl ? nv.received : undefined);
  } else {
    hit = nv?.received;
  }
  return hit ?? idx.byCve.get(v.id);
}

