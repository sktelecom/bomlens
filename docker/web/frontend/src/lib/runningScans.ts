// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";

import { listRunningScans, type RunningScan } from "@/lib/api";

/** How often the new-scan screen asks which scans are running. */
export const RUNNING_POLL_MS = 5000;

/** "name version" for a running scan; the name alone when it has no version. */
export function runningLabel(r: Pick<RunningScan, "project" | "version">): string {
  return r.version ? `${r.project} ${r.version}` : r.project;
}

/** The scans running on the server, refreshed while `active` is true. */
export function useRunningScans(active: boolean): RunningScan[] {
  const [rows, setRows] = useState<RunningScan[]>([]);
  useEffect(() => {
    if (!active) {
      setRows([]);
      return;
    }
    let live = true;
    const load = () => {
      void listRunningScans().then((r) => {
        if (live) setRows(r);
      });
    };
    load();
    const timer = window.setInterval(load, RUNNING_POLL_MS);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, [active]);
  return rows;
}
