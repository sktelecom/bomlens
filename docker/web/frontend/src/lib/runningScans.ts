// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";

import { listRunningScans, type DoneEvent, type RunningScan, type ScanStarted } from "@/lib/api";

/** How often the new-scan screen asks which scans are running. */
export const RUNNING_POLL_MS = 5000;

/** "name version" for a running scan; the name alone when it has no version. */
export function runningLabel(r: Pick<RunningScan, "project" | "version">): string {
  return r.version ? `${r.project} ${r.version}` : r.project;
}

/** How a tab showing a scan's progress treats the stream's done event: a scan
 *  stopped before it finished (cancelled here or in another tab, or left with
 *  no tab following it) has no result to show. */
export function scanEndOf(done: Pick<DoneEvent, "cancelled">): "cancelled" | "result" {
  return done.cancelled === true ? "cancelled" : "result";
}

/** The log a tab starts from when it joins a running scan: a note in place of
 *  the early lines the server no longer holds, else nothing (the replay
 *  follows). The tab that started the scan starts empty. */
export function attachedLogStart(
  info: Pick<ScanStarted, "attached" | "droppedLines">,
  note: (count: number) => string,
): string[] {
  return info.attached && info.droppedLines > 0 ? [note(info.droppedLines)] : [];
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
