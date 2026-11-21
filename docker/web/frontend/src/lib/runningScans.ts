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

/** How often the new-scan screen asks again while it lists a scan this tab
 *  saw stopped (cancelled here or in another tab): the server lists it until
 *  it has stopped, which takes a moment, and the notice should go then. */
export const STOPPING_POLL_MS = 1000;
/** How long a stopped scan is asked about at the faster pace. */
export const STOPPING_WATCH_MS = 120_000;

// Run id -> when this tab saw it stopped. Module-level, as the new-scan
// screen mounts only after the progress screen that saw the cancel is gone.
const stopping = new Map<string, number>();

/** Note that this tab saw a scan stopped, so the running-scans notice asks
 *  about it more often until the server no longer lists it. */
export function noteScanStopping(id: string, now: number = Date.now()): void {
  if (id) stopping.set(id, now);
}

/** Forget every noted scan (tests). */
export function clearStoppingScans(): void {
  stopping.clear();
}

/** The delay before the next running-scans poll: short while the list holds a
 *  scan this tab saw stopped (noted less than STOPPING_WATCH_MS ago), the
 *  usual interval otherwise. Notes that are old or no longer listed go. */
export function nextRunningPoll(
  rows: Pick<RunningScan, "id">[],
  now: number = Date.now(),
): number {
  const listed = new Set(rows.map((r) => r.id));
  let fast = false;
  for (const [id, at] of stopping) {
    if (!listed.has(id) || now - at >= STOPPING_WATCH_MS) stopping.delete(id);
    else fast = true;
  }
  return fast ? STOPPING_POLL_MS : RUNNING_POLL_MS;
}

/** The scans running on the server, refreshed while `active` is true: at
 *  once, again whenever the tab is shown, and on the interval nextRunningPoll
 *  gives. A reply that arrives after a newer request was sent is ignored. */
export function useRunningScans(active: boolean): RunningScan[] {
  const [rows, setRows] = useState<RunningScan[]>([]);
  useEffect(() => {
    if (!active) {
      setRows([]);
      return;
    }
    let live = true;
    let seq = 0;
    let timer: number | undefined;
    const load = () => {
      window.clearTimeout(timer);
      const mine = ++seq;
      void listRunningScans().then((r) => {
        if (!live || mine !== seq) return;
        setRows(r);
        timer = window.setTimeout(load, nextRunningPoll(r));
      });
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") load();
    };
    load();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      live = false;
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [active]);
  return rows;
}
