// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Which added folder the New scan form starts on. The desktop app restarts its
 * scanner when a folder is added and the page reloads, which would drop the form
 * back to its first screen; remembering the folders seen last time lets the form
 * return to the one that just appeared, and otherwise to the one used last.
 *
 * Browser storage can be missing or throw (private windows, blocked site data),
 * so every access is guarded and the form works without it.
 */

const LAST_KEY = "bomlens.lastScanRoot";
const KNOWN_KEY = "bomlens.knownScanRoots";

export interface ScanRootEntry {
  path: string;
  hostPath: string;
}

/** The two operations used on a storage, so a test can pass a plain object. */
export interface MemoryStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function defaultStore(): MemoryStore | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

function read(store: MemoryStore | null, key: string): string | null {
  try {
    return store?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function write(store: MemoryStore | null, key: string, value: string): void {
  try {
    store?.setItem(key, value);
  } catch {
    /* storage unavailable: the form still works without memory */
  }
}

function readList(store: MemoryStore | null, key: string): string[] | null {
  const raw = read(store, key);
  if (raw === null) return null;
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : null;
  } catch {
    return null;
  }
}

const idOf = (r: ScanRootEntry) => r.hostPath || r.path;

/**
 * The container path of the folder to preselect: one added since the page was
 * last open, else the one scanned last, else the first. "" when nothing is
 * added. Also records the folders now known, so the same folder is "new" once.
 */
export function chooseInitialRoot(
  roots: ScanRootEntry[],
  store: MemoryStore | null = defaultStore(),
): string {
  if (roots.length === 0) return "";
  const known = readList(store, KNOWN_KEY);
  write(store, KNOWN_KEY, JSON.stringify(roots.map(idOf)));
  if (known) {
    const fresh = roots.filter((r) => !known.includes(idOf(r)));
    if (fresh.length > 0) return fresh[fresh.length - 1].path;
  }
  const last = read(store, LAST_KEY);
  const hit = last ? roots.find((r) => idOf(r) === last) : undefined;
  return (hit ?? roots[0]).path;
}

/** Remember the folder a scan was started from. */
export function rememberScanRoot(
  roots: ScanRootEntry[],
  path: string,
  store: MemoryStore | null = defaultStore(),
): void {
  const root = roots.find((r) => r.path === path);
  if (root) write(store, LAST_KEY, idOf(root));
}

/**
 * The scan location the form shows and submits. The list offers the launch
 * folder ("") only when `offersLaunch`, then the added folders. A choice the
 * list does not offer (none made yet, the launch folder when it is hidden, or a
 * folder that went away) falls back to the first entry, which is the one a
 * select element shows, so the value sent is always the one on screen.
 */
export function effectiveScanRoot(
  chosen: string,
  roots: ScanRootEntry[],
  offersLaunch: boolean,
): string {
  if (roots.length === 0) return "";
  if (chosen === "" ? offersLaunch : roots.some((r) => r.path === chosen)) return chosen;
  return offersLaunch ? "" : roots[0].path;
}
