// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Which columns a table shows, and how that choice survives a reload.
 *
 * The stored value is a list of *hidden* column ids rather than visible ones,
 * so a column added in a later release shows up by default instead of staying
 * invisible for everyone who ever opened the menu.
 *
 * Storage is injected rather than imported: the unit tests run under Node,
 * where there is no localStorage, and keeping the parsing pure is what makes
 * the unknown-key defence testable at all. This is the same browser-local,
 * no-account storage the theme and language already use — nothing leaves the
 * machine.
 */

/** A column the reader may hide. Required columns are simply not listed. */
export interface ColumnDef {
  /** Stable id — the stored value, so it must not change between releases. */
  id: string;
  /** i18n key for the menu entry and the table header. */
  labelKey: string;
}

/** The components table's optional columns, in table order. */
export const COMPONENT_COLUMNS: ColumnDef[] = [
  { id: "version", labelKey: "result.colVersion" },
  { id: "type", labelKey: "result.colType" },
  { id: "scope", labelKey: "result.colScope" },
  { id: "risk", labelKey: "result.colRisk" },
  { id: "license", labelKey: "result.colLicense" },
];

/** localStorage key for the components table. Namespaced like sbom.theme. */
export const COMPONENT_VIEW_KEY = "sbom.components.hiddenColumns";

/** The minimal storage surface used here, so a test can pass a plain object. */
export interface ViewStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/**
 * Read a stored list of hidden column ids, keeping only ids the table still
 * has. A stale id from an older release, a hand-edited value, or another
 * origin's key would otherwise hide nothing while quietly staying in storage.
 */
export function parseHidden(raw: string | null, known: string[]): string[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const allowed = new Set(known);
  return [...new Set(parsed.filter((v): v is string => typeof v === "string" && allowed.has(v)))];
}

/** Serialize for storage. */
export function serializeHidden(hidden: string[]): string {
  return JSON.stringify([...new Set(hidden)]);
}

/** Toggle one column's visibility, returning the new hidden list. */
export function toggleHidden(hidden: string[], id: string): string[] {
  return hidden.includes(id) ? hidden.filter((h) => h !== id) : [...hidden, id];
}

/** Default store: the browser's localStorage when there is one. */
export function defaultStore(): ViewStore | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    // Storage can throw outright when the browser blocks it (private mode,
    // third-party restrictions). The table still works; it just forgets.
    return null;
  }
}

/** Load the hidden-column list for a table. Falls back to none. */
export function readHidden(
  key: string,
  known: string[],
  store: ViewStore | null = defaultStore(),
): string[] {
  if (!store) return [];
  try {
    return parseHidden(store.getItem(key), known);
  } catch {
    return [];
  }
}

/** Persist the hidden-column list. Silent when storage is unavailable. */
export function writeHidden(
  key: string,
  hidden: string[],
  store: ViewStore | null = defaultStore(),
): void {
  if (!store) return;
  try {
    store.setItem(key, serializeHidden(hidden));
  } catch {
    // Out of quota or blocked — the choice applies for this session only.
  }
}
