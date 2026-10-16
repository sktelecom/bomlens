// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Row density of the result tables, and how the choice survives a reload.
 *
 * Two steps, not a free-form size: compact rows are 32px, comfortable rows are
 * 40px. The choice is one preference for every table (a reader who wants dense
 * rows wants them on the Components and the Vulnerabilities screen alike) and
 * lives in the same browser-local storage as the column choice, injected the
 * same way so the parsing stays testable under Node.
 */
import { defaultStore, type ViewStore } from "./tableView";

export type Density = "compact" | "comfortable";

export const DENSITIES: readonly Density[] = ["compact", "comfortable"];
export const DEFAULT_DENSITY: Density = "comfortable";

/** localStorage key, namespaced like the column choice. */
export const DENSITY_KEY = "sbom.table.density";

/** Row height of each step, in px. Exposed so the virtual list can estimate the
 *  height of a chunk it has not rendered yet. */
export const ROW_HEIGHT_PX: Record<Density, number> = {
  compact: 32,
  comfortable: 40,
};

/** Class on the <table>; index.css turns it into the cell height and padding. */
export function densityClass(density: Density): string {
  return `table-density-${density}`;
}

/** A stored value is trusted only if it is one of the two known steps. */
export function parseDensity(raw: string | null): Density {
  return DENSITIES.find((d) => d === raw) ?? DEFAULT_DENSITY;
}

export function readDensity(store: ViewStore | null = defaultStore()): Density {
  if (!store) return DEFAULT_DENSITY;
  try {
    return parseDensity(store.getItem(DENSITY_KEY));
  } catch {
    return DEFAULT_DENSITY;
  }
}

/** Silent when storage is unavailable: the choice then lasts for the session. */
export function writeDensity(density: Density, store: ViewStore | null = defaultStore()): void {
  if (!store) return;
  try {
    store.setItem(DENSITY_KEY, density);
  } catch {
    // Out of quota or blocked.
  }
}
