// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from "react";

/**
 * Tracks a CSS media query. Used where a screen needs a different structure
 * (not just different styling) on narrow viewports, so only one of the two
 * layouts is ever mounted and the page never holds duplicate links or controls.
 */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (notify) => {
      const mq = window.matchMedia(query);
      mq.addEventListener("change", notify);
      return () => mq.removeEventListener("change", notify);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}

/** Below Tailwind's `md` breakpoint (768 px). */
export const NARROW_QUERY = "(max-width: 767px)";
