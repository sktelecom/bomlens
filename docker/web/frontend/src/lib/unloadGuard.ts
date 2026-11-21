// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A scan is tied to the tabs following it: once none has for the server's
 * grace (a reload joins it again well within it), it ends and what it found is
 * not kept. The browser's own "leave this page?" prompt is the warning, raised
 * only while a scan runs.
 *
 * Automated tests navigate away from a running scan on purpose and would be
 * stopped by the prompt, so it can be switched off: at build time with
 * VITE_NO_UNLOAD_GUARD=1, or in a page with `window.__BOMLENS_NO_UNLOAD_GUARD__`
 * or the localStorage entry `bomlens.noUnloadGuard` = "1".
 */

export interface GuardEnv {
  __BOMLENS_NO_UNLOAD_GUARD__?: unknown;
  localStorage?: { getItem(key: string): string | null };
}

export function unloadGuardEnabled(
  win: GuardEnv | undefined = typeof window === "undefined" ? undefined : window,
  buildFlag: string | undefined = import.meta.env.VITE_NO_UNLOAD_GUARD,
): boolean {
  if (buildFlag === "1") return false;
  if (!win) return true;
  if (win.__BOMLENS_NO_UNLOAD_GUARD__) return false;
  try {
    if (win.localStorage?.getItem("bomlens.noUnloadGuard") === "1") return false;
  } catch {
    /* storage unavailable: the guard stays on */
  }
  return true;
}

/** The handler that raises the browser's prompt. */
export function warnBeforeUnload(e: BeforeUnloadEvent): void {
  e.preventDefault();
  e.returnValue = "";
}
