/**
 * Desktop-app (Electron) bridge. The desktop shell injects `window.sbomDesktop`
 * via its preload script; in a plain browser it is absent. Only the scan-folder
 * channels are used from the SPA — startup channels belong to the status screen.
 * Wrapped in accessors so components stay testable without a real window.
 */

export interface ScanMountResult {
  ok: boolean;
  reason?: string;
  mounts?: string[];
}

export interface DesktopBridge {
  chooseScanFolder?: () => Promise<ScanMountResult>;
  removeScanFolder?: (hostPath: string) => Promise<ScanMountResult>;
}

declare global {
  interface Window {
    sbomDesktop?: DesktopBridge;
  }
}

/** The bridge object, or null outside the desktop app (or in tests). */
export function desktopBridge(w: { sbomDesktop?: DesktopBridge } | undefined =
  typeof window === "undefined" ? undefined : window): DesktopBridge | null {
  return w?.sbomDesktop ?? null;
}

/** Whether the scan-folder picker is available (desktop app new enough). */
export function canManageScanFolders(bridge: DesktopBridge | null): boolean {
  return typeof bridge?.chooseScanFolder === "function";
}
