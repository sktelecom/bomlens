import { describe, expect, it } from "vitest";

import { canManageScanFolders, desktopBridge } from "./desktop";

describe("desktopBridge", () => {
  it("returns null outside the desktop app", () => {
    expect(desktopBridge(undefined)).toBeNull();
    expect(desktopBridge({})).toBeNull();
  });

  it("returns the injected bridge object", () => {
    const bridge = { chooseScanFolder: async () => ({ ok: true }) };
    expect(desktopBridge({ sbomDesktop: bridge })).toBe(bridge);
  });
});

describe("canManageScanFolders", () => {
  it("requires the chooseScanFolder channel", () => {
    expect(canManageScanFolders(null)).toBe(false);
    expect(canManageScanFolders({})).toBe(false);
    expect(canManageScanFolders({ chooseScanFolder: async () => ({ ok: true }) })).toBe(true);
  });
});
