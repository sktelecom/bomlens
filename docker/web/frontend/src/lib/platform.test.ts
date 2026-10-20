// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";

import { isAppleKeyboard } from "./platform";

describe("isAppleKeyboard", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("is true on a Mac and false on Windows or Linux", () => {
    vi.stubGlobal("navigator", { platform: "MacIntel", userAgent: "" });
    expect(isAppleKeyboard()).toBe(true);
    vi.stubGlobal("navigator", { platform: "Win32", userAgent: "" });
    expect(isAppleKeyboard()).toBe(false);
    vi.stubGlobal("navigator", { platform: "Linux x86_64", userAgent: "" });
    expect(isAppleKeyboard()).toBe(false);
  });

  it("falls back to the user agent when the platform is empty", () => {
    vi.stubGlobal("navigator", { platform: "", userAgent: "Mozilla/5.0 (iPhone)" });
    expect(isAppleKeyboard()).toBe(true);
  });
});
