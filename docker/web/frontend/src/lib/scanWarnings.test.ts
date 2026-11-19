// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { scanWarningText } from "./scanWarnings";

describe("scanWarningText", () => {
  it("names the translation for a code the server sends", () => {
    const w = "SAME_FOLDER_SCAN_RUNNING: [WARN] a previous scan of this folder (x) appears to still be running";
    const shown = scanWarningText(w);
    expect(shown.key).toBe("result.warnSameFolderScan");
    expect(shown.text).toBe("a previous scan of this folder (x) appears to still be running");
  });

  it("leaves any other warning as the scanner wrote it, minus the marker", () => {
    expect(scanWarningText("[WARN] no package manifest detected")).toEqual({
      key: null,
      text: "no package manifest detected",
    });
  });

  it("does not take an unknown code for a translation", () => {
    const shown = scanWarningText("SOMETHING_ELSE: [WARN] text");
    expect(shown.key).toBeNull();
  });
});
