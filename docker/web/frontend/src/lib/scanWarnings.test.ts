// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { parseScanWaiting } from "./api";
import { scanWaitingText, scanWarningText } from "./scanWarnings";

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

describe("scanWaitingText", () => {
  const line =
    "[INFO] Another scan of this folder is running (a web UI scan); this scan waits for it to finish, so that neither one sees the other's build files. Cancel this scan to stop waiting.";

  it("names the running view's waiting notice for a scan of the same folder", () => {
    expect(scanWaitingText("SAME_FOLDER_SCAN_RUNNING", line)).toEqual({ key: "run.waitingSameFolder", text: line });
  });

  it("shows the scanner's own line for a reason it has no wording for", () => {
    expect(scanWaitingText("SOMETHING_ELSE", "[INFO] waiting for a lock")).toEqual({
      key: null,
      text: "waiting for a lock",
    });
  });
});

describe("parseScanWaiting", () => {
  it("reads a wait under way", () => {
    expect(parseScanWaiting({ waiting: true, code: "SAME_FOLDER_SCAN_RUNNING", detail: "x" })).toEqual({
      code: "SAME_FOLDER_SCAN_RUNNING",
      detail: "x",
    });
    expect(parseScanWaiting({ waiting: true, code: "SAME_FOLDER_SCAN_RUNNING" })?.detail).toBe("");
  });

  it("reads the end of the wait, or anything else, as no wait", () => {
    expect(parseScanWaiting({ waiting: false, code: "SAME_FOLDER_SCAN_RUNNING" })).toBeNull();
    expect(parseScanWaiting({ waiting: true })).toBeNull();
    expect(parseScanWaiting({ waiting: "yes", code: "X" })).toBeNull();
    expect(parseScanWaiting(null)).toBeNull();
    expect(parseScanWaiting("waiting")).toBeNull();
  });
});
