// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";

import { cancelScan, parseScanStarted } from "./api";
import {
  attachedLogStart,
  clearStoppingScans,
  nextRunningPoll,
  noteScanStopping,
  RUNNING_POLL_MS,
  runningLabel,
  scanEndOf,
  STOPPING_POLL_MS,
  STOPPING_WATCH_MS,
} from "./runningScans";

describe("runningLabel", () => {
  it("joins name and version, and leaves the name alone without a version", () => {
    expect(runningLabel({ project: "acme", version: "1.2" })).toBe("acme 1.2");
    expect(runningLabel({ project: "acme", version: "" })).toBe("acme");
  });
});

describe("scanEndOf", () => {
  it("has no result to show for a cancelled scan", () => {
    expect(scanEndOf({ cancelled: true })).toBe("cancelled");
  });
  it("shows the result otherwise, and for a payload from before the field", () => {
    expect(scanEndOf({ cancelled: false })).toBe("result");
    expect(scanEndOf({})).toBe("result");
  });
});

describe("attachedLogStart", () => {
  const note = (n: number) => `${n} hidden`;
  it("notes the early lines a joining tab cannot see", () => {
    expect(attachedLogStart({ attached: true, droppedLines: 12 }, note)).toEqual(["12 hidden"]);
  });
  it("starts empty when the log is whole or the tab started the scan", () => {
    expect(attachedLogStart({ attached: true, droppedLines: 0 }, note)).toEqual([]);
    expect(attachedLogStart({ attached: false, droppedLines: 5 }, note)).toEqual([]);
  });
});

describe("parseScanStarted", () => {
  it("reads the started event", () => {
    expect(
      parseScanStarted({
        id: "acme_1.0",
        project: "acme",
        version: "1.0",
        startedAt: 1700000000,
        attached: true,
        droppedLines: 3,
        deepCve: true,
      }),
    ).toEqual({
      id: "acme_1.0",
      project: "acme",
      version: "1.0",
      startedAt: 1700000000,
      attached: true,
      droppedLines: 3,
      deepCve: true,
    });
  });
  it("fills defaults for missing or odd fields", () => {
    expect(parseScanStarted({ id: "x_1", droppedLines: -4, attached: "yes" })).toEqual({
      id: "x_1",
      project: "",
      version: "",
      startedAt: 0,
      attached: false,
      droppedLines: 0,
      deepCve: false,
    });
  });
  it("refuses a payload that names no run", () => {
    expect(parseScanStarted(null)).toBeNull();
    expect(parseScanStarted({ id: "" })).toBeNull();
    expect(parseScanStarted("acme_1.0")).toBeNull();
  });
});

describe("cancelScan", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("posts the encoded id and reports whether this request stopped the scan", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ cancelling: true })));
    vi.stubGlobal("fetch", fetchMock);
    expect(await cancelScan("my app_1.0")).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith("/scan-cancel?id=my%20app_1.0", { method: "POST" });
  });

  it("is false when the scan was already stopping, is gone, or the request failed", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ cancelling: false }))));
    expect(await cancelScan("a_1")).toBe(false);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 404 })));
    expect(await cancelScan("a_1")).toBe(false);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    expect(await cancelScan("a_1")).toBe(false);
  });
});

describe("nextRunningPoll", () => {
  afterEach(() => clearStoppingScans());
  const row = (id: string) => ({ id });

  it("asks at the usual interval when no listed scan was seen stopped", () => {
    expect(nextRunningPoll([row("a_1")], 0)).toBe(RUNNING_POLL_MS);
    expect(nextRunningPoll([], 0)).toBe(RUNNING_POLL_MS);
  });

  it("asks sooner while a scan this tab saw stopped is still listed", () => {
    noteScanStopping("a_1", 1000);
    expect(nextRunningPoll([row("b_1"), row("a_1")], 2000)).toBe(STOPPING_POLL_MS);
    expect(nextRunningPoll([row("a_1")], 3000)).toBe(STOPPING_POLL_MS);
  });

  it("drops the note once the server no longer lists the scan", () => {
    noteScanStopping("a_1", 1000);
    expect(nextRunningPoll([], 2000)).toBe(RUNNING_POLL_MS);
    // Listed again later (a new scan of the same name): the usual pace.
    expect(nextRunningPoll([row("a_1")], 3000)).toBe(RUNNING_POLL_MS);
  });

  it("stops asking sooner after the watch window", () => {
    noteScanStopping("a_1", 0);
    expect(nextRunningPoll([row("a_1")], STOPPING_WATCH_MS)).toBe(RUNNING_POLL_MS);
  });

  it("ignores an empty id", () => {
    noteScanStopping("", 0);
    expect(nextRunningPoll([row("")], 1)).toBe(RUNNING_POLL_MS);
  });
});
