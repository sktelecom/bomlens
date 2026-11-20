// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { runningLabel } from "./runningScans";

describe("runningLabel", () => {
  it("joins name and version, and leaves the name alone without a version", () => {
    expect(runningLabel({ project: "acme", version: "1.2" })).toBe("acme 1.2");
    expect(runningLabel({ project: "acme", version: "" })).toBe("acme");
  });
});
