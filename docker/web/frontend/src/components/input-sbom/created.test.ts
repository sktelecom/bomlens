// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { formatCreated } from "./created";

describe("formatCreated", () => {
  it("writes UTC dates in the interface language", () => {
    expect(formatCreated("2026-01-02T03:04:05Z", "en")).toBe("Jan 2, 2026, 03:04 UTC");
    expect(formatCreated("2026-01-02T03:04:05Z", "ko")).toBe("2026. 1. 2. 03:04 (UTC)");
  });
  it("returns text that is not a date as it came", () => {
    expect(formatCreated("last Tuesday", "en")).toBe("last Tuesday");
  });
});
