// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { VulnItem } from "./api";
import { openIds } from "./vulnOpen";

const v = (id: string, pkg: string, installed = "1"): VulnItem => ({ id, pkg, installed, fixed: "", severity: "HIGH", title: "" });

describe("openIds", () => {
  it("uses the bare CVE id when it is unique", () => {
    const a = v("CVE-1", "x");
    const ids = openIds([a, v("CVE-2", "x")]);
    expect(ids.idOf(a)).toBe("CVE-1");
    expect(ids.find("CVE-1")).toBe(a);
    expect(ids.find("nope")).toBeUndefined();
  });

  it("adds the package, then the installed version, then a counter for repeats", () => {
    const a = v("CVE-1", "x", "1");
    const b = v("CVE-1", "y", "1");
    const c = v("CVE-1", "y", "2");
    const d = v("CVE-1", "y", "2");
    const ids = openIds([a, b, c, d]);
    expect(ids.idOf(a)).toBe("CVE-1:x");
    expect(ids.idOf(b)).toBe("CVE-1:y");
    expect(ids.idOf(c)).toBe("CVE-1:y@2");
    expect(ids.idOf(d)).toBe("CVE-1:y@2#2");
    for (const row of [a, b, c, d]) expect(ids.find(ids.idOf(row))).toBe(row);
  });
});
