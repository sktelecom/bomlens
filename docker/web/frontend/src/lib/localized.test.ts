// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { renderLocalized } from "./localized";

const t = (key: string, opts?: Record<string, unknown>) =>
  opts && Object.keys(opts).length ? `${key}(${Object.entries(opts).map(([k, v]) => `${k}=${v}`).join(";")})` : key;

describe("renderLocalized", () => {
  it("passes copied values through untouched", () => {
    expect(renderLocalized(t, { key: "a", params: { license: "MIT" } })).toBe("a(license=MIT)");
  });

  it("renders a nested phrase before the outer one", () => {
    expect(renderLocalized(t, { key: "a", params: { inner: { key: "b" } } })).toBe("a(inner=b)");
  });

  it("joins a list with commas", () => {
    expect(
      renderLocalized(t, { key: "a", params: { names: ["x", { key: "v", params: { name: "y" } }] } }),
    ).toBe("a(names=x, v(name=y))");
  });
});
