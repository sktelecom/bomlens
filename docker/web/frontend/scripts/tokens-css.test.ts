// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
// @ts-expect-error plain .mjs without types
import { parseTokens, renderTokensCss } from "./tokens-css.mjs";

const SAMPLE = `
@layer base {
  :root {
    --background: 0 0% 98%; /* #fafafa */
    /* --commented: 1 2 3; */
    --risk-high: 234 88 12;
    --radius: 0.375rem;
    --shadow-sm: 0 1px 2px rgb(0 0 0 / 0.1);
    --duration-fast: 150ms;
    --text-sm: 0.875rem;
    --font-sans: "Inter", sans-serif;
    --brand: 349 100% 46%;
    --brand: 349 100% 40%;
    --hex: #ea002c;
  }
  .dark {
    --background: 240 6% 6%;
    --risk-high: 251   146 60;
  }
  body { color: hsl(var(--foreground)); }
}
`;

describe("parseTokens", () => {
  const { light, dark } = parseTokens(SAMPLE);
  it("reads colour channels, hex and font sizes from :root", () => {
    expect(light.get("--background")).toBe("0 0% 98%");
    expect(light.get("--risk-high")).toBe("234 88 12");
    expect(light.get("--hex")).toBe("#ea002c");
    expect(light.get("--text-sm")).toBe("0.875rem");
  });
  it("skips non-colour, non-font-size tokens and comments", () => {
    for (const k of ["--radius", "--shadow-sm", "--duration-fast", "--font-sans", "--commented"]) {
      expect(light.has(k)).toBe(false);
    }
  });
  it("keeps the last duplicate declaration", () => {
    expect(light.get("--brand")).toBe("349 100% 40%");
  });
  it("reads the dark block separately and normalises whitespace", () => {
    expect(dark.get("--background")).toBe("240 6% 6%");
    expect(dark.get("--risk-high")).toBe("251 146 60");
    expect(dark.size).toBe(2);
  });
  it("throws when a block is missing", () => {
    expect(() => parseTokens(":root { --a: 1 2 3; }")).toThrow(/\.dark/);
    expect(() => parseTokens(".dark { --a: 1 2 3; }")).toThrow(/:root/);
  });
});

describe("renderTokensCss", () => {
  it("emits :root then .dark, deterministically", () => {
    const out = renderTokensCss(SAMPLE);
    expect(out).toBe(renderTokensCss(SAMPLE));
    expect(out.indexOf(":root {")).toBeLessThan(out.indexOf(".dark {"));
    expect(out).toContain("  --risk-high: 234 88 12;");
    expect(out).not.toContain("--radius");
  });
});
