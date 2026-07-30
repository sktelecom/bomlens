// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { demoInstallUrl, IS_STATIC_DEMO } from "./demo";

describe("demoInstallUrl", () => {
  it("points at the English install guide by default", () => {
    expect(demoInstallUrl("en")).toBe(
      "https://sktelecom.github.io/bomlens/start/first-scan/",
    );
  });

  it("points at the Korean guide when the UI is Korean", () => {
    expect(demoInstallUrl("ko")).toBe(
      "https://sktelecom.github.io/bomlens/ko/start/first-scan/",
    );
  });

  // i18next reports region tags ("ko-KR") and casing varies by browser, so the
  // match is a case-insensitive prefix rather than an equality check.
  it.each(["ko-KR", "KO", "ko-kr"])("treats %s as Korean", (lang) => {
    expect(demoInstallUrl(lang)).toContain("/ko/start/first-scan/");
  });

  it.each(["en-US", "en-GB", "ja", "kor"])(
    "treats %s as non-Korean",
    (lang) => {
      expect(demoInstallUrl(lang)).not.toContain("/ko/");
    },
  );

  // Before i18next resolves a language the components still render once.
  it.each([undefined, ""])("falls back to English for %p", (lang) => {
    expect(demoInstallUrl(lang)).toBe(
      "https://sktelecom.github.io/bomlens/start/first-scan/",
    );
  });
});

describe("IS_STATIC_DEMO", () => {
  it("is off unless the bundle was built with a demo data base", () => {
    expect(IS_STATIC_DEMO).toBe(false);
  });
});
