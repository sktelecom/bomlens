// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { parseMap } from "./aiDeclaration";
import { demoInstallUrl, demoRunAction, IS_STATIC_DEMO, releaseNotesUrl } from "./demo";
import serverMap from "../../../../lib/spdx3-ai-map.json";

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

describe("releaseNotesUrl", () => {
  const base = "https://github.com/sktelecom/bomlens/releases";
  it("points at the release page of a stamped version", () => {
    expect(releaseNotesUrl("1.13.5")).toBe(`${base}/tag/v1.13.5`);
    expect(releaseNotesUrl("v1.13.5")).toBe(`${base}/tag/v1.13.5`);
  });
  it("falls back to the release list without a stamp or with a pre-release one", () => {
    expect(releaseNotesUrl(undefined)).toBe(base);
    expect(releaseNotesUrl("")).toBe(base);
    expect(releaseNotesUrl("1.13.6-dev")).toBe(base);
  });
});

describe("IS_STATIC_DEMO", () => {
  it("is off unless the bundle was built with a demo data base", () => {
    expect(IS_STATIC_DEMO).toBe(false);
  });
});

describe("demoRunAction", () => {
  it("keeps the model questionnaire reachable and refuses every other source", () => {
    expect(demoRunAction("ai-declare")).toBe("questions");
    for (const s of ["current-dir", "git-url", "docker-image", "ai-model", "model-upload", "sbom-upload"]) {
      expect(demoRunAction(s)).toBe("disabled");
    }
  });
});

describe("the mapping bundled with the demo", () => {
  it("is the file server.py serves and the questionnaire can read it", () => {
    // The demo build aliases @spdx3-map to this very file (vite.config.ts),
    // so a mapping the questionnaire cannot parse would break the demo.
    expect(parseMap(serverMap)).not.toBeNull();
  });
});
