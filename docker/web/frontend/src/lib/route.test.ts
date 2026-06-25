import { describe, expect, it } from "vitest";

import { buildHash, homeHash, parseHash, scanHash } from "./route";

describe("parseHash", () => {
  it("treats empty / bare slash as home", () => {
    expect(parseHash("")).toEqual({ kind: "home" });
    expect(parseHash("#")).toEqual({ kind: "home" });
    expect(parseHash("#/")).toEqual({ kind: "home" });
  });

  it("parses a scan without a section as Overview", () => {
    expect(parseHash("#/scan/demo_1.0")).toEqual({
      kind: "scan",
      id: "demo_1.0",
      section: "overview",
    });
  });

  it("parses a scan with a section", () => {
    expect(parseHash("#/scan/demo_1.0/components")).toEqual({
      kind: "scan",
      id: "demo_1.0",
      section: "components",
    });
  });

  it("tolerates a missing leading slash", () => {
    expect(parseHash("#scan/demo_1.0/vulnerabilities")).toEqual({
      kind: "scan",
      id: "demo_1.0",
      section: "vulnerabilities",
    });
  });

  it("decodes an encoded id", () => {
    expect(parseHash("#/scan/my%20app_1.0/licenses")).toEqual({
      kind: "scan",
      id: "my app_1.0",
      section: "licenses",
    });
  });

  it("falls back to home on a malformed hash", () => {
    expect(parseHash("#/scan")).toEqual({ kind: "home" });
    expect(parseHash("#/scan/")).toEqual({ kind: "home" });
    expect(parseHash("#/other/thing")).toEqual({ kind: "home" });
  });
});

describe("buildHash / scanHash / homeHash", () => {
  it("builds home as a bare slash", () => {
    expect(homeHash()).toBe("#/");
    expect(buildHash({ kind: "home" })).toBe("#/");
  });

  it("omits the section for Overview", () => {
    expect(scanHash("demo_1.0")).toBe("#/scan/demo_1.0");
    expect(scanHash("demo_1.0", "overview")).toBe("#/scan/demo_1.0");
  });

  it("includes a non-overview section", () => {
    expect(scanHash("demo_1.0", "components")).toBe(
      "#/scan/demo_1.0/components",
    );
  });

  it("round-trips an id needing encoding", () => {
    const h = scanHash("my app_1.0", "vulnerabilities");
    expect(parseHash(h)).toEqual({
      kind: "scan",
      id: "my app_1.0",
      section: "vulnerabilities",
    });
  });
});
