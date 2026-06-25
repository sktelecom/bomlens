import { describe, expect, it } from "vitest";

import { buildHash, homeHash, newHash, parseHash, scanHash } from "./route";

describe("parseHash", () => {
  it("treats empty / bare slash as Recent (home)", () => {
    expect(parseHash("")).toEqual({ kind: "recent" });
    expect(parseHash("#")).toEqual({ kind: "recent" });
    expect(parseHash("#/")).toEqual({ kind: "recent" });
  });

  it("parses the New scan screen", () => {
    expect(parseHash("#/new")).toEqual({ kind: "new" });
    expect(parseHash("#new")).toEqual({ kind: "new" });
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

  it("falls back to Recent on a malformed hash", () => {
    expect(parseHash("#/scan")).toEqual({ kind: "recent" });
    expect(parseHash("#/scan/")).toEqual({ kind: "recent" });
    expect(parseHash("#/other/thing")).toEqual({ kind: "recent" });
  });
});

describe("buildHash / scanHash / homeHash / newHash", () => {
  it("builds Recent (home) as a bare slash", () => {
    expect(homeHash()).toBe("#/");
    expect(buildHash({ kind: "recent" })).toBe("#/");
  });

  it("builds the New scan hash", () => {
    expect(newHash()).toBe("#/new");
    expect(buildHash({ kind: "new" })).toBe("#/new");
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
