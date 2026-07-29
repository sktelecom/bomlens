import { describe, expect, it } from "vitest";

import { formatLabel, inputFacts, parseInputSbom } from "./inputSbom";

const CYCLONEDX = {
  format: "CycloneDX",
  specVersion: "1.5",
  documentId: "urn:uuid:1234",
  documentName: "supplier-app",
  created: "2026-01-02T03:04:05Z",
  tools: ["cdxgen 12.0.0"],
  authors: ["Jo Lee"],
  supplier: "Supplier Inc.",
  rootComponent: {
    name: "supplier-app",
    version: "2.1.0",
    type: "application",
    purl: "pkg:generic/supplier-app@2.1.0",
    licenses: ["Apache-2.0"],
  },
  componentCount: 42,
  originalName: "supplier.cdx.json",
  originalBytes: 8192,
};

describe("parseInputSbom", () => {
  it("reads the document header the scanner captured", () => {
    const input = parseInputSbom(CYCLONEDX);
    expect(input.format).toBe("CycloneDX");
    expect(input.tools).toEqual(["cdxgen 12.0.0"]);
    expect(input.rootComponent.licenses).toEqual(["Apache-2.0"]);
    expect(input.componentCount).toBe(42);
  });

  it("survives a missing or malformed artifact without inventing values", () => {
    for (const raw of [null, undefined, [], "nope", {}]) {
      const input = parseInputSbom(raw);
      expect(input.format).toBe("");
      expect(input.tools).toEqual([]);
      expect(input.componentCount).toBe(0);
      expect(input.rootComponent.name).toBe("");
    }
  });

  it("drops non-string entries from the creator lists", () => {
    const input = parseInputSbom({ tools: ["syft", 7, null, "  "], authors: "no" });
    expect(input.tools).toEqual(["syft"]);
    expect(input.authors).toEqual([]);
  });
});

describe("formatLabel", () => {
  it("joins the format and its spec version", () => {
    expect(formatLabel(parseInputSbom(CYCLONEDX))).toBe("CycloneDX 1.5");
  });

  it("prints the format alone when no version was recorded", () => {
    expect(formatLabel(parseInputSbom({ format: "SPDX" }))).toBe("SPDX");
  });

  it("is empty when the format could not be established", () => {
    expect(formatLabel(parseInputSbom({}))).toBe("");
  });
});

describe("inputFacts", () => {
  it("lists the header facts in reading order", () => {
    const facts = inputFacts(parseInputSbom(CYCLONEDX));
    expect(facts.map((f) => f.labelKey)).toEqual([
      "format",
      "documentName",
      "created",
      "tools",
      "supplier",
      "authors",
      "documentId",
      "rootComponent",
      "rootLicense",
      "purl",
    ]);
    expect(facts[0].value).toBe("CycloneDX 1.5");
    expect(facts[7].value).toBe("supplier-app 2.1.0");
  });

  it("omits what the supplier did not state rather than showing a blank row", () => {
    const facts = inputFacts(
      parseInputSbom({ format: "SPDX", specVersion: "2.3", componentCount: 3 }),
    );
    expect(facts.map((f) => f.labelKey)).toEqual(["format"]);
  });

  it("marks identifiers for monospace and prose fields for normal text", () => {
    const facts = inputFacts(parseInputSbom(CYCLONEDX));
    const byKey = Object.fromEntries(facts.map((f) => [f.labelKey, f]));
    expect(byKey.documentId.mono).toBe(true);
    expect(byKey.purl.mono).toBe(true);
    expect(byKey.supplier.mono).toBeUndefined();
  });

  it("names a root component that carries no version", () => {
    const facts = inputFacts(
      parseInputSbom({ rootComponent: { name: "lone-app" } }),
    );
    expect(facts.find((f) => f.labelKey === "rootComponent")?.value).toBe(
      "lone-app",
    );
  });
});
