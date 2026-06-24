import { describe, expect, it } from "vitest";

import type { ComponentItem } from "./api";
import { severityFor, vulnSeverityIndex } from "./dependencies";
import { parseSbomGraph, type RawSbom } from "./sbomGraph";

const components: ComponentItem[] = [
  { name: "openssl", version: "3.0.0", group: "", purl: "", type: "library", licenses: [], maxSeverity: "CRITICAL", vulnCount: 2 },
  { name: "zlib", version: "1.2.0", group: "", purl: "", type: "library", licenses: [] },
];

describe("vulnSeverityIndex / severityFor", () => {
  it("indexes only vulnerable components, by name@version", () => {
    const idx = vulnSeverityIndex(components);
    expect(severityFor(idx, "openssl", "3.0.0")).toBe("CRITICAL");
    expect(severityFor(idx, "OpenSSL", "3.0.0")).toBe("CRITICAL"); // case-insensitive
    expect(severityFor(idx, "zlib", "1.2.0")).toBeUndefined();
    expect(severityFor(idx, "openssl", "9.9")).toBeUndefined(); // version-sensitive
  });
});

describe("parseSbomGraph vuln annotation", () => {
  const sbom: RawSbom = {
    metadata: { component: { "bom-ref": "root", name: "demo", version: "1.0" } },
    components: [
      { "bom-ref": "a", name: "openssl", version: "3.0.0", purl: "a" },
      { "bom-ref": "b", name: "zlib", version: "1.2.0", purl: "b" },
    ],
    dependencies: [
      { ref: "root", dependsOn: ["a"] },
      { ref: "a", dependsOn: ["b"] },
    ],
  };

  it("marks vulnerable nodes with their severity in graph and tree", () => {
    const idx = vulnSeverityIndex(components);
    const g = parseSbomGraph(sbom, (n, v) => severityFor(idx, n, v));
    const openssl = g.nodes.find((n) => n.name === "openssl");
    const zlib = g.nodes.find((n) => n.name === "zlib");
    expect(openssl?.vuln).toBe("CRITICAL");
    expect(openssl?.direct).toBe(true);
    expect(zlib?.vuln).toBeUndefined();
    // tree root (openssl) carries the severity too
    expect(g.tree[0]?.vuln).toBe("CRITICAL");
  });

  it("leaves nodes unmarked when no lookup is given", () => {
    const g = parseSbomGraph(sbom);
    expect(g.nodes.every((n) => n.vuln === undefined)).toBe(true);
  });
});
