import { describe, expect, it } from "vitest";

import type { DoneEvent } from "./api";
import { searchScan } from "./search";

const RESULT = {
  sbom: {
    componentList: [
      { name: "openssl", version: "3.0", group: "", purl: "pkg:deb/openssl@3.0", type: "library", licenses: [] },
      { name: "zlib", version: "1.2", group: "", purl: "pkg:deb/zlib@1.2", type: "library", licenses: [] },
    ],
  },
  security: {
    vulnerabilities: [
      { id: "CVE-2024-0001", severity: "CRITICAL", pkg: "openssl", installed: "3.0", fixed: "3.0.1", title: "heap overflow" },
      { id: "CVE-2024-0002", severity: "LOW", pkg: "zlib", installed: "1.2", fixed: "", title: "info leak" },
    ],
  },
} as unknown as DoneEvent;

describe("searchScan", () => {
  it("returns nothing for a blank query", () => {
    expect(searchScan(RESULT, "  ")).toEqual({ components: [], vulns: [] });
  });

  it("matches components by name/purl and vulns by package", () => {
    const r = searchScan(RESULT, "openssl");
    expect(r.components.map((c) => c.name)).toEqual(["openssl"]);
    expect(r.vulns.map((v) => v.id)).toEqual(["CVE-2024-0001"]);
  });

  it("matches a vulnerability by CVE id", () => {
    const r = searchScan(RESULT, "cve-2024-0002");
    expect(r.components).toEqual([]);
    expect(r.vulns.map((v) => v.id)).toEqual(["CVE-2024-0002"]);
  });

  it("caps each kind", () => {
    const many = {
      sbom: { componentList: Array.from({ length: 10 }, (_, i) => ({ name: `libx${i}`, version: "1", group: "", purl: "", type: "library", licenses: [] })) },
      security: { vulnerabilities: [] },
    } as unknown as DoneEvent;
    expect(searchScan(many, "libx", 6).components).toHaveLength(6);
  });
});
