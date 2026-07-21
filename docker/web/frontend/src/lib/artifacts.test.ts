import { describe, expect, it } from "vitest";

import type { ResultFile } from "./api";
import { formatLabel, groupArtifacts } from "./artifacts";

const file = (name: string, size = 100): ResultFile => ({ name, size });

const PREFIX = "app_1.0";

// A full scan's worth of artifacts across multiple formats, plus a detached
// SBOM signature. Order is intentionally scrambled to exercise rank sorting.
const RESULTS: ResultFile[] = [
  file(`${PREFIX}_security.json`),
  // Internal EPSS enrichment feed — must NOT surface as a second JSON chip
  // on the security card.
  file(`${PREFIX}_security_epss.json`, 3),
  file(`${PREFIX}_risk-report.md`),
  file(`${PREFIX}_bom.json`, 4096),
  file(`${PREFIX}_risk-report.html`),
  file(`${PREFIX}_bom.json.sig`, 256),
  file(`${PREFIX}_NOTICE.txt`),
  file(`${PREFIX}_conformance.md`),
  file(`${PREFIX}_security.html`),
  file(`${PREFIX}_scancode.json`),
];

describe("groupArtifacts", () => {
  it("groups files into logical artifacts ordered by rank", () => {
    const groups = groupArtifacts(RESULTS);
    expect(groups.map((g) => g.key)).toEqual([
      "riskReport",
      "sbom",
      "notice",
      "conformance",
      "security",
      "license",
    ]);
  });

  it("flags the risk report as the single primary deliverable", () => {
    const groups = groupArtifacts(RESULTS);
    expect(groups.filter((g) => g.primary).map((g) => g.key)).toEqual(["riskReport"]);
  });

  it("collects every format of a report under one card, richest first", () => {
    const groups = groupArtifacts(RESULTS);
    const risk = groups.find((g) => g.key === "riskReport")!;
    // html (0) before md (1).
    expect(risk.formats.map((f) => f.ext)).toEqual(["html", "md"]);
    const security = groups.find((g) => g.key === "security")!;
    expect(security.formats.map((f) => f.ext)).toEqual(["html", "json"]);
  });

  it("derives i18n keys from the group key", () => {
    const sbom = groupArtifacts(RESULTS).find((g) => g.key === "sbom")!;
    expect(sbom.titleKey).toBe("result.kind.sbom.title");
    expect(sbom.descKey).toBe("result.kind.sbom.desc");
  });

  it("attaches the .sig to the SBOM card and excludes it from formats", () => {
    const sbom = groupArtifacts(RESULTS).find((g) => g.key === "sbom")!;
    expect(sbom.signature?.name).toBe(`${PREFIX}_bom.json.sig`);
    expect(sbom.formats.map((f) => f.name)).toEqual([`${PREFIX}_bom.json`]);
    // The signature never becomes a viewable format chip.
    expect(sbom.formats.some((f) => f.ext === "sig")).toBe(false);
  });

  it("marks json/html/md/txt viewable but never the signature", () => {
    const groups = groupArtifacts(RESULTS);
    const notice = groups.find((g) => g.key === "notice")!;
    expect(notice.formats[0]).toMatchObject({ ext: "txt", viewable: true });
    const sbom = groups.find((g) => g.key === "sbom")!;
    expect(sbom.formats[0].viewable).toBe(true);
  });

  it("surfaces a lone signature as its own downloadable card", () => {
    const groups = groupArtifacts([file(`${PREFIX}_bom.json.sig`, 256)]);
    expect(groups.map((g) => g.key)).toEqual(["signature"]);
    const sig = groups[0];
    expect(sig.formats).toHaveLength(1);
    expect(sig.formats[0]).toMatchObject({ ext: "sig", viewable: false });
    expect(sig.signature).toBeUndefined();
  });

  it("folds the SPDX export onto the SBOM card as a distinct chip", () => {
    const groups = groupArtifacts([
      file(`${PREFIX}_bom.json`, 4096),
      file(`${PREFIX}_bom.spdx.json`, 2048),
    ]);
    expect(groups.map((g) => g.key)).toEqual(["sbom"]);
    // CycloneDX json (rank 3) before the spdx pseudo-extension (rank 4).
    expect(groups[0].formats.map((f) => f.ext)).toEqual(["json", "spdx"]);
    expect(groups[0].formats.map((f) => f.name)).toEqual([
      `${PREFIX}_bom.json`,
      `${PREFIX}_bom.spdx.json`,
    ]);
    expect(groups[0].formats.every((f) => f.viewable)).toBe(true);
    // The file is here, so the card must not also offer to create it.
    expect(groups[0].spdxExportable).toBe(false);
  });

  it("marks the SBOM card exportable only while no SPDX file exists", () => {
    const [sbom] = groupArtifacts([file(`${PREFIX}_bom.json`)]);
    expect(sbom.spdxExportable).toBe(true);

    // Other cards never carry the export affordance.
    const groups = groupArtifacts([
      file(`${PREFIX}_bom.json`),
      file(`${PREFIX}_NOTICE.txt`),
    ]);
    expect(groups.find((g) => g.key === "notice")!.spdxExportable).toBe(false);
  });

  it("keeps the CycloneDX signature on the card when the SPDX one exists too", () => {
    const groups = groupArtifacts([
      file(`${PREFIX}_bom.json`),
      file(`${PREFIX}_bom.spdx.json`),
      file(`${PREFIX}_bom.spdx.json.sig`, 256),
      file(`${PREFIX}_bom.json.sig`, 256),
    ]);
    const sbom = groups.find((g) => g.key === "sbom")!;
    expect(sbom.signature?.name).toBe(`${PREFIX}_bom.json.sig`);
    // Neither .sig ever becomes a format chip.
    expect(sbom.formats.some((f) => f.ext === "sig")).toBe(false);
  });

  it("omits absent groups and returns empty for no results", () => {
    expect(groupArtifacts([])).toEqual([]);
    const only = groupArtifacts([file(`${PREFIX}_bom.json`)]);
    expect(only.map((g) => g.key)).toEqual(["sbom"]);
    expect(only[0].signature).toBeUndefined();
  });
});

describe("formatLabel", () => {
  it("upper-cases the extension", () => {
    expect(formatLabel("html")).toBe("HTML");
    expect(formatLabel("json")).toBe("JSON");
    expect(formatLabel("sig")).toBe("SIG");
    expect(formatLabel("spdx")).toBe("SPDX");
    expect(formatLabel("")).toBe("");
  });
});
