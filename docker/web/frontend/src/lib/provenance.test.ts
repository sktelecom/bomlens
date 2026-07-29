import { describe, expect, it } from "vitest";

import type { ScanConfig } from "./api";
import { provenanceOf } from "./provenance";

/** A sidecar with only the fields provenance reads; the rest is irrelevant. */
function config(over: Partial<ScanConfig>): ScanConfig {
  return {
    source: "current-dir",
    target: "",
    project: "demo",
    version: "1.0.0",
    notice: true,
    security: true,
    deepLicense: false,
    identifyVendored: false,
    includeOsv: false,
    byteStable: false,
    deepCve: false,
    ...over,
  };
}

describe("provenanceOf", () => {
  it("shows a git URL for a cloned repo", () => {
    expect(
      provenanceOf(
        config({ source: "git-url", target: "https://github.com/acme/app" }),
      ),
    ).toEqual({
      kind: "git",
      value: "https://github.com/acme/app",
      labelKey: "provenance.git",
    });
  });

  it("shows the image reference for a container scan", () => {
    expect(
      provenanceOf(
        config({ source: "docker-image", target: "nginx:1.24-alpine" }),
      ),
    ).toMatchObject({ kind: "image", value: "nginx:1.24-alpine" });
  });

  it("shows the uploaded filename for firmware", () => {
    expect(
      provenanceOf(
        config({ source: "firmware-upload", sourceLabel: "router-v2.bin" }),
      ),
    ).toMatchObject({ kind: "file", value: "router-v2.bin" });
  });

  it("shows the folder path for a directory scan", () => {
    expect(
      provenanceOf(
        config({ source: "rootfs-dir", sourceLabel: "/srv/app" }),
      ),
    ).toMatchObject({ kind: "folder", value: "/srv/app" });
  });

  // A Yocto build directory reaches the same ANALYZE pipeline as an uploaded
  // SBOM, so only the sidecar distinguishes them. It gets its own kind because
  // the components came from the SBOM the build wrote, not from reading the
  // folder — labelling it "Scanned folder" would claim the wrong thing.
  it("shows the build directory for a Yocto scan", () => {
    expect(
      provenanceOf(
        config({ source: "yocto-build-dir", sourceLabel: "/home/me/poky/build" }),
      ),
    ).toEqual({
      kind: "yocto",
      value: "/home/me/poky/build",
      labelKey: "provenance.yocto",
    });
  });

  it("shows the model id for an AI scan", () => {
    expect(
      provenanceOf(
        config({ source: "ai-model", target: "google-bert/bert-base-uncased" }),
      ),
    ).toMatchObject({ kind: "model", value: "google-bert/bert-base-uncased" });
  });

  it("shows the filename for a received SBOM", () => {
    expect(
      provenanceOf(config({ source: "sbom-upload", sourceLabel: "vendor.cdx.json" })),
    ).toMatchObject({ kind: "sbom", value: "vendor.cdx.json" });
  });

  // sourceLabel is the more specific of the two, so it wins when a scan
  // recorded both (a folder scan that also carried a container path).
  it("prefers sourceLabel over target", () => {
    expect(
      provenanceOf(
        config({ source: "rootfs-dir", target: "/src", sourceLabel: "/home/me/app" }),
      ),
    ).toMatchObject({ value: "/home/me/app" });
  });

  // Nothing to show is a real state: older runs have no sidecar at all, and an
  // upload from before filenames were kept has a source but no value. Printing
  // a guess would be worse than printing nothing.
  it.each([null, undefined])("returns null for %p", (c) => {
    expect(provenanceOf(c)).toBeNull();
  });

  it("returns null when the sidecar carries no input value", () => {
    expect(provenanceOf(config({ source: "zip-upload" }))).toBeNull();
  });

  it("returns null for an unknown source", () => {
    expect(
      provenanceOf(config({ source: "teleport" as ScanConfig["source"] })),
    ).toBeNull();
  });
});
