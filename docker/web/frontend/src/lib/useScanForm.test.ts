// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import type { SourceType } from "./api";
import { ACCEPT, composeRootfsTarget, TEXT_INPUT, UPLOAD_KIND } from "./useScanForm";

// useScanForm is a React hook. This repo's Vitest runs in the "node"
// environment with no @testing-library/react or jsdom installed, so the
// stateful hook itself (project/version validation, ANALYZE forcing, vendored
// gating, submit/upload flow) is covered by the Playwright UI suite, not here.
// These unit tests pin the pure, exported lookup maps the hook (and both
// NewScan / ScanForm) rely on.

describe("UPLOAD_KIND", () => {
  it("maps only the upload sources to their server kind", () => {
    expect(UPLOAD_KIND["zip-upload"]).toBe("zip");
    expect(UPLOAD_KIND["sbom-upload"]).toBe("sbom");
    expect(UPLOAD_KIND["firmware-upload"]).toBe("firmware");
    expect(UPLOAD_KIND["model-upload"]).toBe("model");
  });

  it("leaves non-upload sources undefined", () => {
    const nonUpload: SourceType[] = [
      "current-dir",
      "rootfs-dir",
      "git-url",
      "ai-model",
      "docker-image",
    ];
    for (const s of nonUpload) expect(UPLOAD_KIND[s]).toBeUndefined();
  });
});

describe("ACCEPT", () => {
  it("offers an accept list for every upload kind", () => {
    expect(Object.keys(ACCEPT).sort()).toEqual([
      "declaration",
      "firmware",
      "model",
      "package",
      "sbom",
      "zip",
    ]);
  });

  it("includes the expected representative extensions", () => {
    expect(ACCEPT.zip).toContain(".zip");
    expect(ACCEPT.zip).toContain(".tar.gz");
    expect(ACCEPT.sbom).toContain(".json");
    expect(ACCEPT.sbom).toContain(".spdx.json");
    // Weight formats the model reader identifies by magic bytes. .bin is absent:
    // it names both a PyTorch checkpoint and a firmware image, and firmware
    // claims it.
    expect(ACCEPT.model).toContain(".gguf");
    expect(ACCEPT.model).toContain(".safetensors");
    expect(ACCEPT.model).not.toContain(".bin");
    // Measured formats only: a jar is read as a file, a wheel after unpacking.
    // A gem is absent on purpose — it yielded nothing either way.
    expect(ACCEPT.package).toContain(".jar");
    expect(ACCEPT.package).toContain(".whl");
    expect(ACCEPT.package).not.toContain(".gem");
    expect(ACCEPT.firmware).toContain(".bin");
    expect(ACCEPT.firmware).toContain(".squashfs");
    // The declaration the questions write, uploaded for a declared-model scan.
    expect(ACCEPT.declaration).toBe(".json");
  });

  it("is a comma-separated list with no empty entries", () => {
    for (const list of Object.values(ACCEPT)) {
      const parts = list.split(",");
      expect(parts.every((p) => p.length > 1)).toBe(true);
      expect(parts.every((p) => p.startsWith("."))).toBe(true);
    }
  });
});

describe("composeRootfsTarget", () => {
  it("passes the target through when no scan root is selected", () => {
    expect(composeRootfsTarget("", "centos-rootfs/")).toBe("centos-rootfs/");
    expect(composeRootfsTarget("", "  sub/dir  ")).toBe("sub/dir");
  });

  it("submits the root itself when the subpath is empty", () => {
    expect(composeRootfsTarget("/scan-targets/root", "")).toBe("/scan-targets/root");
    expect(composeRootfsTarget("/scan-targets/root", "   ")).toBe("/scan-targets/root");
  });

  it("joins a subpath under the selected root", () => {
    expect(composeRootfsTarget("/scan-targets/root", "usr/lib")).toBe(
      "/scan-targets/root/usr/lib",
    );
  });

  it("folds a leading slash so an absolute subpath cannot restate the base", () => {
    expect(composeRootfsTarget("/scan-targets/root", "/etc")).toBe(
      "/scan-targets/root/etc",
    );
    expect(composeRootfsTarget("/scan-targets/root", "//etc")).toBe(
      "/scan-targets/root/etc",
    );
  });
});

describe("TEXT_INPUT", () => {
  it("provides i18n keys for the free-text sources", () => {
    expect(TEXT_INPUT["git-url"]).toEqual({
      label: "source.gitUrl",
      placeholder: "source.gitPlaceholder",
      hint: "source.gitHint",
    });
    expect(Object.keys(TEXT_INPUT).sort()).toEqual([
      "ai-model",
      "docker-image",
      "git-url",
      "rootfs-dir",
    ]);
  });

  it("has no overlap with the upload sources", () => {
    for (const s of Object.keys(TEXT_INPUT) as SourceType[]) {
      expect(UPLOAD_KIND[s]).toBeUndefined();
    }
  });
});

describe("ACCEPT against the server's upload list", () => {
  // The drop zone refuses a dropped file whose name does not end in an accepted
  // extension, so its list has to be the server's (UPLOAD_EXTS in server.py)
  // exactly: a shorter one would turn away a file the upload form used to take
  // (a firmware .zip), a longer one would let the server answer 415.
  const source = readFileSync(new URL("../../../server.py", import.meta.url), "utf8");
  const block = source.slice(source.indexOf("UPLOAD_EXTS = {"), source.indexOf("\n}\n", source.indexOf("UPLOAD_EXTS = {")));
  const uncommented = block
    .split("\n")
    .map((l) => l.replace(/#.*$/, ""))
    .join("\n");
  const server: Record<string, string[]> = {};
  for (const m of uncommented.matchAll(/"(\w+)":\s*\(([^)]*)\)/g)) {
    server[m[1]] = [...m[2].matchAll(/"(\.[^"]+)"/g)].map((x) => x[1]);
  }

  it("reads every kind from server.py", () => {
    expect(Object.keys(server).sort()).toEqual(Object.keys(ACCEPT).sort());
  });

  for (const kind of Object.keys(ACCEPT) as Array<keyof typeof ACCEPT>) {
    it(`matches the server for ${kind}`, () => {
      const ours = ACCEPT[kind].split(",").map((x) => x.trim());
      // The picker also lists compound names the server covers by their last
      // part (.img.gz, .tar.gz): those are redundant with .gz, so compare on
      // the extensions the server names.
      for (const ext of server[kind]) expect(ours).toContain(ext);
      for (const ext of ours) {
        expect(server[kind].some((s) => ext.endsWith(s))).toBe(true);
      }
    });
  }
});
