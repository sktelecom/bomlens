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
    expect(Object.keys(ACCEPT).sort()).toEqual(["firmware", "sbom", "zip"]);
  });

  it("includes the expected representative extensions", () => {
    expect(ACCEPT.zip).toContain(".zip");
    expect(ACCEPT.zip).toContain(".tar.gz");
    expect(ACCEPT.sbom).toContain(".json");
    expect(ACCEPT.sbom).toContain(".spdx.json");
    expect(ACCEPT.firmware).toContain(".bin");
    expect(ACCEPT.firmware).toContain(".squashfs");
  });

  it("is a comma-separated list with no empty entries", () => {
    for (const list of Object.values(ACCEPT)) {
      const parts = list.split(",");
      expect(parts.length).toBeGreaterThan(1);
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
