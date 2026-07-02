import { describe, expect, it } from "vitest";

import {
  parseSbomIdentity,
  SBOM_PARSE_MAX_CHARS,
  suggestIdentity,
} from "./scanDefaults";

describe("suggestIdentity — git-url", () => {
  it("uses the repo name without .git", () => {
    expect(suggestIdentity("git-url", { target: "https://github.com/acme/demo.git" }))
      .toEqual({ project: "demo" });
    expect(suggestIdentity("git-url", { target: "https://github.com/acme/demo" }))
      .toEqual({ project: "demo" });
  });

  it("tolerates trailing slashes and scp-like URLs", () => {
    expect(suggestIdentity("git-url", { target: "https://gitlab.com/g/sub/repo/" }))
      .toEqual({ project: "repo" });
    expect(suggestIdentity("git-url", { target: "git@github.com:acme/demo.git" }))
      .toEqual({ project: "demo" });
  });

  it("suggests nothing for an empty target", () => {
    expect(suggestIdentity("git-url", { target: "" })).toEqual({});
    expect(suggestIdentity("git-url", {})).toEqual({});
  });
});

describe("suggestIdentity — docker-image", () => {
  it("splits name and tag", () => {
    expect(suggestIdentity("docker-image", { target: "nginx:1.25" }))
      .toEqual({ project: "nginx", version: "1.25" });
  });

  it("keeps only the last path segment of a registry path", () => {
    expect(suggestIdentity("docker-image", { target: "ghcr.io/sktelecom/sbom-scanner:2.0" }))
      .toEqual({ project: "sbom-scanner", version: "2.0" });
  });

  it("does not mistake a registry port for a tag", () => {
    expect(suggestIdentity("docker-image", { target: "registry:5000/nginx" }))
      .toEqual({ project: "nginx" });
    expect(suggestIdentity("docker-image", { target: "registry:5000/nginx:1.25" }))
      .toEqual({ project: "nginx", version: "1.25" });
  });

  it("drops a digest instead of suggesting it as the version", () => {
    expect(
      suggestIdentity("docker-image", { target: "nginx@sha256:0f1e2d3c4b5a" }),
    ).toEqual({ project: "nginx" });
    expect(
      suggestIdentity("docker-image", { target: "ghcr.io/org/app:1.2@sha256:abc" }),
    ).toEqual({ project: "app", version: "1.2" });
  });

  it("suggests only the name for an untagged image", () => {
    expect(suggestIdentity("docker-image", { target: "nginx" })).toEqual({ project: "nginx" });
  });
});

describe("suggestIdentity — ai-model", () => {
  it("uses the model name from org/name", () => {
    expect(suggestIdentity("ai-model", { target: "google-bert/bert-base-uncased" }))
      .toEqual({ project: "bert-base-uncased" });
  });
});

describe("suggestIdentity — uploads (zip / firmware / sbom filename fallback)", () => {
  it("strips archive extensions, including compound ones", () => {
    expect(suggestIdentity("zip-upload", { fileName: "myapp.zip" }))
      .toEqual({ project: "myapp" });
    expect(suggestIdentity("zip-upload", { fileName: "myapp.tar.gz" }))
      .toEqual({ project: "myapp" });
    expect(suggestIdentity("firmware-upload", { fileName: "rootfs.img.gz" }))
      .toEqual({ project: "rootfs" });
  });

  it("splits a trailing version out of the file name", () => {
    expect(suggestIdentity("zip-upload", { fileName: "demo-1.2.3.zip" }))
      .toEqual({ project: "demo", version: "1.2.3" });
    expect(suggestIdentity("firmware-upload", { fileName: "openwrt-21.02.1.img" }))
      .toEqual({ project: "openwrt", version: "21.02.1" });
    expect(suggestIdentity("zip-upload", { fileName: "my-app_v2.0.tgz" }))
      .toEqual({ project: "my-app", version: "2.0" });
  });

  it("does not split an ambiguous bare number", () => {
    expect(suggestIdentity("zip-upload", { fileName: "release-2.zip" }))
      .toEqual({ project: "release-2" });
  });

  it("round-trips our own SBOM output naming for sbom uploads", () => {
    expect(suggestIdentity("sbom-upload", { fileName: "demo_1.0_bom.json" }))
      .toEqual({ project: "demo", version: "1.0" });
  });
});

describe("suggestIdentity — directories", () => {
  it("uses the hostDir leaf for the current folder", () => {
    expect(suggestIdentity("current-dir", { hostDir: "/Users/me/projects/acme-app" }))
      .toEqual({ project: "acme-app" });
    expect(suggestIdentity("current-dir", { hostDir: "C:\\work\\acme-app" }))
      .toEqual({ project: "acme-app" });
    expect(suggestIdentity("current-dir", {})).toEqual({});
  });

  it("uses the target leaf for a rootfs dir", () => {
    expect(suggestIdentity("rootfs-dir", { target: "/mnt/extracted/rootfs" }))
      .toEqual({ project: "rootfs" });
  });
});

describe("parseSbomIdentity", () => {
  it("reads CycloneDX metadata.component", () => {
    const text = JSON.stringify({
      bomFormat: "CycloneDX",
      metadata: { component: { name: "demo", version: "2.1" } },
    });
    expect(parseSbomIdentity(text)).toEqual({ project: "demo", version: "2.1" });
  });

  it("omits the version when CycloneDX has none", () => {
    const text = JSON.stringify({
      bomFormat: "CycloneDX",
      metadata: { component: { name: "demo" } },
    });
    expect(parseSbomIdentity(text)).toEqual({ project: "demo" });
  });

  it("reads the SPDX documentDescribes root package", () => {
    const text = JSON.stringify({
      spdxVersion: "SPDX-2.3",
      documentDescribes: ["SPDXRef-Package-demo"],
      packages: [
        { SPDXID: "SPDXRef-Package-other", name: "other", versionInfo: "9.9" },
        { SPDXID: "SPDXRef-Package-demo", name: "demo", versionInfo: "2.1" },
      ],
    });
    expect(parseSbomIdentity(text)).toEqual({ project: "demo", version: "2.1" });
  });

  it("returns null for non-JSON input (xml / tag-value SPDX)", () => {
    expect(parseSbomIdentity("<bom/>")).toBeNull();
    expect(parseSbomIdentity("SPDXVersion: SPDX-2.3")).toBeNull();
  });

  it("returns null when no identity is present", () => {
    expect(parseSbomIdentity(JSON.stringify({ bomFormat: "CycloneDX" }))).toBeNull();
    expect(parseSbomIdentity(JSON.stringify({ metadata: { component: { name: "" } } }))).toBeNull();
    expect(parseSbomIdentity(JSON.stringify(["not", "an", "object"]))).toBeNull();
  });

  it("skips oversized inputs", () => {
    const huge = `{"pad":"${"x".repeat(SBOM_PARSE_MAX_CHARS)}"}`;
    expect(parseSbomIdentity(huge)).toBeNull();
  });
});
