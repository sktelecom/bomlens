// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { VexReceivedStatement, VulnItem } from "./api";
import { normPurl, receivedFor, receivedIndex } from "./vexReceived";

const row = (over: Partial<VulnItem>): VulnItem =>
  ({ id: "CVE-1", severity: "HIGH", pkg: "openssl", installed: "3.0.0", ...over }) as VulnItem;

const stmt = (over: Partial<VexReceivedStatement>): VexReceivedStatement => ({
  cve: "CVE-1",
  state: "not_affected",
  ...over,
});

describe("receivedFor", () => {
  it("normalizes a purl the way the server does", () => {
    expect(normPurl("pkg:npm/Foo@1.0?arch=x#sub")).toBe("pkg:npm/foo@1.0");
  });

  it("matches a row with a purl on the purl, ignoring qualifiers and case", () => {
    const idx = receivedIndex([stmt({ purl: "pkg:npm/foo@1.0", pkg: "foo", installed: "1.0" })], "acme 1");
    expect(receivedFor(idx, row({ purl: "pkg:NPM/foo@1.0?x=1", pkg: "foo", installed: "1.0" }))?.state).toBe(
      "not_affected",
    );
  });

  it("never applies a purl-bearing statement to another purl that shares a name", () => {
    const idx = receivedIndex([stmt({ purl: "pkg:npm/openssl@3.0.0", pkg: "openssl", installed: "3.0.0" })], null);
    expect(receivedFor(idx, row({ purl: "pkg:generic/openssl@3.0.0" }))).toBeUndefined();
  });

  it("lets a row with no purl match by name and version, whatever the statement carries", () => {
    const idx = receivedIndex([stmt({ purl: "pkg:generic/openssl@3.0.0", pkg: "openssl", installed: "3.0.0" })], null);
    expect(receivedFor(idx, row({}))?.state).toBe("not_affected");
    expect(receivedFor(idx, row({ installed: "3.0.1" }))).toBeUndefined();
  });

  it("lets a purl-less statement reach a row that has a purl, by name and version", () => {
    const idx = receivedIndex([stmt({ pkg: "openssl", installed: "3.0.0" })], null);
    expect(receivedFor(idx, row({ purl: "pkg:generic/openssl@3.0.0" }))?.state).toBe("not_affected");
  });

  it("applies a product-level statement only where no component statement did", () => {
    const idx = receivedIndex(
      [
        stmt({ scope: "product", state: "fixed", detail: "not shipped" }),
        stmt({ pkg: "openssl", installed: "3.0.0", state: "affected" }),
      ],
      "acme 1",
    );
    expect(receivedFor(idx, row({}))?.state).toBe("affected");
    const other = receivedFor(idx, row({ pkg: "zlib", installed: "1" }));
    expect(other).toMatchObject({ state: "fixed", detail: "not shipped", source: "acme 1" });
    expect(receivedFor(idx, row({ id: "CVE-2" }))).toBeUndefined();
  });
});
