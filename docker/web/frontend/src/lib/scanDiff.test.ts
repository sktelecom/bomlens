// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { ComponentItem, VulnItem } from "./api";
import { diffComponents, diffVulnerabilities } from "./scanDiff";

function comp(over: Partial<ComponentItem> = {}): ComponentItem {
  return {
    name: "openssl",
    version: "3.0.0",
    group: "",
    purl: "pkg:generic/openssl@3.0.0",
    type: "library",
    licenses: ["Apache-2.0"],
    ...over,
  };
}

function vuln(over: Partial<VulnItem> = {}): VulnItem {
  return {
    id: "CVE-2024-0001",
    severity: "CRITICAL",
    pkg: "openssl",
    installed: "3.0.0",
    fixed: "3.0.1",
    title: "buffer overflow",
    ...over,
  };
}

describe("diffComponents", () => {
  it("reports a component present only in the current scan as added", () => {
    const d = diffComponents([], [comp({ name: "zlib" })]);
    expect(d.added.map((c) => c.name)).toEqual(["zlib"]);
    expect(d.removed).toEqual([]);
    expect(d.changed).toEqual([]);
  });

  it("reports a component present only in the previous scan as removed", () => {
    const d = diffComponents([comp({ name: "zlib" })], []);
    expect(d.removed.map((c) => c.name)).toEqual(["zlib"]);
    expect(d.added).toEqual([]);
    expect(d.changed).toEqual([]);
  });

  it("reports a version move as changed, not added+removed", () => {
    const d = diffComponents(
      [comp({ version: "3.0.0" })],
      [comp({ version: "3.0.1" })],
    );
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.changed).toEqual([
      { name: "openssl", group: "", from: "3.0.0", to: "3.0.1" },
    ]);
  });

  it("says nothing changed when both lists are identical", () => {
    const list = [comp()];
    const d = diffComponents(list, list);
    expect(d).toEqual({ added: [], removed: [], changed: [] });
  });

  it("keys on group + name, so same-name components in different groups never merge", () => {
    const d = diffComponents(
      [comp({ name: "core", group: "@angular", version: "1.0" })],
      [comp({ name: "core", group: "@babel", version: "1.0" })],
    );
    // Different groups: one removed, one added, not a version change.
    expect(d.added.map((c) => c.group)).toEqual(["@babel"]);
    expect(d.removed.map((c) => c.group)).toEqual(["@angular"]);
    expect(d.changed).toEqual([]);
  });
});

describe("diffVulnerabilities", () => {
  it("reports a CVE present only in the current scan as new", () => {
    const d = diffVulnerabilities([], [vuln({ id: "CVE-2024-0002" })]);
    expect(d.new.map((v) => v.id)).toEqual(["CVE-2024-0002"]);
    expect(d.resolved).toEqual([]);
  });

  it("reports a CVE present only in the previous scan as resolved", () => {
    const d = diffVulnerabilities([vuln({ id: "CVE-2024-0002" })], []);
    expect(d.resolved.map((v) => v.id)).toEqual(["CVE-2024-0002"]);
    expect(d.new).toEqual([]);
  });

  it("says nothing changed when the same CVE id appears in both", () => {
    const d = diffVulnerabilities([vuln()], [vuln()]);
    expect(d.new).toEqual([]);
    expect(d.resolved).toEqual([]);
  });
});
