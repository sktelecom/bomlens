// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { FileNode } from "./scancode";
import { ancestorDirs, dirsWithMatchBelow, fileRowName, filterNodes } from "./sourceTreeFilter";

const file = (path: string): FileNode => ({
  name: path.split("/").pop()!,
  path,
  isDir: false,
  isLink: false,
  licenses: [],
  children: [],
});
const dir = (path: string, children: FileNode[]): FileNode => ({
  name: path.split("/").pop()!,
  path,
  isDir: true,
  isLink: false,
  licenses: [],
  children,
});

const tree = [
  dir("src", [dir("src/main", [file("src/main/App.java")]), file("src/readme.md")]),
  dir("docs", [file("docs/guide.md")]),
  file("LICENSE"),
];

describe("filterNodes", () => {
  it("returns the tree untouched for an empty filter", () => {
    expect(filterNodes(tree, "")).toBe(tree);
  });

  it("keeps a match with the folders on the way to it", () => {
    const out = filterNodes(tree, "app");
    expect(out.map((n) => n.path)).toEqual(["src"]);
    expect(out[0].children.map((n) => n.path)).toEqual(["src/main"]);
  });

  it("matches without regard to case", () => {
    expect(filterNodes(tree, "license").map((n) => n.path)).toEqual(["LICENSE"]);
  });

  it("keeps every child of a folder matched by its own name", () => {
    const out = filterNodes(tree, "docs");
    expect(out[0].children.map((n) => n.path)).toEqual(["docs/guide.md"]);
  });

  it("returns nothing when no name matches", () => {
    expect(filterNodes(tree, "zzz")).toEqual([]);
  });
});

describe("dirsWithMatchBelow", () => {
  it("opens folders that lead to a match", () => {
    expect([...dirsWithMatchBelow(tree, "app")].sort()).toEqual(["src", "src/main"]);
  });

  it("leaves a folder matched only by its own name closed", () => {
    expect(dirsWithMatchBelow(tree, "docs").size).toBe(0);
  });

  it("is empty without a filter", () => {
    expect(dirsWithMatchBelow(tree, "").size).toBe(0);
  });
});

describe("ancestorDirs", () => {
  it("lists the folders above a path", () => {
    expect([...ancestorDirs("a/b/c.txt")]).toEqual(["a", "a/b"]);
    expect(ancestorDirs("top.txt").size).toBe(0);
    expect(ancestorDirs(null).size).toBe(0);
  });
});

describe("fileRowName", () => {
  it("is the name alone without licences", () => {
    expect(fileRowName({ name: "main.go", licenses: [] })).toBe("main.go");
  });
  it("lists the labels as the row shows them", () => {
    expect(fileRowName({ name: "LICENSE", licenses: ["MIT", "ISC"] })).toBe("LICENSE, MIT, ISC");
  });
  it("names the folded count and then the folded licences", () => {
    expect(fileRowName({ name: "a.c", licenses: ["MIT", "ISC", "Zlib", "BSD-3-Clause"] })).toBe("a.c, MIT, ISC, +2 (Zlib, BSD-3-Clause)");
  });
});
