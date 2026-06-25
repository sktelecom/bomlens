import { describe, expect, it } from "vitest";

import { parseScanCode, type FileNode } from "./scancode";

// A ScanCode --json-pp report: a flat files[] list with POSIX paths, both
// directories and files, and licenses expressed several different ways.
const REPORT = {
  files: [
    { path: "src", type: "directory" },
    {
      path: "src/main.c",
      type: "file",
      detected_license_expression_spdx: "Apache-2.0",
    },
    {
      path: "src/util.c",
      type: "file",
      // No spdx field → fall back to license_detections.
      license_detections: [
        { license_expression_spdx: "MIT" },
        { license_expression_spdx: "MIT" }, // duplicate, deduped
        { license_expression: "BSD-3-Clause" },
      ],
    },
    { path: "README.md", type: "file" }, // no license
  ],
};

function find(nodes: FileNode[], path: string): FileNode | undefined {
  for (const n of nodes) {
    if (n.path === path) return n;
    const hit = find(n.children, path);
    if (hit) return hit;
  }
  return undefined;
}

describe("parseScanCode", () => {
  it("rebuilds the directory hierarchy from path segments", () => {
    const tree = parseScanCode(REPORT);
    expect(tree.map((n) => n.name).sort()).toEqual(["README.md", "src"]);
    const src = tree.find((n) => n.name === "src")!;
    expect(src.isDir).toBe(true);
    expect(src.children.map((c) => c.name)).toEqual(["main.c", "util.c"]);
  });

  it("sorts directories before files, then alphabetically", () => {
    const tree = parseScanCode(REPORT);
    // src (dir) precedes README.md (file) at the root.
    expect(tree.map((n) => n.name)).toEqual(["src", "README.md"]);
  });

  it("reads the SPDX expression when present", () => {
    const tree = parseScanCode(REPORT);
    expect(find(tree, "src/main.c")!.licenses).toEqual(["Apache-2.0"]);
  });

  it("merges and dedupes license_detections when no top-level expression", () => {
    const tree = parseScanCode(REPORT);
    expect(find(tree, "src/util.c")!.licenses).toEqual(["MIT", "BSD-3-Clause"]);
  });

  it("leaves files with no detected license empty", () => {
    const tree = parseScanCode(REPORT);
    expect(find(tree, "README.md")!.licenses).toEqual([]);
  });

  it("synthesizes intermediate directories absent from files[]", () => {
    // Only a deep file is listed; a/b must be created as directories.
    const tree = parseScanCode({
      files: [{ path: "a/b/c.txt", type: "file", detected_license_expression_spdx: "MIT" }],
    });
    expect(tree.map((n) => n.name)).toEqual(["a"]);
    const a = tree[0];
    expect(a.isDir).toBe(true);
    const b = a.children[0];
    expect(b).toMatchObject({ name: "b", isDir: true });
    expect(b.children[0]).toMatchObject({ name: "c.txt", isDir: false, licenses: ["MIT"] });
  });

  it("is defensive about empty / missing input and skips path-less rows", () => {
    expect(parseScanCode({})).toEqual([]);
    expect(parseScanCode({ files: [] })).toEqual([]);
    expect(parseScanCode({ files: [{ type: "file" }] })).toEqual([]);
  });
});
