// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  indexLinks,
  indexSnapshot,
  lineCount,
  missingReason,
  parseSnapshot,
  type SourceSnapshot,
} from "./sourceSnapshot";

const raw = {
  root: "/src",
  totals: {
    files: 2,
    bytes: 40,
    truncatedFiles: 1,
    skippedBinary: 3,
    skippedBudget: 0,
    skippedUnreadable: 0,
  },
  files: [
    { path: "go.mod", size: 20, content: "module acme\n", truncated: false },
    { path: "big.txt", size: 999, content: "xxx", truncated: true },
  ],
  links: [{ path: "bin/cat", target: "/bin/busybox" }],
};

describe("parseSnapshot", () => {
  it("keeps well-formed files with their sizes and truncation flag", () => {
    const s = parseSnapshot(raw);
    expect(s.root).toBe("/src");
    expect(s.files.map((f) => f.path)).toEqual(["go.mod", "big.txt"]);
    expect(s.files[1].truncated).toBe(true);
    expect(s.totals.skippedBinary).toBe(3);
  });

  it("drops entries that carry no usable path or content", () => {
    const s = parseSnapshot({
      files: [
        { path: "", content: "a" },
        { path: "ok.txt", content: "a" },
        { path: "no-content.txt" },
        { path: "wrong-type.txt", content: 42 },
        null,
      ],
    });
    expect(s.files.map((f) => f.path)).toEqual(["ok.txt"]);
  });

  it("survives an artifact that is missing or malformed entirely", () => {
    for (const input of [null, undefined, 7, "nope", {}, { files: "no" }]) {
      const s = parseSnapshot(input);
      expect(s.files).toEqual([]);
      expect(s.totals.files).toBe(0);
      expect(s.totals.skippedBinary).toBe(0);
    }
  });

  it("coerces negative or non-numeric totals to zero", () => {
    const s = parseSnapshot({
      totals: { files: -3, bytes: "big", skippedBinary: 1.5 },
      files: [],
    });
    expect(s.totals.files).toBe(0);
    expect(s.totals.bytes).toBe(0);
    expect(s.totals.skippedBinary).toBe(1.5);
  });

  it("falls back to the captured count when totals.files is absent", () => {
    const s = parseSnapshot({ files: [{ path: "a", content: "x" }] });
    expect(s.totals.files).toBe(1);
  });
});

describe("indexLinks", () => {
  it("resolves a tree path to where the link points", () => {
    // Most of a container image is links into busybox; the destination is the
    // whole content of such an entry.
    const map = indexLinks(parseSnapshot(raw));
    expect(map.get("bin/cat")).toBe("/bin/busybox");
    expect(map.get("go.mod")).toBeUndefined();
  });

  it("keeps a link whose target could not be read, with an empty destination", () => {
    const map = indexLinks(parseSnapshot({ links: [{ path: "broken" }] }));
    expect(map.get("broken")).toBe("");
  });

  it("is empty for a snapshot that recorded no links", () => {
    expect(indexLinks(parseSnapshot({})).size).toBe(0);
    expect(indexLinks(null).size).toBe(0);
  });
});

describe("indexSnapshot", () => {
  it("looks a file up by its tree path", () => {
    const map = indexSnapshot(parseSnapshot(raw));
    expect(map.get("go.mod")?.content).toBe("module acme\n");
    expect(map.get("absent")).toBeUndefined();
  });

  it("is empty for a missing snapshot", () => {
    expect(indexSnapshot(null).size).toBe(0);
  });
});

describe("missingReason", () => {
  const withTotals = (t: Partial<SourceSnapshot["totals"]>): SourceSnapshot =>
    parseSnapshot({ files: [{ path: "kept.txt", content: "x" }], totals: t });

  it("returns null for a file whose content was captured", () => {
    expect(missingReason(withTotals({}), "kept.txt")).toBeNull();
  });

  it("blames the size limit when the scanner dropped files for budget", () => {
    expect(missingReason(withTotals({ skippedBudget: 4 }), "gone.txt")).toBe(
      "budget",
    );
  });

  it("blames binary content when nothing was dropped for budget", () => {
    expect(missingReason(withTotals({ skippedBinary: 2 }), "app.bin")).toBe(
      "binary",
    );
  });

  it("admits it does not know when no counter explains the gap", () => {
    expect(missingReason(withTotals({}), "gone.txt")).toBe("unknown");
    expect(missingReason(null, "gone.txt")).toBe("unknown");
  });
});

describe("lineCount", () => {
  it("does not count the newline that ends the last line", () => {
    expect(lineCount("a\nb\n")).toBe(2);
    expect(lineCount("a\nb")).toBe(2);
  });

  it("counts a blank final line when the file really has one", () => {
    expect(lineCount("a\n\n")).toBe(2);
  });

  it("is zero for an empty file", () => {
    expect(lineCount("")).toBe(0);
  });
});
