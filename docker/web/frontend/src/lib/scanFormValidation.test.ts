// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { isValidExcludePath, isValidGitRef } from "./useScanForm";

describe("isValidGitRef", () => {
  it("accepts a branch, a tag and a commit id", () => {
    for (const ref of ["main", "release/1.2", "v1.2.0", "a".repeat(40)]) expect(isValidGitRef(ref)).toBe(true);
  });
  it("refuses an option, a parent path and a space", () => {
    for (const ref of ["--upload-pack=x", "a..b", "-x", "a b", ""]) expect(isValidGitRef(ref)).toBe(false);
  });
});

describe("isValidExcludePath", () => {
  it("accepts a relative path", () => {
    for (const p of ["vendor", "vendor/legacy", ".hid"]) expect(isValidExcludePath(p)).toBe(true);
  });
  it("refuses an absolute path, a parent segment, a glob and a backslash", () => {
    for (const p of ["/etc", "../x", "a/../b", "a*", "a?", "a[b", "a\\b", "."]) expect(isValidExcludePath(p)).toBe(false);
  });
});
