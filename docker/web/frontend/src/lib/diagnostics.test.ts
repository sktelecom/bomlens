// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { copyToClipboard, ISSUE_FORM_URL } from "./diagnostics";

describe("copyToClipboard", () => {
  it("writes the text and reports success", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    expect(await copyToClipboard("hello", { clipboard: { writeText } })).toBe(true);
    expect(writeText).toHaveBeenCalledWith("hello");
  });

  it("reports failure when the clipboard rejects", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    expect(await copyToClipboard("x", { clipboard: { writeText } })).toBe(false);
  });

  it("reports failure when there is no clipboard API", async () => {
    expect(await copyToClipboard("x", {})).toBe(false);
    expect(await copyToClipboard("x", undefined)).toBe(false);
  });
});

describe("ISSUE_FORM_URL", () => {
  // The issue form file is the one source of truth: the URL must name a form
  // that exists. (electron/test/helpmenu.test.mjs checks its own copy the same
  // way, and that it equals this one.)
  const template = ISSUE_FORM_URL.split("template=")[1];
  const forms = resolve(__dirname, "../../../../../.github/ISSUE_TEMPLATE");

  it("points at the bug-report form on the public repository", () => {
    expect(ISSUE_FORM_URL.startsWith("https://github.com/sktelecom/bomlens/issues/new?template=")).toBe(true);
  });

  it("names a form file that exists", () => {
    expect(existsSync(resolve(forms, template))).toBe(true);
  });
});
