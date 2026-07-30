// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

/**
 * The source viewer: the tree says WHAT was scanned, the pane beside it shows
 * the file's captured text. The source-tree section has no @visual baseline, so
 * these functional assertions are the only thing guarding the view.
 */

const FILES = {
  files: [
    { path: "src", type: "directory" },
    { path: "src/main.go", type: "file" },
    { path: "src/app.bin", type: "file" },
    { path: "bin", type: "directory" },
    { path: "bin/cat", type: "symlink" },
    { path: "LICENSE", type: "file" },
  ],
};

const SNAPSHOT = {
  root: "/src",
  totals: {
    files: 2,
    bytes: 60,
    truncatedFiles: 0,
    skippedBinary: 1,
    skippedBudget: 0,
    skippedUnreadable: 0,
    links: 1,
  },
  links: [{ path: "bin/cat", target: "/bin/busybox" }],
  files: [
    {
      path: "LICENSE",
      size: 12,
      content: "MIT License\n",
      truncated: false,
    },
    {
      path: "src/main.go",
      size: 44,
      content: 'package main\n\nfunc main() {\n\tprintln("hi")\n}\n',
      truncated: false,
    },
  ],
};

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "testapp_1.0",
  results: [
    { name: "testapp_1.0_bom.json", size: 1234 },
    { name: "testapp_1.0_files.json", size: 200 },
    { name: "testapp_1.0_source.json", size: 400 },
  ],
  security: null,
  conformance: null,
  sbom: { components: 1, componentList: [] },
};

/** Stub the API and land on a finished scan with a source tree + snapshot. */
async function runScan(page: Page, snapshot: unknown = SNAPSHOT) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({
      contentType: "text/event-stream",
      body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n`,
    }),
  );
  await page.route("**/file**", (r) => {
    const url = r.request().url();
    if (url.includes("_source.json")) {
      if (snapshot === null) return r.fulfill({ status: 404, body: "" });
      return r.fulfill({
        contentType: "application/json",
        body: JSON.stringify(snapshot),
      });
    }
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify(FILES),
    });
  });

  await page.goto("/#/new");
  await page.fill("#project", "testapp");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
  await page
    .getByRole("navigation")
    .locator('a[href$="/sourceTree"]')
    .first()
    .click();
}

test("a scanned file's content opens from the tree", async ({ page }) => {
  await runScan(page);

  // Nothing selected yet: the pane invites a choice rather than sitting blank.
  await expect(page.getByText("Pick a file to read what was scanned.")).toBeVisible();

  await page.getByRole("button", { name: /main\.go/ }).click();

  // The real file body is on screen, line by line.
  await expect(page.getByText("package main")).toBeVisible();
  await expect(page.getByText('println("hi")')).toBeVisible();
  await expect(page.getByText("5 lines")).toBeVisible();
});

test("selection is announced and moves between files", async ({ page }) => {
  await runScan(page);

  const goFile = page.getByRole("button", { name: /main\.go/ });
  await goFile.click();
  await expect(goFile).toHaveAttribute("aria-current", "true");

  const license = page.getByRole("button", { name: /LICENSE/ });
  await license.click();
  await expect(license).toHaveAttribute("aria-current", "true");
  await expect(goFile).not.toHaveAttribute("aria-current", "true");
  await expect(page.getByText("MIT License")).toBeVisible();
});

test("a file is reachable by keyboard alone", async ({ page }) => {
  await runScan(page);
  const license = page.getByRole("button", { name: /LICENSE/ });
  await license.focus();
  await expect(license).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByText("MIT License")).toBeVisible();
});

test("a binary file says why it has no preview instead of showing nothing", async ({
  page,
}) => {
  await runScan(page);
  await page.getByRole("button", { name: /app\.bin/ }).click();
  await expect(
    page.getByText(
      "No preview — this file is binary, so only its path was recorded.",
    ),
  ).toBeVisible();
});

test("the capture summary reports what was left out", async ({ page }) => {
  await runScan(page);
  await expect(
    page.getByText("2 file(s) captured from the scanned tree."),
  ).toBeVisible();
  await expect(
    page.getByText("1 left out (binary, or past the capture limit)."),
  ).toBeVisible();
});

test("a truncated file is flagged, not passed off as complete", async ({ page }) => {
  await runScan(page, {
    ...SNAPSHOT,
    totals: { ...SNAPSHOT.totals, truncatedFiles: 1 },
    files: [
      { path: "LICENSE", size: 900000, content: "MIT License\n", truncated: true },
    ],
  });
  await page.getByRole("button", { name: /LICENSE/ }).click();
  await expect(page.getByText("Shown in part")).toBeVisible();
});

test("the tree still renders when the scan captured no content", async ({ page }) => {
  // A scan from before the snapshot existed: the structure must survive, and
  // the pane must explain the gap rather than the section failing.
  await runScan(page, null);
  await expect(page.getByRole("button", { name: /main\.go/ })).toBeVisible();
  await page.getByRole("button", { name: /main\.go/ }).click();
  await expect(page.getByText("No content was captured for this file.")).toBeVisible();
});

test("a symlink shows where it points instead of a blank pane", async ({ page }) => {
  // In a container image most of /bin is links into busybox; the destination is
  // the whole answer, and an empty content box would read as a broken view.
  await runScan(page);
  await page.getByRole("button", { name: /cat/ }).click();
  await expect(page.getByText("This is a symlink to")).toBeVisible();
  await expect(page.getByText("/bin/busybox")).toBeVisible();
});

test("links are counted in the capture summary", async ({ page }) => {
  await runScan(page);
  await expect(page.getByText("1 symlinks.")).toBeVisible();
});
