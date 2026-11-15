// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

import { type Lang, seedThemeLang, type Theme } from "./visual";

/**
 * The Source tree screen on Primer: a keyboard tree beside the selected file's
 * text. Covers the filter, the folder keys, the wrap switch, the "show the
 * rest" reset between files, the loading and error states, layout without
 * clipping, and axe in both themes and languages.
 */

const LONG = Array.from({ length: 1620 }, (_, i) => `line ${i + 1}`).join("\n") + "\n";

const FILES = {
  files: [
    { path: "src", type: "directory" },
    { path: "src/main", type: "directory" },
    { path: "src/main/ThisIsAVeryLongSourceFileNameThatHasToWrapInsteadOfBeingCutOffAnywhere.java", type: "file" },
    { path: "src/main.go", type: "file" },
    { path: "src/app.bin", type: "file" },
    { path: "bin", type: "directory" },
    { path: "bin/cat", type: "symlink" },
    { path: "LICENSE", type: "file" },
    { path: "long.txt", type: "file" },
    { path: "other.txt", type: "file" },
  ],
};

const SNAPSHOT = {
  root: "/src",
  totals: { files: 4, bytes: 60, truncatedFiles: 0, skippedBinary: 1, skippedBudget: 0, skippedUnreadable: 0, links: 1 },
  links: [{ path: "bin/cat", target: "/bin/busybox" }],
  files: [
    { path: "LICENSE", size: 12, content: "MIT License\n", truncated: false },
    { path: "long.txt", size: 20000, content: LONG, truncated: false },
    { path: "other.txt", size: 6, content: "other\n", truncated: false },
    { path: "src/main.go", size: 44, content: 'package main\n\nfunc main() {\n\tprintln("hi")\n}\n', truncated: false },
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

async function open(
  page: Page,
  opts: { theme?: Theme; lang?: Lang; files?: unknown; done?: unknown; snapshot?: unknown; tree?: "ok" | "fail" | "slow"; hold?: Promise<void> } = {},
) {
  await seedThemeLang(page, opts.theme ?? "light", opts.lang ?? "en");
  await page.route("**/capabilities", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }));
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) => r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(opts.done ?? DONE)}\n\n` }));
  await page.route("**/file**", async (r) => {
    const url = r.request().url();
    if (url.includes("_source.json")) return r.fulfill({ contentType: "application/json", body: JSON.stringify(opts.snapshot ?? SNAPSHOT) });
    if (opts.hold) await opts.hold;
    if (opts.tree === "fail") return r.fulfill({ status: 500, body: "" });
    return r.fulfill({ contentType: "application/json", body: JSON.stringify(opts.files ?? FILES) });
  });
  await page.goto("/#/new");
  await page.fill("#project", "testapp");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
  await page.getByRole("navigation").locator('a[href$="/sourceTree"]').first().click();
}

test("the filter keeps matching files with their folders and says when none match", async ({ page }) => {
  await open(page);
  const tree = page.getByRole("tree");
  await expect(tree.getByRole("treeitem", { name: /main\.go/ })).toBeVisible();
  await page.getByRole("textbox", { name: "Filter by file name" }).fill("main");
  await expect(tree.getByRole("treeitem", { name: /main\.go/ })).toBeVisible();
  await expect(tree.getByRole("treeitem", { name: /LICENSE/ })).toHaveCount(0);
  await page.getByRole("textbox", { name: "Filter by file name" }).fill("zzz");
  await expect(page.getByText("No file name matches.")).toBeVisible();
  await page.getByRole("textbox", { name: "Filter by file name" }).fill("");
  await expect(tree.getByRole("treeitem", { name: /LICENSE/ })).toBeVisible();
});

test("a folder opens and closes from the keyboard", async ({ page }) => {
  await open(page);
  const folder = page.getByRole("treeitem", { name: "src", exact: true });
  await expect(folder).toHaveAttribute("aria-expanded", "true");
  await folder.focus();
  await page.keyboard.press("ArrowLeft");
  await expect(folder).toHaveAttribute("aria-expanded", "false");
  await page.keyboard.press("ArrowRight");
  await expect(folder).toHaveAttribute("aria-expanded", "true");
});

test("long lines wrap by default and the switch turns that off", async ({ page }) => {
  await open(page);
  await page.getByRole("treeitem", { name: /main\.go/ }).click();
  const wrap = page.getByRole("button", { name: "Wrap lines" });
  await expect(wrap).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("table.bl-src-code")).toHaveClass(/bl-src-wrap/);
  await wrap.click();
  await expect(wrap).toHaveAttribute("aria-pressed", "false");
  await expect(page.locator("table.bl-src-code")).not.toHaveClass(/bl-src-wrap/);
});

test("the rest of a long file starts folded again on another file", async ({ page }) => {
  await open(page);
  await page.getByRole("treeitem", { name: /long\.txt/ }).click();
  await expect(page.getByText("line 1500", { exact: true })).toBeVisible();
  await expect(page.getByText("line 1501", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Show the remaining 120 lines" }).click();
  await expect(page.getByText("line 1620", { exact: true })).toBeVisible();
  await page.getByRole("treeitem", { name: /other\.txt/ }).click();
  await page.getByRole("treeitem", { name: /long\.txt/ }).click();
  await expect(page.getByRole("button", { name: "Show the remaining 120 lines" })).toBeVisible();
  await expect(page.getByText("line 1620", { exact: true })).toHaveCount(0);
});

test("an empty inventory says so and offers no filter", async ({ page }) => {
  await open(page, { files: { files: [] } });
  await expect(page.getByText("No source files were scanned.")).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Filter by file name" })).toHaveCount(0);
});

test("a tree that cannot load shows an error with a retry that works", async ({ page }) => {
  await open(page, { tree: "fail" });
  await expect(page.getByRole("alert")).toContainText("Could not load the source file tree.");
  const requested: string[] = [];
  await page.unroute("**/file**");
  await page.route("**/file**", (r) => {
    const url = r.request().url();
    requested.push(url);
    if (url.includes("_source.json")) return r.fulfill({ contentType: "application/json", body: JSON.stringify(SNAPSHOT) });
    return r.fulfill({ contentType: "application/json", body: JSON.stringify(FILES) });
  });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("treeitem", { name: /LICENSE/ })).toBeVisible();
  // The retry asks for the snapshot again as well as the tree.
  expect(requested.some((u) => u.includes("_source.json"))).toBe(true);
  expect(requested.some((u) => !u.includes("_source.json"))).toBe(true);
});

test("the tree shows a loading status until it arrives", async ({ page }) => {
  let release!: () => void;
  const hold = new Promise<void>((res) => (release = res));
  await open(page, { hold });
  await expect(page.getByRole("status").filter({ hasText: "Loading source tree" })).toBeVisible();
  release();
  await expect(page.getByRole("treeitem", { name: /LICENSE/ })).toBeVisible();
});

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`nothing is clipped at ${width}px, ${lang}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await open(page, { lang });
      // The long name sits one folder down: open it, then check it wraps.
      await page.getByRole("treeitem", { name: "main", exact: true }).click();
      await expect(page.getByRole("treeitem", { name: /ThisIsAVeryLong/ })).toBeVisible();
      await page.getByRole("treeitem", { name: /main\.go/ }).click();
      const bad = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        clipped: [...document.querySelectorAll("main [role=tree] *, main .bl-src-head *")].filter((e) => {
          const s = getComputedStyle(e);
          return s.textOverflow === "ellipsis" || (e.scrollWidth > e.clientWidth + 1 && s.overflow !== "visible");
        }).length,
      }));
      expect(bad.page).toBeLessThanOrEqual(0);
      expect(bad.clipped).toBe(0);
    });
  }
  for (const theme of ["light", "dark"] as const) {
    test(`the screen clears axe, ${lang} ${theme}`, async ({ page }) => {
      await open(page, { lang, theme });
      const run = () => new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      await expect(page.getByRole("treeitem", { name: /main\.go/ })).toBeVisible();
      expect((await run()).violations).toEqual([]);
      await page.getByRole("treeitem", { name: /main\.go/ }).click();
      await expect(page.locator(".hljs-keyword").first()).toBeVisible();
      expect((await run()).violations).toEqual([]);
    });
  }
}

test("a short file that was cut off still says so", async ({ page }) => {
  // other.txt has one line, well under the 1,500-line cap, yet was cut at capture.
  await open(page, {
    snapshot: { ...SNAPSHOT, files: [{ path: "other.txt", size: 900000, content: "other\n", truncated: true }] },
  });
  await page.getByRole("treeitem", { name: /other\.txt/ }).click();
  await expect(page.getByText("The rest of this file went past the capture limit and was not stored.")).toBeVisible();
});

test("a scan with no stored contents says so once, not per file", async ({ page }) => {
  await open(page, { done: { ...DONE, results: DONE.results.filter((r) => !r.name.includes("_source")) } });
  await expect(page.getByTestId("source-note")).toHaveText(/did not store file contents/);
  await page.getByRole("treeitem", { name: /main\.go/ }).click();
  await expect(page.getByText("This scan did not store file contents. Only the file structure is shown.")).toHaveCount(2);
  await expect(page.getByText("No content was captured for this file.")).toHaveCount(0);
});

test("one summary line ends with the licence hint when the scan was not ScanCode", async ({ page }) => {
  await open(page);
  const note = page.getByTestId("source-note");
  await expect(note).toContainText("4 files captured.");
  await expect(note).toContainText("License details appear when you run a ScanCode (deep-license) scan.");
  await expect(page.getByTestId("source-note")).toHaveCount(1);
});

test("clearing the filter keeps the open file visible and the reader's folders open", async ({ page }) => {
  await open(page);
  // Open src/main, pick a file below it, then filter and clear.
  await page.getByRole("treeitem", { name: "main", exact: true }).click();
  await page.getByRole("treeitem", { name: /ThisIsAVeryLong/ }).click();
  const box = page.getByRole("textbox", { name: "Filter by file name" });
  await box.fill("LICENSE");
  await expect(page.getByRole("treeitem", { name: /ThisIsAVeryLong/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Clear the filter" }).click();
  await expect(box).toHaveValue("");
  await expect(page.getByRole("treeitem", { name: /ThisIsAVeryLong/ })).toBeVisible();
  await expect(page.getByRole("treeitem", { name: /ThisIsAVeryLong/ })).toHaveAttribute("aria-current", "true");
});

test("a folder matched only by its own name stays closed", async ({ page }) => {
  await open(page);
  await page.getByRole("textbox", { name: "Filter by file name" }).fill("src");
  const folder = page.getByRole("treeitem", { name: "src", exact: true });
  await expect(folder).toBeVisible();
  await expect(folder).toHaveAttribute("aria-expanded", "false");
});
