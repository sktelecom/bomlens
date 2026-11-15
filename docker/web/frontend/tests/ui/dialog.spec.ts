// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * Modal behaviour that the visual snapshots and axe cannot see: the confirm
 * step in front of a delete (the files go from disk, so there is no undo), and
 * the focus contract of the shared Modal — focus enters the panel, Tab stays
 * inside it, and it returns to the opener on close.
 *
 * The backend is stubbed, and DELETE calls are counted, so "cancel deletes
 * nothing" is asserted against the network rather than the screen.
 */

const SCANS = [
  {
    id: "demo_2.1",
    project: "demo",
    version: "2.1",
    components: 1,
    maxSeverity: null,
    isAiScan: false,
    componentType: "application",
    generatedAt: 1700000000,
  },
];

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_2.1",
  results: [{ name: "demo_2.1_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: {
    components: 1,
    componentList: [
      {
        name: "openssl",
        version: "3.0.0",
        group: "",
        purl: "pkg:github/openssl/openssl",
        type: "library",
        licenses: ["Apache-2.0"],
      },
    ],
  },
};

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "2.1" } },
  components: [
    { "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o" },
  ],
  dependencies: [],
};

/** Stub the backend and record every DELETE the app sends. */
async function stub(page: Page) {
  const deletes: string[] = [];
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SCANS) }),
  );
  await page.route("**/scan-delete**", (r) => {
    deletes.push(new URL(r.request().url()).searchParams.get("id") ?? "");
    return r.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/scan?id=demo_2.1", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  return deletes;
}

/** The row's delete lives in its menu: open the menu, choose Delete. */
async function deleteFromRow(page: Page) {
  await page.getByRole("button", { name: /^More actions for/ }).first().click();
  await page.getByRole("menuitem", { name: "Delete" }).click();
}

test("deleting a scan asks first, and cancelling sends nothing", async ({ page }) => {
  const deletes = await stub(page);
  await page.goto("/?ui=next#/");
  await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();

  await deleteFromRow(page);

  // The prompt names the scan and warns that the files go.
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("demo 2.1");
  await expect(dialog).toContainText("cannot be undone");

  // Focus opens on Cancel, the safe choice.
  await expect(page.getByRole("button", { name: "Cancel" })).toBeFocused();

  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
  expect(deletes).toEqual([]);
  await expect(page.getByRole("cell", { name: /demo/ }).first()).toBeVisible();
});

test("confirming the prompt deletes the scan and says so", async ({ page }) => {
  const deletes = await stub(page);
  await page.goto("/?ui=next#/");
  await deleteFromRow(page);

  // The confirm button carries the destructive verb, not a bare "OK".
  await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();

  await expect.poll(() => deletes).toEqual(["demo_2.1"]);
  await expect(page.getByText("Scan deleted")).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("Escape dismisses the prompt without deleting", async ({ page }) => {
  const deletes = await stub(page);
  await page.goto("/?ui=next#/");
  await deleteFromRow(page);
  await expect(page.getByRole("dialog")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(deletes).toEqual([]);
});

test("the prompt is accessible", async ({ page }) => {
  await stub(page);
  await page.goto("/?ui=next#/");
  await deleteFromRow(page);
  await expect(page.getByRole("dialog")).toBeVisible();
  // The panel fades in; a contrast check taken mid-fade reads blended colours.
  await waitForSettled(page.getByRole("dialog"));

  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});

test("the artifact viewer traps focus and hands it back", async ({ page }) => {
  await stub(page);
  await page.goto("/?ui=next#/scan/demo_2.1/artifacts");

  const opener = page.getByRole("button", { name: "View" }).first();
  await opener.click();

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();

  // Focus moved into the panel...
  await expect(
    dialog.locator(":focus"),
    "focus should sit on a control inside the dialog",
  ).toHaveCount(1);

  // ...and Tab keeps it there, however many times it is pressed.
  for (let i = 0; i < 6; i += 1) await page.keyboard.press("Tab");
  await expect(dialog.locator(":focus")).toHaveCount(1);

  // Closing returns focus to the button that opened it.
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(opener).toBeFocused();
});
