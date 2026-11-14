// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

import { captureMain, COMBOS, seedThemeLang, type Lang, type Theme } from "./visual";

/**
 * The submitted-SBOM section: for a scan whose input was someone else's SBOM,
 * what that document said before it was converted to CycloneDX. The assertions
 * here cover the fields; the @visual baseline at the end covers the layout.
 */

const INPUT = {
  format: "SPDX",
  specVersion: "2.3",
  documentId: "https://acme.example/spdxdocs/supplier-app",
  documentName: "supplier-app-2.3.1",
  created: "2026-01-02T03:04:05Z",
  tools: ["syft-1.18.1"],
  authors: [],
  supplier: "Supplier Inc.",
  rootComponent: {
    name: "supplier-app",
    version: "",
    type: "",
    purl: "",
    licenses: ["CC0-1.0"],
  },
  componentCount: 2,
  originalName: "supplier.spdx.json",
  originalBytes: 8192,
};

const DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "supplier_1.0",
  results: [
    { name: "supplier_1.0_bom.json", size: 1234 },
    { name: "supplier_1.0_input.json", size: 400 },
  ],
  security: null,
  conformance: null,
  sbom: { components: 2, componentList: [] },
};

async function runAnalyze(
  page: Page,
  input: unknown = INPUT,
  theme: Theme = "light",
  lang: Lang = "en",
) {
  await seedThemeLang(page, theme, lang);
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
  await page.route("**/file**", (r) =>
    input === null
      ? r.fulfill({ status: 404, body: "" })
      : r.fulfill({
          contentType: "application/json",
          body: JSON.stringify(input),
        }),
  );

  await page.goto("/#/new");
  await page.fill("#project", "supplier");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click(); // language-independent
  await page
    .getByRole("navigation")
    .locator('a[href$="/inputSbom"]')
    .first()
    .click();
}

test("the submitted document's own identity is on screen", async ({ page }) => {
  await runAnalyze(page);

  await expect(page.getByText("supplier.spdx.json")).toBeVisible();
  // The format the supplier wrote in — not the CycloneDX everything else shows.
  await expect(page.getByText("SPDX 2.3")).toBeVisible();
  await expect(page.getByText("syft-1.18.1")).toBeVisible();
  await expect(page.getByText("Supplier Inc.")).toBeVisible();
  // Shown in UTC in the interface language; the recorded ISO text stays as the tooltip.
  const created = page.getByText("Jan 2, 2026, 03:04 UTC", { exact: true });
  await expect(created).toBeVisible();
  await expect(created).toHaveAttribute("title", "2026-01-02T03:04:05Z");
  await expect(page.getByText("2 entries", { exact: true })).toBeVisible();
});

test("fields the supplier left out are omitted, not shown blank", async ({
  page,
}) => {
  await runAnalyze(page, {
    format: "CycloneDX",
    specVersion: "1.6",
    componentCount: 5,
    originalName: "bare.cdx.json",
  });
  await expect(page.getByText("CycloneDX 1.6")).toBeVisible();
  // No tool, supplier or timestamp was recorded, so those rows are absent
  // rather than printed empty or guessed at.
  await expect(page.getByText("Produced by")).toHaveCount(0);
  await expect(page.getByText("Supplier", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Created", { exact: true })).toHaveCount(0);
});

test("the section points at the components list instead of repeating it", async ({
  page,
}) => {
  await runAnalyze(page);
  const link = page.getByRole("link", { name: "Components", exact: true }).last();
  await expect(link).toHaveAttribute("href", /components/);
});

test("a failed load offers a retry rather than an empty section", async ({
  page,
}) => {
  await runAnalyze(page, null);
  await expect(
    page.getByText("Could not load the details of the submitted SBOM."),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: /Retry/i })).toBeVisible();
});

test("a source scan never offers the submitted-SBOM section", async ({ page }) => {
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
      body: `event: done\ndata: ${JSON.stringify({
        ...DONE,
        mode: "SOURCE",
        results: [{ name: "supplier_1.0_bom.json", size: 1234 }],
      })}\n\n`,
    }),
  );
  await page.goto("/#/new");
  await page.fill("#project", "supplier");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click(); // language-independent
  await expect(
    page.getByRole("navigation").locator('a[href$="/inputSbom"]'),
  ).toHaveCount(0);
});

const LONG = {
  ...INPUT,
  // No hyphen, slash or space to break at: the browser has to break inside the word.
  originalName: "SupplierDocument".repeat(8) + ".json",
  documentName: "x".repeat(150),
  documentId: "0123456789abcdef".repeat(8),
  rootComponent: { ...INPUT.rootComponent, purl: "pkg:maven/" + "a".repeat(140) },
};

test("the footer links to Components without repeating a number that matches", async ({ page }) => {
  await runAnalyze(page);
  const footer = page.getByText("The entries themselves are listed", { exact: false });
  await expect(footer).toBeVisible();
  await expect(footer).not.toContainText("(2)");
  await expect(page.getByText("after conversion")).toHaveCount(0);
});

test("a hint names the converted count only when it differs from the entries", async ({ page }) => {
  await runAnalyze(page, { ...INPUT, componentCount: 5 });
  await expect(page.getByText("2 components after conversion")).toBeVisible();
});

test("the empty header values leave no blank row", async ({ page }) => {
  await runAnalyze(page);
  // INPUT has no authors and no root version/purl, so 8 facts of 10 remain.
  await expect(page.getByRole("term")).toHaveCount(8);
});

test("retry reloads the details after a failed load", async ({ page }) => {
  let calls = 0;
  await seedThemeLang(page, "light", "en");
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
  await page.route("**/file**", (r) => {
    // Only the input summary is counted: other artifact requests must not use up the failure.
    if (r.request().url().includes("_input.json")) calls += 1;
    return calls === 1
      ? r.fulfill({ status: 500, body: "" })
      : r.fulfill({ contentType: "application/json", body: JSON.stringify(INPUT) });
  });
  await page.goto("/#/new");
  await page.fill("#project", "supplier");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
  await page.getByRole("navigation").locator('a[href$="/inputSbom"]').first().click();
  await expect(page.getByRole("alert")).toBeVisible();
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("SPDX 2.3")).toBeVisible();
});

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`long names wrap without ellipsis or overflow at ${width}, ${lang}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await runAnalyze(page, LONG, "light", lang);
      await expect(page.locator(".bl-is-head h2")).toBeVisible();
      const bad = await page.evaluate(() => {
        const out: string[] = [];
        for (const el of document.querySelectorAll<HTMLElement>(".bl-is *")) {
          if (el.className.toString().includes("VisuallyHidden")) continue;
          const cs = getComputedStyle(el);
          if (cs.textOverflow === "ellipsis") out.push("ellipsis " + el.className);
          if (el.scrollWidth > el.clientWidth + 1 && cs.display !== "inline" && cs.overflowX !== "visible") out.push("clip " + el.className);
        }
        for (const el of document.querySelectorAll<HTMLElement>(".bl-is-head h2, .bl-is-facts dd")) {
          if (el.scrollWidth > el.clientWidth) out.push("overflow " + el.tagName + " " + (el.textContent ?? "").slice(0, 20));
        }
        const root = document.documentElement;
        if (root.scrollWidth > root.clientWidth) out.push("page overflow");
        return out;
      });
      expect(bad).toEqual([]);
    });
  }
  for (const theme of ["light", "dark"] as const) {
    test(`the screen clears axe, ${lang} ${theme}`, async ({ page }) => {
      await runAnalyze(page, INPUT, theme, lang);
      await expect(page.locator(".bl-is-head h2")).toBeVisible();
      const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(res.violations).toEqual([]);
    });
  }
}

for (const { theme, lang } of COMBOS) {
  test(`submitted SBOM matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await runAnalyze(page, INPUT, theme, lang);
    await expect(page.getByText("supplier.spdx.json")).toBeVisible();
    await captureMain(page, "input-sbom", theme, lang);
  });
}
