// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * "Report a problem": with a finished scan open, succeeded or failed, the Help
 * menu opens a dialog with the diagnostics summary on screen in full and one
 * button that puts exactly that text on the clipboard. Nothing is sent anywhere, so the test also asserts that no request
 * other than the read-only summary fetch is made by pressing the button.
 */
const SUMMARY = [
  "BomLens diagnostics",
  "app version: 1.12.0",
  "scanner image: ghcr.io/sktelecom/bomlens:1.12.0",
  "container engine: server 27.0.3, Docker Desktop (linux/aarch64)",
  "mode: SOURCE",
  "outcome: OUTCOME",
  "warnings: 1",
  "  [WARN] cannot read /Users/***/proj/pom.xml",
  "",
].join("\n");

const base = {
  id: "testapp_1.0",
  mode: "SOURCE",
  results: [{ name: "testapp_1.0_bom.json", size: 1234 }],
  security: null,
  conformance: null,
  sbom: { components: 1, componentList: [] },
};

async function stub(page: Page, ok: boolean) {
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
      body: `event: done\ndata: ${JSON.stringify({ ...base, ok })}\n\n`,
    }),
  );
  await page.route("**/diagnostics**", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        text: SUMMARY.replace("OUTCOME", ok ? "succeeded" : "failed"),
      }),
    }),
  );
}

/** The Help menu's "Report a problem" with a finished scan open: it opens the dialog. */
async function openReport(page: Page) {
  await page.getByTestId("help-menu").click();
  await page.getByTestId("help-report").click();
  await expect(page.getByRole("dialog", { name: "Report a problem" })).toBeVisible();
}

async function run(page: Page) {
  await page.goto("/#/new");
  await page.fill("#project", "testapp");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

for (const ok of [true, false]) {
  test(`a ${ok ? "successful" : "failed"} scan shows the summary and copies it in one press`, async ({
    page,
    context,
  }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await stub(page, ok);
    const requests: string[] = [];
    page.on("request", (req) => requests.push(new URL(req.url()).pathname));

    await run(page);
    if (ok) {
      // A finished scan fetches nothing until the dialog is opened.
      await expect(page.getByTestId("report-text")).toHaveCount(0);
      expect(requests).not.toContain("/diagnostics");
      await openReport(page);
    } else {
      // A failed scan shows the summary expanded in its banner, with no dialog.
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await expect(page.getByTestId("report-text-inline")).toBeVisible();
      await openReport(page);
    }

    const shown = page.getByRole("dialog").getByTestId("report-text");
    await expect(shown).toBeVisible();
    const expected = SUMMARY.replace("OUTCOME", ok ? "succeeded" : "failed");
    await expect(shown).toHaveValue(expected);
    await expect(page.getByRole("dialog").getByTestId("report-problem")).toContainText(/nothing is sent anywhere/i);

    const before = requests.length;
    await page.getByRole("dialog").getByRole("button", { name: "Copy summary" }).click();
    await expect(page.getByText("Summary copied")).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(expected);
    // Pressing the button is local: no request follows it.
    expect(requests.length).toBe(before);
  });
}

test("the issue form opens away from the app", async ({ page }) => {
  await stub(page, false);
  await run(page);
  await openReport(page);
  const link = page.getByRole("dialog").getByRole("link", { name: "Open the issue form" });
  await expect(link).toHaveAttribute("href", /issues\/new\?template=bug_report\.yml$/);
  await expect(link).toHaveAttribute("target", "_blank");
  await expect(link).toHaveAttribute("rel", /noopener/);
});

test("the help menu links to the issue form", async ({ page }) => {
  await stub(page, true);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByTestId("help-menu").click();
  await expect(page.getByTestId("help-report")).toHaveAttribute(
    "href",
    /issues\/new\?template=bug_report\.yml$/,
  );
});

test("with a finished scan open the help menu entry opens the dialog instead of leaving the app", async ({ page }) => {
  await stub(page, true);
  await run(page);
  await page.getByTestId("help-menu").click();
  // A button, not a link: nothing leaves the app until the dialog's own link is used.
  await expect(page.getByTestId("help-report")).not.toHaveAttribute("href", /.+/);
  await page.getByTestId("help-report").click();
  const dialog = page.getByRole("dialog", { name: "Report a problem" });
  await expect(dialog.getByTestId("report-text")).toBeVisible();
  await expect(dialog.getByRole("link", { name: "Open the issue form" })).toHaveAttribute(
    "href",
    /issues\/new\?template=bug_report\.yml$/,
  );
  // Escape closes it and the page behind is intact.
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(page.getByTestId("report-text")).toHaveCount(0);
});

test("a failed scan's banner carries the summary expanded, with copy and the issue form", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await stub(page, false);
  await run(page);
  const banner = page.getByRole("alert");
  await expect(banner).toBeVisible();
  // No dialog opens by itself: the summary sits in the banner, already shown.
  await expect(page.getByRole("dialog")).toHaveCount(0);
  const inline = banner.getByTestId("report-text-inline");
  await expect(inline).toHaveValue(SUMMARY.replace("OUTCOME", "failed"));
  await banner.getByTestId("report-problem-inline").getByRole("button", { name: "Copy summary" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(SUMMARY.replace("OUTCOME", "failed"));
  await expect(banner.getByTestId("report-problem-inline").getByRole("link", { name: "Open the issue form" })).toHaveAttribute(
    "href",
    /issues\/new\?template=bug_report\.yml$/,
  );
  // The banner's button opens the same dialog as the help menu.
  await banner.getByRole("button", { name: "Report a problem" }).click();
  await expect(page.getByRole("dialog", { name: "Report a problem" }).getByTestId("report-text")).toBeVisible();
});

test("a successful scan has no summary on the page until the dialog is opened", async ({ page }) => {
  await stub(page, true);
  await run(page);
  await expect(page.getByTestId("report-text-inline")).toHaveCount(0);
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("the dialog closes when the scan on screen changes", async ({ page }) => {
  await stub(page, true);
  await page.route("**/scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        { id: "testapp_1.0", project: "testapp", version: "1.0", components: 1, maxSeverity: null, isAiScan: false, generatedAt: 1700000000 },
        { id: "other_2.0", project: "other", version: "2.0", components: 1, maxSeverity: null, isAiScan: false, generatedAt: 1700000100 },
      ]),
    }),
  );
  await page.route("**/scan?id=other_2.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ ...base, id: "other_2.0", ok: true }) }),
  );
  await run(page);
  await openReport(page);
  // Leave for another scan by the URL hash (the modal is dismissed by the route change).
  await page.evaluate(() => {
    location.hash = "#/";
  });
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.evaluate(() => {
    location.hash = "#/scan/other_2.0";
  });
  await page.locator("main h1").first().waitFor();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByTestId("report-text")).toHaveCount(0);
});

test("focus returns to the control that opened the dialog", async ({ page }) => {
  await stub(page, false);
  await run(page);
  // From the help menu: back on the Help button.
  await openReport(page);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByTestId("help-menu")).toBeFocused();
  // From the failed scan's banner: back on the banner's button.
  const button = page.getByRole("alert").getByRole("button", { name: "Report a problem" });
  await button.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(button).toBeFocused();
});

test("a blocked clipboard says so and leaves the text to copy by hand", async ({ page }) => {
  await stub(page, false);
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
  });
  await run(page);
  await openReport(page);
  await page.getByRole("dialog").getByRole("button", { name: "Copy summary" }).click();
  await expect(page.getByRole("dialog").getByText(/Copying was blocked here/)).toBeVisible();
  await expect(page.getByTestId("report-text")).toBeVisible();
});

test("the copy log button copies the visible log", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await stub(page, true);
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({
      contentType: "text/event-stream",
      body:
        `event: log\ndata: "first line"\n\nevent: log\ndata: "second line"\n\n` +
        `event: done\ndata: ${JSON.stringify({ ...base, ok: true })}\n\n`,
    }),
  );
  await run(page);
  await page.getByText("Run log").first().click(); // open the collapsed log
  await page.getByRole("button", { name: "Copy log" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    "first line\nsecond line",
  );
});

test("a blocked clipboard on the log copy says so", async ({ page }) => {
  await stub(page, true);
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
  });
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({
      contentType: "text/event-stream",
      body:
        `event: log\ndata: "first line"\n\n` +
        `event: done\ndata: ${JSON.stringify({ ...base, ok: true })}\n\n`,
    }),
  );
  await run(page);
  await page.getByText("Run log").first().click();
  await expect(page.getByText(/read it before you paste it/i)).toBeVisible();
  await page.getByRole("button", { name: "Copy log" }).click();
  await expect(page.getByText(/Select the log above and copy it by hand/)).toBeVisible();
});

test("a scan that ends in a stream error sends its on-screen error to the summary", async ({
  page,
}) => {
  await stub(page, false);
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({
      contentType: "text/event-stream",
      body: `event: error\ndata: ${JSON.stringify({ detail: "Failed to launch scan: boom", key: null })}\n\n`,
    }),
  );
  const seen: string[] = [];
  await page.route("**/diagnostics**", (r) => {
    seen.push(r.request().url());
    return r.fulfill({ contentType: "application/json", body: JSON.stringify({ text: "x" }) });
  });
  await run(page);
  await expect(page.getByTestId("report-text")).toBeVisible();
  expect(new URL(seen[0]).searchParams.get("error")).toBe("Failed to launch scan: boom");
});

test("the report dialog has no accessibility violations", async ({ page }) => {
  await stub(page, false);
  await run(page);
  await expect(page.getByTestId("report-text-inline")).toBeVisible();
  await openReport(page);
  await expect(page.getByTestId("report-text")).toBeVisible();
  // Both copy buttons (banner and dialog) are enabled: a disabled one is still loading.
  for (const b of await page.getByRole("button", { name: "Copy summary" }).all()) await expect(b).toBeEnabled();
  // The dialog fades in; a contrast check mid-fade reads blended colours.
  await waitForSettled(page.getByRole("dialog"));
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
