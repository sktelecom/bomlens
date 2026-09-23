// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * "Report a problem": after a scan ends, succeeded or failed, the diagnostics
 * summary is on screen in full and one button puts exactly that text on the
 * clipboard. Nothing is sent anywhere, so the test also asserts that no request
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
    // A healthy result stays folded, like the run log; a failed one opens it.
    if (ok) {
      await expect(page.getByTestId("report-text")).toHaveCount(0);
      expect(requests).not.toContain("/diagnostics");
      await page.getByText("Report a problem", { exact: true }).click();
    }

    const shown = page.getByTestId("report-text");
    await expect(shown).toBeVisible();
    const expected = SUMMARY.replace("OUTCOME", ok ? "succeeded" : "failed");
    await expect(shown).toHaveValue(expected);
    await expect(page.getByTestId("report-problem")).toContainText(/nothing is sent anywhere/i);

    const before = requests.length;
    await page.getByRole("button", { name: "Copy summary" }).click();
    await expect(page.getByText("Summary copied")).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(expected);
    // Pressing the button is local: no request follows it.
    expect(requests.length).toBe(before);
  });
}

test("the issue form opens away from the app", async ({ page }) => {
  await stub(page, false);
  await run(page);
  const link = page.getByRole("link", { name: "Open the issue form" });
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

test("a blocked clipboard says so and leaves the text to copy by hand", async ({ page }) => {
  await stub(page, false);
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
  });
  await run(page);
  await page.getByRole("button", { name: "Copy summary" }).click();
  await expect(page.getByText(/Copying was blocked here/)).toBeVisible();
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

test("the report panel has no accessibility violations", async ({ page }) => {
  await stub(page, false);
  await run(page);
  await expect(page.getByTestId("report-text")).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
