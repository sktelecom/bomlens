// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { seedThemeLang } from "./visual";

/**
 * Following a running scan from a reloaded tab or another one. The stream is an
 * EventSource the test drives (window.__emit), installed on every page load, so
 * a reload gets a fresh one and the test can see which URL it opened.
 */

async function stub(page: Page, running: object[] = []) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/running-scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(running) }),
  );
}

async function fakeStream(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("bomlens.noUnloadGuard", "1");
    const w = window as unknown as Record<string, unknown>;
    w.__closed = false;
    class FakeES {
      listeners: Record<string, ((e: MessageEvent) => void)[]> = {};
      onerror: (() => void) | null = null;
      constructor(url: string) {
        w.__es = this;
        w.__url = url;
      }
      addEventListener(type: string, fn: (e: MessageEvent) => void) {
        (this.listeners[type] ||= []).push(fn);
      }
      close() {
        w.__closed = true;
      }
    }
    w.EventSource = FakeES;
    w.__emit = (type: string, data: string) => {
      const es = w.__es as FakeES;
      for (const fn of es.listeners[type] ?? []) fn({ data } as MessageEvent);
    };
  });
}

const emit = (page: Page, type: string, data: unknown) =>
  page.evaluate(
    ([t, d]) => (window as unknown as { __emit: (a: string, b: string) => void }).__emit(t, d),
    [type, JSON.stringify(data)] as const,
  );

const streamUrl = (page: Page) =>
  page.waitForFunction(() => (window as unknown as { __url?: string }).__url).then((h) => h.jsonValue());

const started = (id: string, project: string, attached: boolean, droppedLines = 0) => ({
  id,
  project,
  version: "1.0",
  startedAt: 1700000000,
  attached,
  droppedLines,
  deepCve: false,
});

const DONE = {
  ok: true,
  id: "demo-service_1.0",
  mode: "SOURCE",
  results: [],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

test("a reloaded tab joins its running scan: the log so far, then new lines, then the result", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await fakeStream(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo-service");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
  expect(await streamUrl(page)).toContain("/scan-stream?");
  await emit(page, "started", started("demo-service_1.0", "demo-service", false));
  await emit(page, "log", "[stub] first line");
  // The address names the running scan, so a reload knows what to join.
  await expect(page).toHaveURL(/#\/running\/demo-service_1\.0$/);

  await page.reload();
  expect(await streamUrl(page)).toBe("/scan-attach?id=demo-service_1.0");
  await emit(page, "started", started("demo-service_1.0", "demo-service", true, 2));
  await emit(page, "log", "[stub] first line");
  await emit(page, "log", "[stub] a new line");
  await expect(page.getByRole("heading", { level: 1, name: "Scanning…" })).toBeVisible();
  await expect(page.getByRole("main").getByText("demo-service 1.0").first()).toBeVisible();
  const log = page.getByTestId("run-log");
  await expect(log).toContainText("(2 earlier log lines are not shown)");
  await expect(log).toContainText("[stub] first line");
  await expect(log).toContainText("[stub] a new line");

  await emit(page, "done", DONE);
  await expect(page).toHaveURL(/#\/scan\/demo-service_1\.0$/);
  await expect(page.getByRole("heading", { level: 1, name: "Scanning…" })).toHaveCount(0);
});

test("another tab opens a running scan from the notice and cancels it by id", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, [{ id: "acme_1.0", project: "acme", version: "1.0", startedAt: 1700000000 }]);
  const cancels: string[] = [];
  await page.route("**/scan-cancel**", (r) => {
    cancels.push(r.request().method() + " " + new URL(r.request().url()).search);
    return r.fulfill({ contentType: "application/json", body: JSON.stringify({ cancelling: true }) });
  });
  await fakeStream(page);
  await page.goto("/#/new");
  const notice = page.getByTestId("running-scans");
  await expect(notice).toContainText("A scan is running");
  await notice.getByRole("link", { name: "acme 1.0" }).click();
  await expect(page).toHaveURL(/#\/running\/acme_1\.0$/);
  expect(await streamUrl(page)).toBe("/scan-attach?id=acme_1.0");
  await emit(page, "started", started("acme_1.0", "acme", true));
  await emit(page, "log", "[stub] tick 3");
  await expect(page.getByRole("main").getByText("acme 1.0").first()).toBeVisible();

  // The same confirm dialog as in the tab that started it.
  await page.getByTestId("run-cancel").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("acme 1.0 is still running");
  await dialog.getByRole("button", { name: "Cancel scan" }).click();
  await expect(page.getByText("The scan was cancelled", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What do you want to scan?" })).toBeVisible();
  await expect(page).toHaveURL(/#\/new$/);
  expect(cancels).toEqual(["POST ?id=acme_1.0"]);
  expect(await page.evaluate(() => (window as unknown as { __closed: boolean }).__closed)).toBe(true);
});

test("a scan cancelled in another tab returns a following tab to New scan and says so", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await fakeStream(page);
  await page.goto("/#/running/acme_1.0");
  expect(await streamUrl(page)).toBe("/scan-attach?id=acme_1.0");
  await emit(page, "started", started("acme_1.0", "acme", true));
  await emit(page, "done", { ok: false, id: "acme_1.0", cancelled: true, results: [], sbom: null, security: null, conformance: null });
  await expect(page.getByText("The scan was cancelled in another tab")).toBeVisible();
  await expect(page.getByRole("heading", { name: "What do you want to scan?" })).toBeVisible();
  await expect(page).toHaveURL(/#\/new$/);
});

for (const via of ["this tab", "another tab"] as const) {
  test(`the running-scans notice goes once a scan cancelled in ${via} has stopped, without a reload`, async ({ page }) => {
    await seedThemeLang(page, "light", "en");
    await stub(page);
    // The server lists the scan for a moment after the cancel, while it stops.
    let listed = true;
    await page.route("**/running-scans", (r) =>
      r.fulfill({
        contentType: "application/json",
        body: JSON.stringify(listed ? [{ id: "acme_1.0", project: "acme", version: "1.0", startedAt: 1700000000 }] : []),
      }),
    );
    await page.route("**/scan-cancel**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify({ cancelling: true }) }),
    );
    await fakeStream(page);
    await page.goto("/#/running/acme_1.0");
    expect(await streamUrl(page)).toBe("/scan-attach?id=acme_1.0");
    await emit(page, "started", started("acme_1.0", "acme", true));
    if (via === "this tab") {
      await page.getByTestId("run-cancel").click();
      await page.getByRole("alertdialog").getByRole("button", { name: "Cancel scan" }).click();
    } else {
      await emit(page, "done", { ok: false, id: "acme_1.0", cancelled: true, results: [], sbom: null, security: null, conformance: null });
    }
    await expect(page.getByRole("heading", { name: "What do you want to scan?" })).toBeVisible();
    const notice = page.getByTestId("running-scans");
    await expect(notice).toContainText("acme 1.0");
    listed = false;
    // Well inside the usual five-second interval: the tab asks again sooner.
    await expect(notice).toHaveCount(0, { timeout: 2500 });
  });
}

test("the running-scans notice asks again when the tab is shown", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  let listed = true;
  await page.route("**/running-scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify(listed ? [{ id: "acme_1.0", project: "acme", version: "1.0", startedAt: 1700000000 }] : []),
    }),
  );
  await page.goto("/#/new");
  const notice = page.getByTestId("running-scans");
  await expect(notice).toContainText("acme 1.0");
  listed = false;
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await expect(notice).toHaveCount(0, { timeout: 2500 });
});

test("a scan that is no longer running opens as a past scan instead", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.route("**/scan?id=**", (r) => r.fulfill({ status: 404, contentType: "application/json", body: "{}" }));
  await fakeStream(page);
  await page.goto("/#/running/gone_1.0");
  expect(await streamUrl(page)).toBe("/scan-attach?id=gone_1.0");
  // The server's 404 reaches an EventSource as an error before any event.
  await page.evaluate(() => (window as unknown as { __es: { onerror: () => void } }).__es.onerror());
  await expect(page.getByText("Scan “gone_1.0” was not found")).toBeVisible();
  await expect(page).toHaveURL(/#\/$/);
});

for (const theme of ["light", "dark"] as const) {
  test(`the running-scans notice with its links has no accessibility violations (${theme})`, async ({ page }) => {
    await seedThemeLang(page, theme, "en");
    await stub(page, [
      { id: "acme_1.0", project: "acme", version: "1.0", startedAt: 1700000000 },
      { id: "beta_2.0", project: "beta", version: "2.0", startedAt: 1700000001 },
    ]);
    await page.goto("/#/new");
    const notice = page.getByTestId("running-scans");
    await expect(notice).toContainText("2 scans are running");
    await expect(notice.getByRole("link")).toHaveCount(2);
    await page.mouse.move(0, 0);
    const results = await new AxeBuilder({ page })
      .include('[data-testid="running-scans"]')
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  });
}
