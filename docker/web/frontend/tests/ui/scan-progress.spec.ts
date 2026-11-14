// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { COMBOS, seedThemeLang, type Lang, type Theme } from "./visual";

/**
 * The scan progress and failure screens. A held scan stream is faked with an
 * EventSource the test drives (window.__es), so lines arrive when the test
 * says; the failures use the real stream wire format through page.route.
 */

async function stub(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/diagnostics**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ text: "BomLens diagnostics\nmode: SOURCE\noutcome: failed\n" }) }),
  );
}

/** Replace EventSource with one the test drives: window.__emit(type, data), window.__closed. */
async function fakeStream(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.__closed = false;
    class FakeES {
      listeners: Record<string, ((e: MessageEvent) => void)[]> = {};
      onerror: (() => void) | null = null;
      url: string;
      constructor(url: string) {
        this.url = url;
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
  page.evaluate(([t, d]) => (window as unknown as { __emit: (a: string, b: string) => void }).__emit(t, d), [type, JSON.stringify(data)] as const);

async function start(page: Page, opts: { project?: string } = {}) {
  await page.goto("/#/new");
  await page.fill("#project", opts.project ?? "demo-service");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
}

async function setup(page: Page, theme: Theme = "light", lang: Lang = "en") {
  await seedThemeLang(page, theme, lang);
  await stub(page);
}

test("a running scan shows the title, the project, the steps with their states and the open log", async ({ page }) => {
  await setup(page);
  await fakeStream(page);
  await start(page);
  await expect(page.getByRole("heading", { level: 1, name: "Scanning…" })).toBeVisible();
  await expect(page.getByRole("main").getByText("demo-service 1.0")).toBeVisible();
  const steps = page.getByTestId("run-steps");
  // Deep CVE matching was not asked for, so its step is not listed.
  await expect(steps.getByText("Deep CVE matching")).toHaveCount(0);
  await expect(steps.getByText("Generate SBOM")).toBeVisible();
  await emit(page, "log", "[1/2] cdxgen run");
  await emit(page, "log", "[normalize] ok");
  await expect(steps.getByText("Generate SBOM").locator("xpath=..")).toContainText("done");
  await expect(steps.getByText("Normalize").locator("xpath=..")).toContainText("in progress");
  await expect(steps.getByText("Report").locator("xpath=..")).toContainText("waiting");
  // 2 of 5 visible steps reached: (1 + 0.5) / 5.
  await expect(steps).toContainText("30%");
  await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "30");
  const log = page.getByRole("log", { name: "Run log" });
  await expect(log).toContainText("[1/2] cdxgen run");
  await expect(log).toBeVisible();
  await expect(page.getByTestId("run-log")).toContainText("2 lines");
  await expect(page.getByTestId("run-log")).toHaveJSProperty("open", true);
});

test("the log follows new lines at its end, stops when scrolled up, and resumes at the end", async ({ page }) => {
  await setup(page);
  await fakeStream(page);
  await start(page);
  for (let i = 0; i < 80; i++) await emit(page, "log", `line ${i}`);
  const log = page.getByRole("log", { name: "Run log" });
  await expect(log).toContainText("line 79");
  const metrics = () => log.evaluate((el) => ({ top: el.scrollTop, end: el.scrollHeight - el.clientHeight }));
  await expect.poll(async () => (await metrics()).top).toBeGreaterThan(0);
  expect((await metrics()).end - (await metrics()).top).toBeLessThan(2);
  // Read upward: new lines no longer move the box.
  await log.evaluate((el) => (el.scrollTop = 40));
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))));
  await emit(page, "log", "late line");
  await expect(log).toContainText("late line");
  expect((await metrics()).top).toBe(40);
  // Back to the end: following resumes.
  await log.evaluate((el) => (el.scrollTop = el.scrollHeight));
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))));
  await emit(page, "log", "another line");
  await expect(log).toContainText("another line");
  await expect.poll(async () => (await metrics()).end - (await metrics()).top).toBeLessThan(2);
});

test("copy log puts the shown lines on the clipboard", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await setup(page);
  await fakeStream(page);
  await start(page);
  await emit(page, "log", "first");
  await emit(page, "log", "second");
  await expect(page.getByText(/read it before you paste it/i)).toBeVisible();
  await page.getByRole("button", { name: "Copy log" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("first\nsecond");
  await expect(page.getByText("Log copied")).toBeVisible();
});

test("a blocked clipboard on the log copy says so", async ({ page }) => {
  await setup(page);
  await page.addInitScript(() => Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true }));
  await fakeStream(page);
  await start(page);
  await emit(page, "log", "first");
  await page.getByRole("button", { name: "Copy log" }).click();
  await expect(page.getByText(/Select the log above and copy it by hand/)).toBeVisible();
});

test("Cancel asks first; Keep scanning leaves the scan running", async ({ page }) => {
  await setup(page);
  await fakeStream(page);
  await start(page);
  await page.getByTestId("run-cancel").click();
  const dialog = page.getByRole("alertdialog", { name: "Cancel this scan?" });
  await expect(dialog).toContainText("demo-service 1.0 is still running");
  await expect(dialog.getByRole("button", { name: "Keep scanning" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  // Focus goes back to the button that opened the dialog.
  await expect(page.getByTestId("run-cancel")).toBeFocused();
  expect(await page.evaluate(() => (window as unknown as { __closed: boolean }).__closed)).toBe(false);
  await expect(page.getByRole("heading", { level: 1, name: "Scanning…" })).toBeVisible();
});

test("the cancel dialog goes away when the scan fails behind it", async ({ page }) => {
  await setup(page);
  await fakeStream(page);
  await start(page);
  await page.getByTestId("run-cancel").click();
  await expect(page.getByRole("alertdialog")).toBeVisible();
  await emit(page, "error", { detail: "Failed to launch scan: boom", key: null });
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  await expect(page.getByRole("alert")).toBeVisible();
});

test("confirming Cancel closes the stream, goes to New scan and says so", async ({ page }) => {
  await setup(page);
  await fakeStream(page);
  await start(page);
  await page.getByTestId("run-cancel").click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Cancel scan" }).click();
  await expect(page.getByRole("heading", { name: "What do you want to scan?" })).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { __closed: boolean }).__closed)).toBe(true);
  await expect(page.getByText("The scan was cancelled")).toBeVisible();
});

test("a finished scan replaces the run with the result", async ({ page }) => {
  await setup(page);
  await fakeStream(page);
  await start(page);
  await emit(page, "log", "[risk] done");
  await emit(page, "done", { ok: true, id: "demo_1.0", mode: "SOURCE", results: [], security: null, conformance: null, sbom: { components: 0, componentList: [] } });
  await expect(page.getByRole("heading", { level: 1, name: "Scanning…" })).toHaveCount(0);
  await expect(page).toHaveURL(/#\/scan\/demo_1\.0/);
  // The folded run log on the result says how the run ended, in words.
  await expect(page.getByTestId("run-log-status")).toHaveText("Finished");
});

test("a failed git clone leads with the cause and the fix, keeps the scanner message in the log, and offers Retry and New scan", async ({ page }) => {
  await setup(page);
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({
      contentType: "text/event-stream",
      body: `event: error\ndata: ${JSON.stringify({ detail: "git clone failed: repository not found\nfatal: Authentication failed", key: "run.errorGitNotFoundOrPrivate" })}\n\n`,
    }),
  );
  await start(page);
  const banner = page.getByRole("alert");
  await expect(banner).toContainText("The scan didn't finish");
  await expect(banner).toContainText("The repository was not found, or it is private.");
  await expect(banner).toContainText("enter a token");
  await expect(page.getByRole("heading", { level: 1, name: "Scan failed" })).toBeVisible();
  await expect(banner.getByRole("button", { name: "Retry" })).toBeVisible();
  await expect(banner.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "#/new");
  // The recognised cause keeps the log folded; the scanner's words are in it, once.
  const log = page.getByTestId("run-log");
  await expect(log).toHaveJSProperty("open", false);
  await log.getByText("Run log").click();
  await expect(log.getByRole("log")).toContainText("fatal: Authentication failed");
  await expect(page.getByTestId("run-server-message")).toHaveCount(0);
  // Report a problem opens by itself and shows the summary.
  await expect(page.getByTestId("report-text")).toHaveValue(/outcome: failed/);
  // No step had started, so none is marked failed, and no percentage reads as progress.
  const steps = page.getByTestId("run-steps");
  await expect(steps).not.toContainText("failed");
  await expect(steps.getByText("waiting")).toHaveCount(5);
  await expect(steps.locator(".bl-run-pct")).toHaveCount(0);
});

test("an unrecognised failure opens the run log and says to read it", async ({ page }) => {
  await setup(page);
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: error\ndata: ${JSON.stringify({ detail: "Failed to launch scan: boom", key: null })}\n\n` }),
  );
  await start(page);
  await expect(page.getByRole("alert")).toContainText("The scan stopped before it finished.");
  await expect(page.getByRole("alert")).toContainText("Open the run log for the cause");
  await expect(page.getByTestId("run-log")).toHaveJSProperty("open", true);
  // The message is in the log once, not again above it, and the box is as tall as its lines.
  await expect(page.getByTestId("run-server-message")).toHaveCount(0);
  await expect(page.getByTestId("run-log").getByText("Failed to launch scan: boom")).toHaveCount(1);
  expect((await page.getByRole("log").boundingBox())!.height).toBeLessThan(120);
});

test("a stream that drops without a done event is the failure screen, and exit code 126 names the tool and its runtime", async ({ page }) => {
  await setup(page);
  await fakeStream(page);
  await start(page);
  await emit(page, "log", "[1/2] cdxgen");
  await emit(page, "log", "node: cannot execute binary file");
  await emit(page, "log", "cdxgen exited with code 126");
  await page.evaluate(() => (window as unknown as { __es: { onerror: () => void } }).__es.onerror());
  await expect(page.getByRole("alert")).toContainText("The scan tool (cdxgen) could not be started (exit code 126).");
  await expect(page.getByRole("alert")).toContainText("cannot run Node.js on this machine");
  // The step it stopped on is the one marked failed, and no percentage is shown.
  await expect(page.getByTestId("run-steps").getByText("Generate SBOM").locator("xpath=..")).toContainText("failed");
  await expect(page.getByTestId("run-steps").locator(".bl-run-pct")).toHaveCount(0);
});

test("a scan with a token has no Retry, and says why", async ({ page }) => {
  await setup(page);
  await page.route("**/git-cred", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify({ credId: "c1" }) }));
  await page.route("**/scan-stream**", (r) => r.abort());
  await page.goto("/#/new");
  await page.getByRole("radio", { name: "GitHub URL" }).click();
  await page.fill("#target", "https://github.com/acme/private-service.git");
  await page.fill("#project", "private-service");
  await page.fill("#version", "main");
  await page.getByLabel("Token (private repo, optional)").fill("ghp_secret");
  await page.getByTestId("run-scan").click();
  const banner = page.getByRole("alert");
  await expect(banner).toBeVisible();
  await expect(banner.getByRole("button", { name: "Retry" })).toHaveCount(0);
  await expect(banner.getByRole("link", { name: "New scan" })).toBeVisible();
  await expect(banner).toContainText("Retry is not offered");
});

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`the running and failed screens fit at ${width}px (${lang}): long names and lines wrap, nothing is cut`, async ({ page }) => {
      await setup(page, "light", lang);
      await page.setViewportSize({ width, height: 800 });
      await fakeStream(page);
      await start(page, { project: "a-very-long-project-name-that-keeps-going-and-going-and-going-without-any-break-at-all" });
      await emit(page, "log", `x${"0123456789".repeat(40)}`);
      await expect(page.getByRole("log")).toContainText("x0123456789");
      const overflowX = () => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(await overflowX()).toBeLessThanOrEqual(0);
      const title = page.getByRole("main").getByText("a-very-long-project-name").first();
      expect(await title.evaluate((el) => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(0);
      const log = page.getByRole("log");
      expect(await log.evaluate((el) => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(0);
      await page.evaluate(() => (window as unknown as { __es: { onerror: () => void } }).__es.onerror());
      await expect(page.getByRole("alert")).toBeVisible();
      expect(await overflowX()).toBeLessThanOrEqual(0);
    });
  }
}

for (const { theme, lang } of COMBOS) {
  for (const state of ["running", "failed"] as const) {
    test(`the ${state} screen has no accessibility violations (${theme}, ${lang})`, async ({ page }) => {
      await setup(page, theme, lang);
      await fakeStream(page);
      await start(page);
      await emit(page, "log", "[1/2] cdxgen run");
      await emit(page, "log", "[normalize] ok");
      if (state === "failed") {
        await emit(page, "error", { detail: "git clone failed", key: "run.errorGitNetwork" });
        await expect(page.getByRole("alert")).toBeVisible();
        await expect(page.getByTestId("report-text")).toBeVisible();
      }
      await page.mouse.move(0, 0);
      const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(results.violations).toEqual([]);
    });
  }
}
