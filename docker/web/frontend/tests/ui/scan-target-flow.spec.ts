// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

/**
 * Scan target flow and the list's lifecycle marks: the folder input is the
 * default when the launch folder is the results folder, the version comes from
 * the folder's manifest, a folder that would merge projects and a same-name
 * scan are asked about before the scan starts, a cancelled scan stays in the
 * list, and the first-run screen waits for the list. The backend is stubbed.
 */

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

const APP_CAPS = {
  firmware: false,
  scanoss: false,
  docker: true,
  hostDir: "/Users/dev/sbom-output",
  outputHostDir: "/Users/dev/sbom-output",
  launchIsOutput: true,
  scanRoots: [{ path: "/scan-targets/acme", hostPath: "/Users/dev/acme" }],
};

async function stub(page: Page, caps: object, extra: { info?: object; exists?: boolean } = {}) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/project-info**", (r) =>
    extra.info
      ? r.fulfill({ contentType: "application/json", body: JSON.stringify(extra.info) })
      : r.fulfill({ status: 404, body: "{}" }),
  );
  await page.route("**/scan-exists**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ exists: extra.exists === true }) }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
}

test.beforeEach(async ({ page }) => {
  // The tab-close prompt would stop a test that leaves a running scan.
  await page.addInitScript(() => {
    (window as unknown as { __BOMLENS_NO_UNLOAD_GUARD__: boolean }).__BOMLENS_NO_UNLOAD_GUARD__ = true;
    window.localStorage.removeItem("bomlens.knownScanRoots");
    window.localStorage.removeItem("bomlens.lastScanRoot");
  });
});

test("a launch folder that is the results folder is not the default or a name", async ({ page }) => {
  await stub(page, APP_CAPS, { info: { version: "2.4.1", versionFrom: "pom.xml", hasManifest: true, subProjects: [] } });
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  // The folder input is on, with the added folder chosen; nothing is named
  // after the results folder.
  await expect(page.getByTestId("source-rootfs-dir")).toHaveAttribute("aria-checked", "true");
  await expect(page.locator("#scanRoot")).toHaveValue("/scan-targets/acme");
  await expect(page.locator("#project")).toHaveValue("acme");
  // The version is the one the folder's pom.xml states.
  await expect(page.locator("#version")).toHaveValue("2.4.1");
  // The launch folder is not offered as a place to scan.
  await expect(page.locator("#scanRoot option")).toHaveCount(1);
  await page.getByTestId("source-current-dir").click();
  await expect(page.getByTestId("current-dir-is-output")).toBeVisible();
  await expect(page.locator("#project")).toHaveValue("");
});

// The Windows launcher with a folder to scan: the list holds only that folder.
const ONE_ROOT_CAPS = {
  firmware: false,
  scanoss: false,
  docker: true,
  hostDir: "C:\\Users\\dev\\sbom-output",
  outputHostDir: "C:\\Users\\dev\\sbom-output",
  launchIsOutput: true,
  scanRoots: [{ path: "/scan-targets/mounted", hostPath: "C:\\Users\\dev\\r2" }],
};

async function runFolderScan(page: Page, sub: string) {
  await stub(page, ONE_ROOT_CAPS);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  // Leaving the folder input and coming back starts it over.
  await page.getByTestId("source-current-dir").click();
  await page.getByTestId("source-rootfs-dir").click();
  await expect(page.locator("#scanRoot option")).toHaveCount(1);
  await expect(page.locator("#scanRoot")).toHaveValue("/scan-targets/mounted");
  await page.fill("#target", sub);
  await page.fill("#project", "r2");
  await page.fill("#version", "1.0");
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  return new URL((await scanReq).url()).searchParams;
}

test("a single added folder on screen is the folder the scan is sent", async ({ page }) => {
  const params = await runFolderScan(page, "rust");
  expect(params.get("source")).toBe("scan-target-src");
  expect(params.get("target")).toBe("/scan-targets/mounted/rust");
});

test("\".\" under an added folder scans that folder", async ({ page }) => {
  const params = await runFolderScan(page, ".");
  expect(params.get("source")).toBe("scan-target-src");
  expect(params.get("target")).toBe("/scan-targets/mounted");
});

test("the advanced note for OS root filesystems is folded away", async ({ page }) => {
  await stub(page, APP_CAPS);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  const adv = page.getByTestId("rootfs-advanced");
  await expect(adv).toBeVisible();
  await expect(adv).not.toHaveAttribute("open", "");
});

test("a folder that would merge projects asks first, and Continue starts the scan", async ({ page }) => {
  await stub(page, APP_CAPS, { info: { version: "", versionFrom: "", hasManifest: false, subProjects: ["api", "web"] } });
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByRole("button", { name: /Run scan/i }).click();
  const merged = page.getByTestId("confirm-merged");
  await expect(merged).toContainText("2 projects (api, web)");
  await expect(page.getByTestId("confirm-keep")).toHaveCount(0);
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByTestId("confirm-go").click();
  expect(new URL((await scanReq).url()).searchParams.get("timestamp")).toBe("");
});

test("Cancel in the question starts nothing", async ({ page }) => {
  await stub(page, APP_CAPS, { info: { version: "", versionFrom: "", hasManifest: false, subProjects: ["api", "web"] } });
  let started = false;
  page.on("request", (req) => {
    if (req.url().includes("/scan-stream")) started = true;
  });
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByRole("button", { name: /Run scan/i }).click();
  await expect(page.getByTestId("confirm-merged")).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByTestId("confirm-merged")).toHaveCount(0);
  expect(started).toBe(false);
});

test("a finished scan of the same name asks to overwrite or keep both", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, { exists: true });
  await page.goto("/#/new");
  await page.getByRole("radio", { name: "GitHub URL" }).click();
  await page.fill("#target", "https://github.com/acme/demo.git");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
  await expect(page.getByTestId("confirm-overwrite")).toContainText("demo 1.0");
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByTestId("confirm-keep").click();
  expect(new URL((await scanReq).url()).searchParams.get("timestamp")).toBe("true");
});

test("the first-run screen waits for the list instead of flashing before it", async ({ page }) => {
  await page.route("**/capabilities", (r) => r.fulfill({ contentType: "application/json", body: "{}" }));
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  let release: () => void = () => {};
  const gate = new Promise<void>((res) => (release = res));
  await page.route("**/scans", async (r) => {
    await gate;
    await r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        { id: "a_1", project: "a", version: "1", components: 3, maxSeverity: null, isAiScan: false, componentType: "application", inputSource: "current-dir", generatedAt: 1700000000 },
      ]),
    });
  });
  await page.goto("/#/");
  await expect(page.getByTestId("recent-loading")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Generate your first SBOM" })).toHaveCount(0);
  release();
  await expect(page.getByRole("link", { name: /a @1/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Generate your first SBOM" })).toHaveCount(0);
});

test("a cancelled scan is listed as cancelled, is not a link, and the list says where results stay", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ outputHostDir: "/Users/dev/sbom-output", hostDir: "/p" }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        { id: "gone_2.0", project: "gone", version: "2.0", components: 0, maxSeverity: null, isAiScan: false, componentType: null, inputSource: "scan-target-src", generatedAt: 1700000100, cancelled: true },
        { id: "ok_1.0", project: "ok", version: "1.0", components: 5, maxSeverity: null, isAiScan: false, componentType: "application", inputSource: "current-dir", generatedAt: 1700000000 },
      ]),
    }),
  );
  await page.goto("/#/");
  await expect(page.getByTestId("scan-cancelled")).toHaveText("Cancelled");
  await expect(page.getByTestId("scan-cancelled-name")).toContainText("gone");
  await expect(page.getByRole("link", { name: /gone/ })).toHaveCount(0);
  await expect(page.getByRole("link", { name: /ok @1.0/ })).toBeVisible();
  await expect(page.getByTestId("recent-output-dir")).toHaveText("/Users/dev/sbom-output");
  await expect(page.getByTestId("recent-kept-note")).toContainText("after you remove or reinstall the app");
});
