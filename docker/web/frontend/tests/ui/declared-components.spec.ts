// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// Declared components (sbom-declared.cdx.json): the "Read sbom-declared.cdx.json"
// switch (off sends no_components=true, the CLI's --no-components), the failed
// scan when the file is refused, and the origin badge on declared components.

const SWITCH = "Read sbom-declared.cdx.json";

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

const REFUSED = {
  ok: false,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.refused.json", size: 100 }],
  sbom: null,
  security: null,
  conformance: null,
  errorMessage:
    "[ERROR] the declared components were refused (reasons above), so the SBOM is not complete. Fix the declaration file and scan again.",
  declarationRefused: {
    file: "demo_1.0_bom.refused.json",
    reasons: [
      "sbom-declared.cdx.json (at the scan target root): component 'fw-app' 1.0: bomlens:artifact out/fw-app.bin does not exist",
      "sbom-declared.cdx.json (at the scan target root): component 'hal': bomlens:origin is missing",
    ],
  },
};

async function stub(page: Page, done: object = DONE) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(done)}\n\n` }),
  );
}

async function openForm(page: Page, done?: object) {
  await stub(page, done);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
}

async function noComponentsSent(page: Page) {
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  return new URL((await scanReq).url()).searchParams.get("no_components");
}

test("a source scan reads the declaration file by default", async ({ page }) => {
  await openForm(page);
  await page.getByText("Result quality").click();
  await expect(page.getByRole("switch", { name: SWITCH })).toBeChecked();
  expect(await noComponentsSent(page)).toBe("");
});

test("turning it off sends no_components=true", async ({ page }) => {
  await openForm(page);
  await page.getByText("Result quality").click();
  await page.getByRole("switch", { name: SWITCH }).click();
  expect(await noComponentsSent(page)).toBe("true");
});

test("it is offered for a directory, which may be a Yocto build directory", async ({ page }) => {
  await openForm(page);
  await page.getByRole("button", { name: /Directory \/ rootfs/i }).click();
  await page.getByText("Result quality").click();
  await expect(page.getByRole("switch", { name: SWITCH })).toBeVisible();
});

test("it is not offered for an SBOM upload", async ({ page }) => {
  await openForm(page);
  await page.getByRole("button", { name: /SBOM upload/i }).click();
  const group = page.getByText("Result quality");
  if ((await group.count()) > 0) await group.click();
  await expect(page.getByRole("switch", { name: SWITCH })).toHaveCount(0);
});

test("a refused declaration names each reason and offers the refused SBOM", async ({ page }) => {
  await openForm(page, REFUSED);
  await page.getByRole("button", { name: /Run scan/i }).click();
  const card = page.getByTestId("declaration-refused");
  await expect(card).toBeVisible();
  await expect(card.getByText("The declaration file was refused")).toBeVisible();
  await expect(card.getByText(/bomlens:origin is missing/)).toBeVisible();
  await expect(card.getByText(/out\/fw-app\.bin does not exist/)).toBeVisible();
  const download = card.getByRole("link", { name: "Download" });
  await expect(download).toHaveAttribute("href", "/file?id=demo_1.0&name=demo_1.0_bom.refused.json");
  await expect(download).toHaveAttribute("download", "demo_1.0_bom.refused.json");
  await expect(card.getByRole("link", { name: "View the refused SBOM" })).toHaveAttribute(
    "href",
    "/file?id=demo_1.0&name=demo_1.0_bom.refused.json",
  );
  // The generic failure text gives way to this card.
  await expect(page.getByText("The scan didn't finish")).toHaveCount(0);
});

test("declared components carry an origin badge in the components table", async ({ page }) => {
  const componentList = [
    { name: "fw-app", version: "1.0", group: "", purl: "", type: "application", licenses: [], declaredOrigin: "first-party" },
    { name: "hal", version: "2.1", group: "", purl: "", type: "library", licenses: [], declaredOrigin: "third-party" },
    { name: "zlib", version: "1.3", group: "", purl: "pkg:generic/zlib@1.3", type: "library", licenses: [] },
  ];
  const done = { ...DONE, id: "decl_1.0", sbom: { components: 3, componentList } };
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "decl_1.0", project: "decl", version: "1.0", components: 3, maxSeverity: null, isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=decl_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }),
  );
  await page.goto("/#/scan/decl_1.0/components");
  await page.getByText("zlib").first().waitFor();
  const badges = page.getByTestId("declared-origin");
  await expect(badges).toHaveCount(2);
  await expect(badges.nth(0)).toHaveText("first-party");
  await expect(badges.nth(1)).toHaveText("third-party");
});

test("a declaration step that failed without reasons shows the scan's own error", async ({ page }) => {
  const failed = {
    ...REFUSED,
    errorMessage: "[ERROR] the declared components could not be added to the SBOM (see above).",
    declarationRefused: { file: "demo_1.0_bom.refused.json", reasons: [] },
  };
  await openForm(page, failed);
  await page.getByRole("button", { name: /Run scan/i }).click();
  const card = page.getByTestId("declaration-refused");
  await expect(card.getByText(/could not be added to the SBOM \(see above\)/)).toBeVisible();
  await expect(card.getByRole("link", { name: "Download" })).toBeVisible();
});

test("a refused run is listed and reopens on its refusal", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_1.0", project: "demo", version: "1.0", components: 0, maxSeverity: null, isAiScan: false, componentType: null, inputSource: "current-dir", generatedAt: 1700000000, refused: true },
    ]) }),
  );
  await page.route("**/scan?id=demo_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ ...REFUSED, mode: null }) }),
  );
  await page.goto("/#/");
  await expect(page.getByText("Declaration refused").first()).toBeVisible();
  await page.goto("/#/scan/demo_1.0");
  const card = page.getByTestId("declaration-refused");
  await expect(card.getByText(/bomlens:origin is missing/)).toBeVisible();
  await expect(card.getByRole("link", { name: "Download" })).toHaveAttribute(
    "href",
    "/file?id=demo_1.0&name=demo_1.0_bom.refused.json",
  );
});

test("a refused run opened by its link names the project and version in the header", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  // Not in the recent list: the header has only the scan's own settings to go on.
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan?id=acme_fw_2.3", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...REFUSED,
        mode: null,
        id: "acme_fw_2.3",
        scanConfig: { source: "current-dir", target: "", project: "acme_fw", version: "2.3" },
      }),
    }),
  );
  await page.goto("/#/scan/acme_fw_2.3");
  await expect(page.getByTestId("declaration-refused")).toBeVisible();
  await expect(page.locator("main h1")).toContainText("acme_fw");
  await expect(page.locator("main h1")).toContainText("2.3");
  await expect(page.locator("main h1")).not.toContainText("acme_fw_2.3");
});
