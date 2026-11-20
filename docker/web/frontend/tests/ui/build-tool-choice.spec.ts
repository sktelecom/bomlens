// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// The Maven or Gradle choice shows only when /project-info reports both a
// pom.xml and a build.gradle(.kts) in the folder, and goes out as build_tool.

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

async function stub(page: Page, buildTools: { maven: boolean; gradle: boolean }) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/project-info**", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        version: "",
        versionFrom: "",
        hasManifest: true,
        subProjects: [],
        buildTools,
      }),
    }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
}

async function openForm(page: Page) {
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByText("Result quality").click();
}

test("the choice is offered when both build files exist and Maven is sent", async ({ page }) => {
  await stub(page, { maven: true, gradle: true });
  await openForm(page);
  const choice = page.getByLabel("Build tool for Maven and Gradle files");
  await expect(choice).toBeVisible();
  await expect(choice).toHaveValue("auto");
  await choice.selectOption("maven");
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  expect(new URL((await scanReq).url()).searchParams.get("build_tool")).toBe("maven");
});

test("the choice is hidden and auto is sent when only one build file exists", async ({ page }) => {
  await stub(page, { maven: true, gradle: false });
  await openForm(page);
  await expect(page.getByLabel("Build tool for Maven and Gradle files")).toHaveCount(0);
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  expect(new URL((await scanReq).url()).searchParams.get("build_tool")).toBe("auto");
});

test("a chosen folder scanned deep gets the build-tool choice and the advisory too", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        firmware: false,
        scanoss: false,
        docker: true,
        hostDir: "/Users/dev/sbom-output",
        outputHostDir: "/Users/dev/sbom-output",
        launchIsOutput: true,
        scanRoots: [{ path: "/scan-targets/acme", hostPath: "/Users/dev/acme" }],
      }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/project-info**", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        version: "",
        versionFrom: "",
        hasManifest: true,
        subProjects: [],
        buildTools: { maven: true, gradle: true },
        engineMemoryLowGb: 3,
        otherScanRunning: true,
      }),
    }),
  );
  await page.goto("/#/new");
  await expect(page.getByTestId("source-rootfs-dir")).toHaveAttribute("aria-checked", "true");
  await expect(page.getByTestId("build-advisory")).toContainText("Another scan is running now");
  await page.getByText("Result quality").click();
  await expect(page.getByLabel("Build tool for Maven and Gradle files")).toBeVisible();
});
