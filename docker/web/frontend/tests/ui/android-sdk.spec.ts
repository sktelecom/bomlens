// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

// A scan of an Android project needs the Android SDK image. When it is missing
// the server stops the scan with a structured error; the app asks for Google's
// terms and builds the image, instead of showing a failed scan.

const TERMS = "https://developer.android.com/studio/terms";

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

const sse = (events: Array<[string, unknown]>) =>
  events.map(([e, d]) => `event: ${e}\ndata: ${JSON.stringify(d)}\n\n`).join("");

function missing(extra: Record<string, unknown> = {}) {
  return sse([
    [
      "error",
      {
        detail: "The Android SDK image bomlens-android-sdk34 is not installed.",
        key: "androidSdkImageMissing",
        code: "ANDROID_SDK_IMAGE_MISSING",
        consentRequired: true,
        api: 34,
        image: "bomlens-android-sdk34",
        termsUrl: TERMS,
        buildAvailable: true,
        ...extra,
      },
    ],
    ["done", { ok: false, id: "demo_1.0", results: [], sbom: null, security: null, conformance: null, code: "ANDROID_SDK_IMAGE_MISSING" }],
  ]);
}

/** The first scan is refused for the missing image; scans after the build succeed. */
async function setup(
  page: Page,
  opts: { first?: string; capabilities?: Record<string, unknown>; build?: string; consentOk?: boolean } = {},
) {
  const calls = { scans: 0, consent: 0, build: 0, cancel: 0, consentBody: "" };
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, androidSdkBuild: true, ...opts.capabilities }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) => {
    calls.scans += 1;
    r.fulfill({
      contentType: "text/event-stream",
      body: calls.scans === 1 ? (opts.first ?? missing()) : sse([["done", DONE]]),
    });
  });
  await page.route("**/android-sdk-status**", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        api: 34,
        image: "bomlens-android-sdk34",
        present: false,
        termsAccepted: true,
        termsUrl: TERMS,
        buildAvailable: true,
        building: false,
      }),
    }),
  );
  await page.route("**/android-sdk-consent", (r) => {
    calls.consent += 1;
    calls.consentBody = r.request().postData() ?? "";
    if (opts.consentOk === false) return r.fulfill({ status: 500, body: "{}" });
    return r.fulfill({ contentType: "application/json", body: JSON.stringify({ termsAccepted: true, termsUrl: TERMS }) });
  });
  await page.route("**/android-sdk-build-stream**", (r) => {
    calls.build += 1;
    r.fulfill({
      contentType: "text/event-stream",
      body:
        opts.build ??
        sse([
          ["log", "#3 [2/5] RUN sdkmanager"],
          ["progress", { phase: "build", step: 2, steps: 5 }],
          ["done", { ok: true, api: 34, image: "bomlens-android-sdk34" }],
        ]),
    });
  });
  await page.route("**/android-sdk-build-cancel**", (r) => {
    calls.cancel += 1;
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ api: 34, cancelling: true }) });
  });
  await page.goto("/#/new");
  await page.getByRole("radio", { name: "GitHub URL" }).click();
  await page.fill("#target", "https://github.com/acme/demo.git");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
  return calls;
}

test("accepting the terms records consent, builds, and scans again", async ({ page }) => {
  const calls = await setup(page);
  const dialog = page.getByTestId("android-sdk-dialog");
  await expect(dialog).toBeVisible();
  await expect(page.getByTestId("run-failed")).toHaveCount(0);
  await expect(page.getByRole("link", { name: /Android SDK terms/ })).toHaveAttribute("href", TERMS);
  await expect(page.getByTestId("android-sdk-skip-note")).toContainText("incomplete");
  await waitForSettled(page.getByRole("dialog"));
  const axe = await new AxeBuilder({ page }).include('[role="dialog"]').analyze();
  expect(axe.violations).toEqual([]);

  await page.getByRole("button", { name: "Accept the terms and prepare now" }).click();
  await expect(dialog).toHaveCount(0);
  expect(JSON.parse(calls.consentBody)).toEqual({ accept: true, termsUrl: TERMS });
  expect(calls.build).toBe(1);
  await expect.poll(() => calls.scans).toBe(2);
});

test("skipping ends the scan with an explanation and builds nothing", async ({ page }) => {
  const calls = await setup(page);
  await page.getByRole("button", { name: "Skip for now" }).click();
  await expect(page.getByTestId("android-sdk-dialog")).toHaveCount(0);
  await expect(page.getByText(/did not run because the Android SDK image is not installed/).first()).toBeVisible();
  expect(calls.consent).toBe(0);
  expect(calls.build).toBe(0);
  expect(calls.scans).toBe(1);
});

test("terms already on file start the build without asking", async ({ page }) => {
  const calls = await setup(page, { first: missing({ consentRequired: false }) });
  await expect.poll(() => calls.build).toBe(1);
  expect(calls.consent).toBe(0);
  await expect.poll(() => calls.scans).toBe(2);
});

test("a failed build names the reason and shows the detail", async ({ page }) => {
  await setup(page, {
    build: sse([
      ["log", "ERROR: no space left on device"],
      ["done", { ok: false, api: 34, image: "bomlens-android-sdk34", reason: "disk", detail: "no space left on device" }],
    ]),
  });
  await page.getByRole("button", { name: "Accept the terms and prepare now" }).click();
  const failed = page.getByTestId("android-sdk-failed");
  await expect(failed).toContainText("ran out of disk space");
  await expect(page.getByTestId("android-sdk-detail")).toHaveText("no space left on device");
  await expect(page.getByTestId("android-sdk-command")).toContainText("ANDROID_API=34");
  await expect(page.getByRole("button", { name: "Try again" })).toBeVisible();
});

test("a server that cannot build shows the command instead of a build button", async ({ page }) => {
  const calls = await setup(page, { first: missing({ buildAvailable: false }) });
  await expect(page.getByTestId("android-sdk-manual")).toBeVisible();
  await expect(page.getByTestId("android-sdk-command")).toHaveText(
    "docker build --build-arg ANDROID_API=34 -t bomlens-android-sdk34 docker/android",
  );
  await expect(page.getByRole("button", { name: "Accept the terms and prepare now" })).toHaveCount(0);
  expect(calls.build).toBe(0);
});

test("capabilities without androidSdkBuild also hide the build button", async ({ page }) => {
  await setup(page, { capabilities: { androidSdkBuild: false } });
  await expect(page.getByTestId("android-sdk-manual")).toBeVisible();
  await expect(page.getByRole("button", { name: "Accept the terms and prepare now" })).toHaveCount(0);
});

test("a consent that cannot be saved keeps the dialog open", async ({ page }) => {
  const calls = await setup(page, { consentOk: false });
  await page.getByRole("button", { name: "Accept the terms and prepare now" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "could not be saved" })).toBeVisible();
  expect(calls.build).toBe(0);
});
