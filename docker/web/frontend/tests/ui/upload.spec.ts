// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

// Exercises the ZIP-upload flow end-to-end in the frontend: selecting the upload
// source, attaching a file, and running posts to /upload then /scan-stream. The
// other specs only use "current folder" (no upload), so the upload wiring — which
// is exactly where a regression shows as "upload failed: Failed to fetch" — was
// never covered. The backend is stubbed; server.py's own upload is covered by
// tests/test-web-ui.sh.
async function stub(page: Page, opts: { uploadOk: boolean }) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: true, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/upload**", (r) =>
    opts.uploadOk
      ? r.fulfill({ contentType: "application/json", body: JSON.stringify({ token: "tok123", filename: "demo.zip" }) })
      : r.fulfill({ status: 413, contentType: "application/json", body: JSON.stringify({ error: "file too large for zip" }) }),
  );
  const done = {
    ok: true, mode: "SOURCE",
    id: "demo_1.0",
    results: [{ name: "demo_1.0_bom.json", size: 100 }],
    security: null, conformance: null,
    sbom: { components: 1, suggestIdentifyVendored: false, componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], vendored: true, matchConfidence: "100%" },
    ] },
  };
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(done)}\n\n` }),
  );
}

async function selectZipAndAttach(page: Page) {
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("radio", { name: /ZIP upload/i }).click();
  await page.locator("#file").setInputFiles({
    name: "demo.zip",
    mimeType: "application/zip",
    buffer: Buffer.from("PK demo zip bytes"),
  });
}

test("ZIP upload flow uploads then renders the scan result", async ({ page }) => {
  await stub(page, { uploadOk: true });
  let uploaded = false;
  page.on("request", (req) => {
    if (req.url().includes("/upload")) uploaded = true;
  });
  await page.goto("/#/new");
  await selectZipAndAttach(page);
  await page.getByRole("button", { name: /Run scan/i }).click();

  // The upload endpoint was called, and the run produced results (no "Failed to fetch").
  await expect.poll(() => uploaded).toBe(true);
  await page.getByRole("link", { name: /^Components/ }).first().click();
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/Failed to fetch/i)).toHaveCount(0);
});

test("a failed upload surfaces an error instead of running the scan", async ({ page }) => {
  await stub(page, { uploadOk: false });
  await page.goto("/#/new");
  await selectZipAndAttach(page);
  await page.getByRole("button", { name: /Run scan/i }).click();
  // The user sees the humanized too-large message, not the server's raw
  // error text, and the scan does not start.
  await expect(page.getByText(/file is too large for the server/i)).toBeVisible();
  await expect(page.getByText("file too large for zip")).toHaveCount(0);
});

/**
 * The dropzone: a file arrives either by the picker or by being dropped, and
 * both land in the same native input so the form has one source of truth.
 *
 * Drops are synthesised here. Playwright cannot drive the OS file manager, so
 * what these cover is the page's own handling of a drop event carrying a file;
 * dragging from a real file manager is checked by hand.
 */
async function dropFile(page: Page, name: string, body: string) {
  await page.evaluate(
    ({ name, body }) => {
      const dt = new DataTransfer();
      dt.items.add(new File([body], name, { type: "application/zip" }));
      const zone = document.querySelector('[data-testid="dropzone"]');
      if (!zone) throw new Error("no dropzone on screen");
      zone.dispatchEvent(new DragEvent("dragover", { dataTransfer: dt, bubbles: true }));
      zone.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true }));
    },
    { name, body },
  );
}

test("a dropped file is attached and can be scanned", async ({ page }) => {
  await stub(page, { uploadOk: true });
  let uploaded = false;
  page.on("request", (req) => {
    if (req.url().includes("/upload")) uploaded = true;
  });
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("radio", { name: /ZIP upload/i }).click();

  await dropFile(page, "dropped.zip", "PK dropped bytes");

  // The zone becomes a summary of the file rather than an invitation to pick one.
  await expect(page.getByTestId("dropzone-name")).toHaveText("dropped.zip");
  await expect(page.locator("#file")).toHaveJSProperty("files.0.name", "dropped.zip");

  await page.getByTestId("run-scan").click();
  await expect.poll(() => uploaded).toBe(true);
  await expect(page.getByText(/Failed to fetch/i)).toHaveCount(0);
});

test("the chosen file can be taken back off", async ({ page }) => {
  await stub(page, { uploadOk: true });
  await page.goto("/#/new");
  await page.getByRole("radio", { name: /ZIP upload/i }).click();
  await dropFile(page, "wrong.zip", "PK wrong");
  await expect(page.getByTestId("dropzone-name")).toHaveText("wrong.zip");

  await page.getByRole("button", { name: /Remove the chosen file/i }).click();

  await expect(page.getByTestId("dropzone-name")).toHaveCount(0);
  await expect(page.locator("#file")).toHaveJSProperty("files.length", 0);
});

test("upload progress is reported while the file goes out", async ({ page }) => {
  await stub(page, { uploadOk: true });
  // Hold the response open so the in-flight state stays on screen, and drive
  // the upload's progress events directly: a stubbed route transfers nothing,
  // so the browser has no real progress to report.
  await page.route("**/upload**", async (r) => {
    await new Promise((res) => setTimeout(res, 1500));
    await r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ token: "tok123", filename: "demo.zip" }),
    });
  });
  await page.addInitScript(() => {
    const send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function (this: XMLHttpRequest, body?: unknown) {
      setTimeout(() => {
        this.upload.dispatchEvent(
          new ProgressEvent("progress", { lengthComputable: true, loaded: 42, total: 100 }),
        );
      }, 50);
      return send.call(this, body as Document | XMLHttpRequestBodyInit | null);
    };
  });

  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("radio", { name: /ZIP upload/i }).click();
  await dropFile(page, "demo.zip", "PK demo");
  await page.getByTestId("run-scan").click();

  await expect(page.getByText("Uploading… 42%")).toBeVisible();
  await expect(page.getByRole("progressbar", { name: "Upload progress" })).toHaveAttribute(
    "aria-valuenow",
    "42",
  );
});

test("the dropzone has no axe violations, before and after a file", async ({ page }) => {
  await stub(page, { uploadOk: true });
  await page.goto("/#/new");
  await page.getByRole("radio", { name: /ZIP upload/i }).click();
  await expect(page.getByTestId("dropzone")).toBeVisible();

  const empty = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(empty.violations).toEqual([]);

  await dropFile(page, "demo.zip", "PK demo");
  await expect(page.getByTestId("dropzone-name")).toBeVisible();
  const filled = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(filled.violations).toEqual([]);
});
