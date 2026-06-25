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
  await page.getByRole("button", { name: /ZIP upload/i }).click();
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
  // The upload error is shown to the user (uploadFailed message), scan not started.
  await expect(page.getByText(/file too large/i)).toBeVisible();
});
