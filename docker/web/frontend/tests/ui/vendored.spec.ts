import { test, expect, type Page } from "@playwright/test";

// Stub the backend API so the UI renders deterministically (no Docker / network).
type Caps = { firmware: boolean; scanoss: boolean; docker: boolean };

async function stub(page: Page, caps: Caps, done?: unknown) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  if (done) {
    // EventSource stream: a single `done` event then close (the app treats a
    // close after `done` as success, see api.ts onerror/finished).
    await page.route("**/scan-stream**", (r) =>
      r.fulfill({
        contentType: "text/event-stream",
        body: `event: done\ndata: ${JSON.stringify(done)}\n\n`,
      }),
    );
  }
}

const VENDORED_DONE = {
  ok: true,
  mode: "SOURCE",
  id: "testapp_1.0",
  results: [{ name: "testapp_1.0_bom.json", size: 1234 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    suggestIdentifyVendored: true,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], vendored: true, matchConfidence: "100%" },
      { name: "<img src=x onerror=window.__xss=1>", version: "1.0", group: "", purl: "pkg:github/a/b", type: "library", licenses: [], vendored: true, matchConfidence: "88%" },
      { name: "express", version: "4.18.2", group: "", purl: "pkg:npm/express", type: "library", licenses: ["MIT"], vendored: false },
    ],
  },
};

async function fillAndRun(page: Page) {
  await page.fill("#project", "testapp");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("Vendored toggle is offered under scan options when scanoss is available", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: true, docker: true });
  await page.goto("/");
  // The redesigned New scan shows the vendored-ID toggle inline under the
  // "Advanced scan options" column for a source scan (the default current-dir),
  // off by default but visible — no separate disclosure to expand.
  const toggle = page.getByText("File-level identification (SCANOSS)");
  await expect(toggle).toBeVisible();
  await expect(page.locator("#scanossToken")).toHaveCount(0);
});

test("Vendored toggle hidden when scanoss is NOT available", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true });
  await page.goto("/");
  await expect(page.getByText("File-level identification (SCANOSS)")).toHaveCount(0);
});

test("result banner appears for the C/C++ suggestion", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: true, docker: true }, VENDORED_DONE);
  await page.goto("/");
  await fillAndRun(page);
  await expect(page.getByText(/is this C\/C\+\+ embedded source/i)).toBeVisible();
});

test("vendored badge + match confidence render; XSS name is inert", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: true, docker: true }, VENDORED_DONE);
  await page.goto("/");
  await fillAndRun(page);
  // Open the Components section (nav is now anchor links) where the
  // per-component table (and badge) lives.
  await page.getByRole("link", { name: /^Components/ }).first().click();

  // vendored badge present with a match-confidence tooltip.
  const badge = page.getByText("vendored", { exact: true }).first();
  await expect(badge).toBeVisible();
  await expect(badge).toHaveAttribute("title", /match 100%/i);

  // The hostile component name renders as inert text, not an executed <img>.
  await expect(page.getByText("<img src=x onerror=window.__xss=1>")).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { __xss?: number }).__xss)).toBeUndefined();
  expect(await page.locator("img[onerror]").count()).toBe(0);
});
