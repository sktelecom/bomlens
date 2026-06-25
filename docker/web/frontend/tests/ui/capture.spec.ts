import { test, type Page } from "@playwright/test";

// Screenshot capture for the docs (run on demand: `npm run capture:ui`, excluded
// from the normal `test:ui` run via the @capture tag). Renders the
// --identify-vendored UI states deterministically with stubbed API responses and
// writes PNGs into docs/images/, so the guide screenshots are reproducible.
const IMAGES = "../../../docs/images";

type Caps = { firmware: boolean; scanoss: boolean; docker: boolean };
async function stub(page: Page, caps: Caps, done?: unknown) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  if (done) {
    await page.route("**/scan-stream**", (r) =>
      r.fulfill({
        contentType: "text/event-stream",
        body: `event: done\ndata: ${JSON.stringify(done)}\n\n`,
      }),
    );
  }
}

const DONE = {
  ok: true,
  mode: "SOURCE",
  results: [{ name: "trelay_26.4.0_bom.json", size: 4096 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    suggestIdentifyVendored: true,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], vendored: true, matchConfidence: "100%" },
      { name: "liblfds", version: "6.1.1", group: "", purl: "pkg:github/liblfds/liblfds", type: "library", licenses: ["Unlicense"], vendored: true, matchConfidence: "100%" },
      { name: "libaes", version: "0.03", group: "", purl: "pkg:github/a/libaes", type: "library", licenses: [], vendored: true, matchConfidence: "92%" },
    ],
  },
};

// Disable fade-in/slide animations so element screenshots are crisp and stable.
async function killAnim(page: Page) {
  await page.addStyleTag({
    content: "*,*::before,*::after{animation:none!important;transition:none!important;opacity:1!important}",
  });
}

async function fillAndRun(page: Page) {
  await page.fill("#project", "trelay");
  await page.fill("#version", "26.4.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("@capture advanced toggle", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: true, docker: true });
  await page.goto("/");
  await killAnim(page);
  // The vendored-ID toggle now sits inline under "Advanced scan options" for a
  // source scan — capture the scan-options column that holds it.
  const toggle = page.getByText("File-level identification (SCANOSS)");
  await toggle.waitFor({ state: "visible" });
  // Screenshot the settings card (the last card on the New scan screen) that
  // holds the scan-options column with the vendored toggle.
  await page.locator(".rounded-2xl, [class*='rounded-']").last().screenshot({
    path: `${IMAGES}/web-ui-identify-vendored-en.png`,
  });
});

test("@capture result banner", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: true, docker: true }, DONE);
  await page.goto("/");
  await fillAndRun(page);
  // The banner is the amber rounded-md box that holds the suggestion text.
  const banner = page
    .locator("div.rounded-md")
    .filter({ hasText: "is this C/C++ embedded source" })
    .first();
  await banner.waitFor({ state: "visible" });
  await killAnim(page);
  await page.evaluate(() => window.scrollTo(0, 0));
  await banner.screenshot({ path: `${IMAGES}/web-ui-vendored-banner-en.png` });
});

test("@capture vendored badge in components table", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: true, docker: true }, DONE);
  await page.goto("/");
  await fillAndRun(page);
  await page.getByRole("link", { name: /^Components/ }).first().click();
  const table = page.locator("table").first();
  await table.waitFor({ state: "visible" });
  await killAnim(page);
  await table.screenshot({ path: `${IMAGES}/web-ui-vendored-badge-en.png` });
});
