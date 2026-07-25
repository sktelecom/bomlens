import { test, expect, type Page } from "@playwright/test";

/**
 * Deep CVE matching (--deep-cve) is an opt-in toggle offered only for an
 * uploaded SBOM ("SBOM upload") and only when this environment can run it
 * (capabilities.deepCve). It matches components against NVD-only advisories,
 * catching vulnerabilities in older Maven libraries other sources miss. The
 * backend is stubbed; server.py's own deep-cve wiring is covered elsewhere.
 */

type Caps = {
  firmware: boolean;
  scanoss: boolean;
  docker: boolean;
  deepCve?: boolean;
  deepCveSibling?: boolean;
};

const DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: {
    components: 1,
    componentList: [
      { name: "log4j-core", version: "2.14.1", group: "org.apache.logging.log4j", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", type: "library", licenses: ["Apache-2.0"] },
    ],
  },
};

async function stub(page: Page, caps: Caps) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/upload**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ token: "tok123", filename: "demo.json" }) }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
}

async function selectSbomUpload(page: Page) {
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /SBOM upload/i }).click();
  await page.locator("#file").setInputFiles({
    name: "demo.json",
    mimeType: "application/json",
    buffer: Buffer.from('{"bomFormat":"CycloneDX"}'),
  });
}

test("deep CVE toggle is offered for an SBOM upload when the capability is present", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true, deepCve: true });
  await page.goto("/#/new");
  await selectSbomUpload(page);
  // Advanced scan options is a collapsed disclosure; expand to reveal the toggle.
  await page.getByText("Advanced scan options").click();
  await expect(page.getByText("Deep CVE matching (maven, NVD)")).toBeVisible();
});

test("deep CVE toggle is hidden when the capability is absent", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true, deepCve: false });
  await page.goto("/#/new");
  await selectSbomUpload(page);
  // The whole advanced-options disclosure has nothing to show for this source,
  // so neither the disclosure nor the toggle appears.
  await expect(page.getByText("Deep CVE matching (maven, NVD)")).toHaveCount(0);
});

test("deep CVE toggle does not appear for a non-SBOM source", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: true, docker: true, deepCve: true });
  await page.goto("/#/new");
  // Default source is the current folder; open its advanced options.
  await page.locator("#project").waitFor();
  await page.getByText("Advanced scan options").click();
  await expect(page.getByText("Deep CVE matching (maven, NVD)")).toHaveCount(0);
});

test("running with deep CVE on sends deep_cve=true on the scan request", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true, deepCve: true });
  await page.goto("/#/new");
  await selectSbomUpload(page);
  await page.getByText("Advanced scan options").click();
  await page.getByRole("switch", { name: "Deep CVE matching (maven, NVD)" }).click();

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("deep_cve")).toBe("true");
});

test("running without deep CVE sends deep_cve=false", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true, deepCve: true });
  await page.goto("/#/new");
  await selectSbomUpload(page);

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("deep_cve")).toBe("false");
});
