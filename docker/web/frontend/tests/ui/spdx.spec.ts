import { expect, test, type Page } from "@playwright/test";

/**
 * SPDX export surfaces. SPDX is not a scan option — the BOM already exists, so
 * the results screen converts it on demand. These cover the user-visible half of
 * that: (1) a scan that already has a `_bom.spdx.json` shows the SPDX chip and no
 * export button, (2) the chip addresses that artifact, (3) a scan without one
 * offers the export, which calls /spdx-export and turns into a real chip, and
 * (4) the offer is hidden where the server cannot convert.
 *
 * The backend is fully stubbed, mirroring rescan.spec.ts; the conversion itself
 * is covered by tests/test-web-ui.sh.
 */

const CONFIG = {
  source: "current-dir",
  target: "",
  project: "demo",
  version: "2.1",
  notice: true,
  security: false,
  deepLicense: false,
  identifyVendored: false,
  includeOsv: false,
};

const BOM = { name: "demo_2.1_bom.json", size: 100 };
const SPDX = { name: "demo_2.1_bom.spdx.json", size: 90 };

function done(results: { name: string; size: number }[]) {
  return {
    ok: true,
    mode: "SOURCE",
    id: "demo_2.1",
    results,
    security: null,
    conformance: null,
    sbom: {
      components: 1,
      componentList: [
        { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"] },
      ],
    },
    scanConfig: CONFIG,
  };
}

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "2.1" } },
  components: [{ "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o" }],
  dependencies: [],
};

async function openScan(
  page: Page,
  opts: { results?: { name: string; size: number }[]; spdxExport?: boolean } = {},
) {
  const results = opts.results ?? [BOM, SPDX];
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        firmware: false,
        scanoss: false,
        docker: true,
        spdxExport: opts.spdxExport ?? true,
      }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_2.1", project: "demo", version: "2.1", components: 1, maxSeverity: null, isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_2.1", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done(results)) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.goto("/?ui=next#/scan/demo_2.1");
  await page.getByRole("navigation").first().waitFor();
}

test("a scan with a .spdx.json artifact shows the SPDX chip in Artifacts", async ({ page }) => {
  await openScan(page);
  await page.getByRole("link", { name: /^Artifacts/ }).click();

  // The SBOM card carries per-format chips; the SPDX pseudo-extension gets
  // its own chip next to JSON (the accessible name carries the size too).
  await expect(page.getByRole("link", { name: /^SPDX\b/ }).first()).toBeVisible();
  // The file is already there, so the card must not also offer to create it.
  await expect(page.getByRole("button", { name: /Export as SPDX/ })).toHaveCount(0);
});

test("the SPDX chip addresses the .spdx.json artifact", async ({ page }) => {
  await openScan(page);
  await page.getByRole("link", { name: /^Artifacts/ }).click();

  const chip = page.getByRole("link", { name: /^SPDX\b/ }).first();
  // The chip must point at the SPDX artifact of THIS run — name and run id.
  const href = await chip.getAttribute("href");
  expect(href).toContain("demo_2.1_bom.spdx.json");
  expect(href).toContain("id=demo_2.1");
});

test("a scan without SPDX exports one on demand, and the chip appears", async ({ page }) => {
  await openScan(page, { results: [BOM] });

  let exportCalls = 0;
  await page.route("**/spdx-export**", (r) => {
    exportCalls += 1;
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: SPDX.name, results: [BOM, SPDX] }),
    });
  });

  await page.getByRole("link", { name: /^Artifacts/ }).click();
  await expect(page.getByRole("link", { name: /^SPDX\b/ })).toHaveCount(0);

  await page.getByRole("button", { name: /Export as SPDX/ }).click();

  // The converted file joins the card as an ordinary download chip, and the
  // now-redundant export button goes away.
  await expect(page.getByRole("link", { name: /^SPDX\b/ }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /Export as SPDX/ })).toHaveCount(0);
  expect(exportCalls).toBe(1);
});

test("the export offer is hidden when the server cannot convert", async ({ page }) => {
  await openScan(page, { results: [BOM], spdxExport: false });
  await page.getByRole("link", { name: /^Artifacts/ }).click();

  await expect(page.getByRole("link", { name: /^JSON\b/ }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /Export as SPDX/ })).toHaveCount(0);
});
