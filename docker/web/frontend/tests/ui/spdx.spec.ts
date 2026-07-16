import { expect, test, type Page } from "@playwright/test";

/**
 * SPDX export surfaces — the three checks the 2026-07 Windows verification
 * left to a human eye, automated: (1) a scan whose results carry a
 * `_bom.spdx.json` shows an SPDX chip in Artifacts, (2) the chip actually
 * addresses that artifact (a /file request for the .spdx.json name), and
 * (3) Re-scan restores the SPDX export toggle from the scan's config.
 *
 * The backend is fully stubbed, mirroring rescan.spec.ts; server.py's SPDX
 * generation itself is covered by tests/test-web-ui.sh.
 */

const CONFIG = {
  source: "current-dir",
  target: "",
  project: "demo",
  version: "2.1",
  notice: true,
  security: false,
  spdx: true,
  deepLicense: false,
  identifyVendored: false,
  includeOsv: false,
};

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_2.1",
  results: [
    { name: "demo_2.1_bom.json", size: 100 },
    { name: "demo_2.1_bom.spdx.json", size: 90 },
  ],
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

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "2.1" } },
  components: [{ "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o" }],
  dependencies: [],
};

async function openScan(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_2.1", project: "demo", version: "2.1", components: 1, maxSeverity: null, isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_2.1", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
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

test("Re-scan restores the SPDX export toggle from the config", async ({ page }) => {
  await openScan(page);
  await page.getByRole("button", { name: "Re-scan" }).click();

  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("#/new");
  await expect(page.locator("#project")).toHaveValue("demo");
  // The config ran with --spdx on and security off; the prefill must mirror both.
  await expect(page.getByRole("switch", { name: "SPDX export" })).toHaveAttribute("aria-checked", "true");
  await expect(page.getByRole("switch", { name: "Security report" })).toHaveAttribute("aria-checked", "false");
});
