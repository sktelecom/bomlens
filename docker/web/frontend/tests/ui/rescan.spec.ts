import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * "Re-scan" flow: a finished scan whose `done` payload carries `scanConfig`
 * gets a top-bar Re-scan button that opens the New scan form prefilled with the
 * same target and toggles (the user then adjusts and runs it). Scans without a
 * config (older history) hide the button. Credentials/files are never seeded.
 *
 * The backend is fully stubbed: a past scan is loaded by deep link, with and
 * without a `scanConfig`, so the button condition and the prefill are exercised
 * without a real server.
 */

const CONFIG = {
  source: "git-url",
  target: "https://github.com/acme/demo",
  project: "demo",
  version: "2.1",
  notice: true,
  security: false,
  deepLicense: true,
  identifyVendored: false,
  includeOsv: false,
};

// A finished scan carrying the config it ran with (re-scannable).
const DONE_WITH_CONFIG = {
  ok: true,
  mode: "SOURCE",
  id: "demo_2.1",
  results: [{ name: "demo_2.1_bom.json", size: 100 }],
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

// An older scan with no config echoed back — the Re-scan button must stay hidden.
const DONE_NO_CONFIG = { ...DONE_WITH_CONFIG, scanConfig: undefined };

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "2.1" } },
  components: [{ "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o" }],
  dependencies: [],
};

async function openScan(page: Page, done: object) {
  // scanoss on so the source-scan toggles (deep license / vendored) render —
  // needed to prove deepLicense prefills.
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: true, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_2.1", project: "demo", version: "2.1", components: 1, maxSeverity: null, isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_2.1", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.goto("/?ui=next#/scan/demo_2.1");
  await page.getByRole("navigation").first().waitFor();
}

test("Re-scan button shows on a scan that carries a config", async ({ page }) => {
  await openScan(page, DONE_WITH_CONFIG);
  await expect(page.getByRole("link", { name: /^Overview/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Re-scan" })).toBeVisible();

  // The top bar with the Re-scan control stays accessible.
  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});

test("Re-scan button is hidden when the scan has no config", async ({ page }) => {
  await openScan(page, DONE_NO_CONFIG);
  await expect(page.getByRole("link", { name: /^Overview/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Re-scan" })).toHaveCount(0);
});

test("Re-scan prefills the New scan form from the config", async ({ page }) => {
  await openScan(page, DONE_WITH_CONFIG);
  await page.getByRole("button", { name: "Re-scan" }).click();

  // Lands on the New scan form, not an immediate re-run.
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("#/new");
  await expect(page.locator("#project")).toHaveValue("demo");
  await expect(page.locator("#version")).toHaveValue("2.1");

  // The git-url source is selected and its target is seeded.
  await expect(page.getByRole("button", { name: "GitHub URL" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#target")).toHaveValue("https://github.com/acme/demo");

  // Toggles mirror the config: security off, deep license on.
  await expect(page.getByRole("switch", { name: "Security report" })).toHaveAttribute("aria-checked", "false");
  await expect(page.getByRole("switch", { name: "License scan (ScanCode)" })).toHaveAttribute("aria-checked", "true");

  // The git token is never seeded (not in the contract).
  await expect(page.locator("#gitToken")).toHaveValue("");

  // A re-runnable input (git URL) is ready to run straight away.
  await expect(page.getByTestId("run-scan")).toBeEnabled();
});

test("a plain New scan after a re-scan starts blank (config consumed once)", async ({ page }) => {
  await openScan(page, DONE_WITH_CONFIG);
  await page.getByRole("button", { name: "Re-scan" }).click();
  await expect(page.locator("#project")).toHaveValue("demo");

  // Go home, then open New scan again from the rail — the parked config was
  // consumed, so the form is empty (the re-scan must not leak into a plain one).
  await page.getByRole("link", { name: "BomLens" }).click();
  await expect(page.getByRole("heading", { name: "Recent scans" })).toBeVisible();
  await page.getByRole("navigation").getByRole("link", { name: "New scan" }).click();
  await expect(page.locator("#project")).toHaveValue("");
  await expect(page.getByRole("button", { name: "Current folder" })).toHaveAttribute("aria-pressed", "true");
});
