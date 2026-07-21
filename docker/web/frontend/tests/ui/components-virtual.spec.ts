import { expect, test, type Page } from "@playwright/test";

/**
 * Large-SBOM component table: rows render in per-chunk <tbody> elements and
 * chunks far from the viewport are recycled into measured spacers, so the
 * whole filtered set is scrollable without the "show more" clicks the table
 * used to need — and without holding thousands of rows in the DOM.
 */

const N = 600;

const componentList = Array.from({ length: N }, (_, i) => ({
  name: `pkg-${String(i).padStart(4, "0")}`,
  version: "1.0.0",
  group: "",
  purl: `pkg:npm/pkg-${String(i).padStart(4, "0")}@1.0.0`,
  type: "library",
  licenses: ["MIT"],
}));

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "big_1.0",
  results: [{ name: "big_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: N, componentList },
};

async function openComponents(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "big_1.0", project: "big", version: "1.0", components: N, maxSeverity: null, isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=big_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.goto("/?ui=next#/scan/big_1.0/components");
  await page.getByText("pkg-0000").first().waitFor();
}

test("the full set is scrollable with a recycled DOM and no show-more clicks", async ({ page }) => {
  await openComponents(page);

  // No manual reveal button anywhere.
  await expect(page.getByRole("button", { name: /show .* more/i })).toHaveCount(0);

  // Far fewer real rows than components: offscreen chunks are spacers.
  const rows = () => page.locator("tbody tr[role='button']").count();
  expect(await rows()).toBeLessThan(N);

  // Scroll the table container to the bottom; the LAST component materializes.
  const container = page.locator("table").locator("xpath=ancestor::div[1]");
  await container.evaluate((el) => el.scrollTo({ top: el.scrollHeight }));
  await expect(page.getByText(`pkg-${String(N - 1).padStart(4, "0")}`)).toBeVisible();

  // The top chunk got recycled meanwhile — the DOM still holds a window,
  // not the whole list.
  expect(await rows()).toBeLessThan(N);
});

test("a row still expands to its detail panel inside a chunk", async ({ page }) => {
  await openComponents(page);
  await page.getByText("pkg-0002", { exact: true }).click();
  await expect(page.getByText("pkg:npm/pkg-0002@1.0.0").first()).toBeVisible();
});
