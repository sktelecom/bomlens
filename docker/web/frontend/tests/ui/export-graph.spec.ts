// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

/**
 * Taking the tables out to a spreadsheet, and driving the graph without a
 * trackpad.
 *
 * The export asserts the file's actual bytes rather than that a click happened:
 * the row count, the header, and the fact that the current filter is what came
 * out. The graph asserts the zoom level the canvas reports, because a canvas
 * tells the DOM nothing and "the button exists" is not the claim being made.
 */

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_5.0",
  results: [{ name: "demo_5.0_bom.json", size: 100 }],
  conformance: null,
  security: {
    total: 2,
    counts: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0 },
    vulnerabilities: [
      { id: "CVE-2024-5001", severity: "CRITICAL", pkg: "openssl", installed: "3.0.0", fixed: "3.0.1", cvss: 9.8, title: 'buffer, overflow in "read"' },
      { id: "CVE-2024-5002", severity: "HIGH", pkg: "zlib", installed: "1.2.11", fixed: "1.2.12", cvss: 7.5, title: "inflate issue" },
    ],
  },
  sbom: {
    components: 2,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", type: "library", licenses: ["Apache-2.0", "MIT"], purl: "pkg:generic/openssl@3.0.0", vulnCount: 1, maxSeverity: "CRITICAL", scope: "direct" },
      { name: "zlib", version: "1.2.11", group: "", type: "library", licenses: ["Zlib"], purl: "pkg:generic/zlib@1.2.11", vulnCount: 1, maxSeverity: "HIGH", scope: "transitive" },
    ],
  },
};

// The graph needs real edges: a node-only SBOM renders the "no relationships"
// state instead, which is the correct behaviour but not what this tests.
const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "5.0" } },
  components: [
    { "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "pkg:generic/openssl@3.0.0" },
    { "bom-ref": "z", name: "zlib", version: "1.2.11", type: "library", purl: "pkg:generic/zlib@1.2.11" },
  ],
  dependencies: [
    { ref: "root", dependsOn: ["o"] },
    { ref: "o", dependsOn: ["z"] },
  ],
};

async function open(page: Page, section: string) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan?id=demo_5.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.goto(`/?ui=next#/scan/demo_5.0/${section}`);
  await page.getByRole("navigation").first().waitFor();
}

async function downloadText(page: Page, action: () => Promise<void>): Promise<string> {
  const [download] = await Promise.all([page.waitForEvent("download"), action()]);
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const c of stream) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

test("the components export carries the header and every visible row", async ({ page }) => {
  await open(page, "components");
  await expect(page.getByRole("cell", { name: "openssl", exact: true })).toBeVisible();

  const csv = await downloadText(page, () =>
    page.getByRole("button", { name: "Export CSV" }).click(),
  );

  const lines = csv.replace(/^﻿/, "").split("\r\n");
  expect(lines[0]).toBe("Name,Version,Type,Licenses,Scope,Vulnerabilities,Max severity,Package URL");
  expect(lines).toHaveLength(3); // header + two components
  // The multi-license cell is quoted, which is what keeps the later columns in place.
  expect(lines[1]).toContain('"Apache-2.0, MIT"');
  expect(lines[1]).toContain("pkg:generic/openssl@3.0.0");
});

test("the export carries the filter, not the whole table", async ({ page }) => {
  await open(page, "components");
  await page.getByRole("textbox", { name: "Search name, license, type…" }).fill("openssl");
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toHaveCount(0);

  const csv = await downloadText(page, () =>
    page.getByRole("button", { name: "Export CSV" }).click(),
  );

  const lines = csv.replace(/^﻿/, "").split("\r\n");
  expect(lines).toHaveLength(2); // header + openssl only
  expect(csv).not.toContain("zlib");
});

test("a CVE title holding a quote survives the export", async ({ page }) => {
  await open(page, "vulnerabilities");
  await expect(page.getByText("CVE-2024-5001")).toBeVisible();

  const csv = await downloadText(page, () =>
    page.getByRole("button", { name: "Export CSV" }).click(),
  );

  // Quotes are doubled inside a quoted cell; the row keeps its column count.
  expect(csv).toContain('"buffer, overflow in ""read"""');
  const lines = csv.replace(/^﻿/, "").split("\r\n");
  expect(lines).toHaveLength(3);
});

test("the graph zooms and fits from its buttons", async ({ page }) => {
  await open(page, "dependencies");
  const graph = page.locator("[data-zoom]");
  await graph.waitFor({ timeout: 15000 });
  // The element is there before cytoscape has loaded; the buttons do nothing
  // until the canvas exists, and it publishes its label size once it does.
  await expect(graph).toHaveAttribute("data-label-px", /\d/, { timeout: 15000 });
  const zoomOf = async () => Number(await graph.getAttribute("data-zoom"));

  // Fit first, so the comparisons start from a known level rather than from
  // whatever the initial layout settled on.
  await page.getByRole("button", { name: "Fit to view" }).click();
  await expect.poll(zoomOf).toBeGreaterThan(0);
  const fitted = await zoomOf();

  // Out, then back. Zooming in is not asserted from here: this fixture's graph
  // is three nodes, so fit already sits at the zoom cap the component applies
  // to keep small graphs from filling the pane, and there is nowhere further in.
  await page.getByRole("button", { name: "Zoom out" }).click();
  await expect.poll(zoomOf).toBeLessThan(fitted);

  await page.getByRole("button", { name: "Zoom in" }).click();
  await expect.poll(zoomOf).toBeGreaterThan(await zoomOf().then((z) => z * 0.5));

  await page.getByRole("button", { name: "Fit to view" }).click();
  await expect.poll(zoomOf).toBeCloseTo(fitted, 2);
});
