// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as path from "node:path";
import { test, type Page } from "@playwright/test";

/**
 * Hero screenshots for docs/images/web-ui-demo.png (English UI) and
 * docs/images/web-ui-demo-ko.png (Korean UI) (run on demand, excluded
 * from the normal `test:ui` run via the @demo tag). Runs the New scan form
 * over a stubbed backend, then captures the Overview screen — counts,
 * needs-attention, severity distribution, license classification and the
 * highest-risk components all in one view.
 *
 * A static PNG rather than a recorded video/GIF: Playwright's video capture
 * (CDP screencast) does not honor deviceScaleFactor — a 2x deviceScaleFactor
 * with an enlarged video.size left the recorded frame only partially painted
 * (the rest blank), and doubling the viewport itself instead changed the
 * page's own layout (more whitespace at the wider width). page.screenshot(),
 * used here, does honor deviceScaleFactor directly, so a 1040x650
 * layout is captured at full 2x pixel density with no such tradeoff.
 *
 * Regenerate (same pinned container as the guide screenshots):
 *   docker run --rm -v "$PWD":/repo -v /repo/docker/web/frontend/node_modules \
 *     -w /repo/docker/web/frontend mcr.microsoft.com/playwright:v1.61.1-jammy \
 *     bash -lc "npm ci --silent && npx playwright test --grep @demo"
 */

// Playwright runs from docker/web/frontend, so cwd-relative is stable.
const IMAGES = path.join(process.cwd(), "..", "..", "..", "docs", "images");
const W = 1040;
const H = 650;

test.use({
  viewport: { width: W, height: H },
  deviceScaleFactor: 2,
});

// ---------------------------------------------------------------------------
// A richer scan than the screenshot fixtures: enough components for a real
// table, mixed license classes for the Licenses axis, a small dependency
// graph, and a handful of vulnerabilities across severities.
// ---------------------------------------------------------------------------

const LIB = [
  ["express", "4.18.2", "MIT", "direct"],
  ["react", "18.3.1", "MIT", "direct"],
  ["openssl", "3.0.0", "Apache-2.0", "direct"],
  ["readline", "8.1.0", "GPL-3.0-only", "direct"],
  ["libpq", "15.4", "PostgreSQL", "direct"],
  ["lodash", "4.17.21", "MIT", "transitive"],
  ["zlib", "1.2.11", "Zlib", "transitive"],
  ["glibc", "2.38", "LGPL-2.1-only", "transitive"],
  ["cairo", "1.17.8", "MPL-1.1", "transitive"],
  ["ghostscript", "10.1.0", "AGPL-3.0-only", "transitive"],
  ["body-parser", "1.20.1", "MIT", "transitive"],
  ["send", "0.18.0", "MIT", "transitive"],
  ["qs", "6.11.0", "BSD-3-Clause", "transitive"],
  ["custom-widget", "0.9.1", "", "transitive"],
] as const;

const VULN: Record<string, { sev: string; count: number }> = {
  openssl: { sev: "CRITICAL", count: 1 },
  zlib: { sev: "HIGH", count: 1 },
  qs: { sev: "MEDIUM", count: 1 },
  send: { sev: "LOW", count: 1 },
};

const componentList = LIB.map(([name, version, lic, scope]) => ({
  name,
  version,
  group: "",
  purl: `pkg:generic/${name}@${version}`,
  type: "library",
  licenses: lic ? [lic] : [],
  scope,
  ...(VULN[name] ? { maxSeverity: VULN[name].sev, vulnCount: VULN[name].count } : {}),
}));

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo-app_1.0.0",
  results: [
    { name: "demo-app_1.0.0_bom.json", size: 48211 },
    { name: "demo-app_1.0.0_NOTICE.txt", size: 20480 },
    { name: "demo-app_1.0.0_NOTICE.html", size: 34816 },
    { name: "demo-app_1.0.0_security.html", size: 25600 },
    { name: "demo-app_1.0.0_risk-report.html", size: 30720 },
  ],
  security: {
    CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 1, UNKNOWN: 0, TOTAL: 4,
    vulnerabilities: [
      { id: "CVE-2024-0001", severity: "CRITICAL", pkg: "openssl", installed: "3.0.0", fixed: "3.0.7", title: "TLS handshake heap buffer overflow", cvss: 9.8, cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", description: "A heap buffer overflow in the TLS handshake allows remote code execution.", url: "https://example.test/CVE-2024-0001", epss: 0.972, kev: true },
      { id: "CVE-2024-0002", severity: "HIGH", pkg: "zlib", installed: "1.2.11", fixed: "1.2.13", title: "inflate out-of-bounds read", cvss: 7.5, epss: 0.101 },
      { id: "CVE-2024-0003", severity: "MEDIUM", pkg: "qs", installed: "6.11.0", fixed: "6.11.1", title: "prototype pollution", cvss: 5.3, epss: 0.012 },
      { id: "CVE-2024-0004", severity: "LOW", pkg: "send", installed: "0.18.0", fixed: "0.19.0", title: "template injection in error page", cvss: 3.1, epss: 0.001 },
    ],
  },
  conformance: null,
  sbom: { components: LIB.length, componentList, directCount: 5, transitiveCount: 9 },
  scanConfig: {
    source: "current-dir", target: "", project: "demo-app", version: "1.0.0",
    notice: true, security: true, deepLicense: false, identifyVendored: false,
  },
};

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo-app", version: "1.0.0" } },
  components: LIB.map(([name, version]) => ({
    "bom-ref": name, name, version, type: "library", purl: `pkg:generic/${name}@${version}`,
  })),
  dependencies: [
    { ref: "root", dependsOn: ["express", "react", "openssl", "readline", "libpq"] },
    { ref: "express", dependsOn: ["body-parser", "send", "qs", "lodash"] },
    { ref: "openssl", dependsOn: ["zlib"] },
    { ref: "libpq", dependsOn: ["glibc"] },
    { ref: "readline", dependsOn: ["glibc"] },
    { ref: "send", dependsOn: ["cairo", "ghostscript", "custom-widget"] },
  ],
};

async function stub(page: Page, lang: "en" | "ko") {
  await page.addInitScript((l) => {
    localStorage.setItem("sbom.theme", "light");
    localStorage.setItem("sbom.lang", l);
  }, lang);
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: true, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
}

const beat = (page: Page, ms: number) => page.waitForTimeout(ms);

for (const lang of ["en", "ko"] as const) {
  test(`capture the Overview hero screenshot, ${lang} @demo`, async ({ page }) => {
    test.setTimeout(60_000);
    await stub(page, lang);

    // New scan: type the project identity, then run.
    await page.goto("/#/new");
    await beat(page, 1200);
    await page.locator("#project").pressSequentially("demo-app", { delay: 70 });
    await page.locator("#version").pressSequentially("1.0.0", { delay: 70 });
    await beat(page, 700);
    await page.getByTestId("run-scan").click();

    // Overview: counts, needs-attention, severity/license axes, highest-risk table.
    await page.locator("main h1").waitFor();
    await beat(page, 1200);
    // The main content area scrolls independently of the document (window.scrollTo
    // has no effect on it), and it starts already scrolled past the page heading
    // and the count cards' numbers. Scroll the heading itself into view instead.
    await page.locator("main h1").scrollIntoViewIfNeeded();
    await beat(page, 300);

    fs.mkdirSync(IMAGES, { recursive: true });
    await page.screenshot({
      path: path.join(IMAGES, lang === "en" ? "web-ui-demo.png" : "web-ui-demo-ko.png"),
    });
  });
}
