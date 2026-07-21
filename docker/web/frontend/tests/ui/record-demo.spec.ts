import * as fs from "node:fs";
import * as path from "node:path";
import { test, type Page } from "@playwright/test";

/**
 * Demo recording for docs/images/web-ui-demo.gif (run on demand, excluded from
 * the normal `test:ui` run via the @demo tag). Replaces the old hand-recorded
 * GIF with a reproducible walkthrough over a stubbed backend: New scan form →
 * run → Overview → Components (filter) → Vulnerabilities (expand) →
 * Dependencies (graph, then tree) → Licenses.
 *
 * Regenerate (same pinned container as the guide screenshots, then convert):
 *   docker run --rm -v "$PWD":/repo -v /repo/docker/web/frontend/node_modules \
 *     -w /repo/docker/web/frontend mcr.microsoft.com/playwright:v1.61.1-jammy \
 *     bash -lc "npm ci --silent && npx playwright test --grep @demo"
 *   ffmpeg -y -i docker/web/frontend/test-results/web-ui-demo.webm \
 *     -vf "fps=8,scale=900:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=192[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5" \
 *     docs/images/web-ui-demo.gif   # from the repo root
 */

// Playwright runs from docker/web/frontend, so cwd-relative is stable.
const OUT_WEBM = path.join(process.cwd(), "test-results", "web-ui-demo.webm");
const W = 900;
const H = 563;

test.use({
  viewport: { width: W, height: H },
  video: { mode: "on", size: { width: W, height: H } },
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
  id: "demo-app_1.4.0",
  results: [
    { name: "demo-app_1.4.0_bom.json", size: 48211 },
    { name: "demo-app_1.4.0_NOTICE.txt", size: 20480 },
    { name: "demo-app_1.4.0_NOTICE.html", size: 34816 },
    { name: "demo-app_1.4.0_security.html", size: 25600 },
    { name: "demo-app_1.4.0_risk-report.html", size: 30720 },
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
    source: "current-dir", target: "", project: "demo-app", version: "1.4.0",
    notice: true, security: true, deepLicense: false, identifyVendored: false, includeOsv: false,
  },
};

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo-app", version: "1.4.0" } },
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

async function stub(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("sbom.theme", "light");
    localStorage.setItem("sbom.lang", "en");
  });
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

test("record the walkthrough video @demo", async ({ page }) => {
  test.setTimeout(120_000);
  await stub(page);

  // 1. New scan: type the project identity, then run.
  await page.goto("/#/new");
  await beat(page, 1200);
  await page.locator("#project").pressSequentially("demo-app", { delay: 70 });
  await page.locator("#version").pressSequentially("1.4.0", { delay: 70 });
  await beat(page, 700);
  await page.getByTestId("run-scan").click();

  // 2. Overview: counts, needs-attention, severity/license axes.
  await page.getByRole("link", { name: /^Overview/ }).waitFor();
  await beat(page, 3000);

  // 3. Components: the table, then narrow to rows with vulnerabilities.
  await page.getByRole("link", { name: /^Components/ }).click();
  await beat(page, 1800);
  await page.getByRole("button", { name: "Has vulnerabilities" }).click();
  await beat(page, 1600);

  // 4. Vulnerabilities: expand the critical CVE in place.
  await page.getByRole("link", { name: /^Vulnerabilities/ }).click();
  await beat(page, 1500);
  await page.getByText("CVE-2024-0001").first().click();
  await beat(page, 2000);

  // 5. Dependencies: the graph, then the tree.
  await page.getByRole("link", { name: /^Dependencies/ }).click();
  await beat(page, 2200);
  await page.getByRole("button", { name: "Tree", exact: true }).click();
  await beat(page, 1800);

  // 6. Licenses: classification axis and distribution.
  await page.getByRole("link", { name: /^Licenses/ }).click();
  await beat(page, 2600);

  // Finalize the video and park it at a stable path for the ffmpeg step.
  await page.close();
  const video = page.video();
  if (video) {
    fs.mkdirSync(path.dirname(OUT_WEBM), { recursive: true });
    fs.copyFileSync(await video.path(), OUT_WEBM);
  }
});
