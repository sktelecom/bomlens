import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * Shell gates for the new UI behind `?ui=next`:
 *  - accessibility (axe) + visual regression for the idle home screen — now
 *    "Recent scans" (`#/`), with the "New scan" screen (`#/new`) covered
 *    separately — across light/dark × en/ko;
 *  - a stubbed end-to-end scan that proves the result content moved from tabs
 *    into the left-rail sections (Phase 1), with scan-type/data adaptation.
 *
 * Theme and language are seeded into localStorage before the app boots so each
 * combination is deterministic. Visual snapshots are tagged @visual and run in
 * the pinned Playwright container so pixels are stable.
 */

type Theme = "light" | "dark";
type Lang = "en" | "ko";

// `main` is the scroll container (overflow-y-auto) AND mounts with
// `animate-fade-in` (translateY(4px) -> 0) on every section switch. Element
// screenshots of `main` scroll it into view first, so a non-zero scrollTop or an
// unsettled transform shifts the whole tall section a few px — a deterministic-
// looking but flaky ~3% diff. Pin the transform to its end state, reset the
// scroll to the top, and wait two animation frames so layout has fully settled
// before the capture.
async function waitForMainSettled(page: Page) {
  await page.locator("main").evaluate(async (el) => {
    await Promise.all(el.getAnimations().map((a) => a.finished.catch(() => undefined)));
    el.scrollTop = 0;
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
}

async function seedThemeLang(page: Page, theme: Theme, lang: Lang) {
  await page.addInitScript(
    ([t, l]) => {
      localStorage.setItem("sbom.theme", t);
      localStorage.setItem("sbom.lang", l);
    },
    [theme, lang],
  );
}

/** Open the idle home screen (Recent scans, `#/`). */
async function openShell(page: Page, theme: Theme, lang: Lang) {
  await seedThemeLang(page, theme, lang);
  await page.goto("/?ui=next");
  // The idle screens carry no section rail (it's per-scan now); the top bar is
  // the stable anchor that mounts with the shell.
  await page.getByRole("banner").waitFor();
}

/** Open the New scan screen (`#/new`) — the source tiles + settings pane. */
async function openNewScan(page: Page, theme: Theme, lang: Lang) {
  await seedThemeLang(page, theme, lang);
  await page.goto("/?ui=next#/new");
  // The settings pane mounts the project field on the New scan screen only.
  await page.locator("#project").waitFor();
}

const COMBOS: Array<{ theme: Theme; lang: Lang }> = [
  { theme: "light", lang: "en" },
  { theme: "dark", lang: "en" },
  { theme: "light", lang: "ko" },
  { theme: "dark", lang: "ko" },
];

for (const { theme, lang } of COMBOS) {
  test(`idle shell has no axe violations — ${theme}/${lang}`, async ({ page }) => {
    // The idle home is now Recent scans (`#/`). With no backend the list is
    // empty, so this also covers the Recent empty state + New scan CTA.
    await openShell(page, theme, lang);
    // Wait out the main fade-in: axe weighs opacity into contrast, so analysing
    // mid-fade (text at opacity < 1) reports false color-contrast violations.
    await waitForMainSettled(page);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  });

  test(`idle shell matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await openShell(page, theme, lang);
    await expect(page).toHaveScreenshot(`shell-idle-${theme}-${lang}.png`, {
      fullPage: true,
      animations: "disabled",
    });
  });
}

test("New scan screen has no axe violations", async ({ page }) => {
  await openNewScan(page, "light", "en");
  await waitForMainSettled(page); // see note above: avoid mid-fade contrast flake
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("New scan screen matches baseline — light/en @visual", async ({ page }) => {
  await openNewScan(page, "light", "en");
  await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
  await expect(page).toHaveScreenshot("shell-new-light-en.png", {
    fullPage: true,
    animations: "disabled",
  });
});

test("AI model source is gated on the AIBOM image", async ({ page }) => {
  // Without the AIBOM image, the tile is locked (aria-disabled, with a visible
  // reason) rather than plain-disabled, so its reason is still announced.
  await openNewScan(page, "light", "en");
  await expect(page.getByRole("button", { name: "AI model" })).toHaveAttribute(
    "aria-disabled",
    "true",
  );
  await expect(page.getByText("AI-model SBOMs need Docker", { exact: false })).toBeVisible();

  // With the AIBOM image, selecting it reveals the HuggingFace model id input.
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true, aibom: true }) }),
  );
  await page.reload();
  await page.locator("#project").waitFor();
  const tile = page.getByRole("button", { name: "AI model" });
  await expect(tile).toBeEnabled();
  await tile.click();
  await expect(page.locator("#target")).toBeVisible();
  await expect(page.locator("#target")).toHaveAttribute("placeholder", /bert-base-uncased/);
});

test("New scan groups sources and switches the source-specific input", async ({ page }) => {
  await openNewScan(page, "light", "en");

  // The source picker offers the grouped tiles in one labelled group.
  const sources = page.getByRole("group", { name: "Source" });
  await expect(sources).toBeVisible();
  await expect(sources.getByRole("button", { name: "Current folder" })).toBeVisible();
  await expect(sources.getByRole("button", { name: "Docker image" })).toBeVisible();

  // Selecting the GitHub tile reveals the URL target input; Docker keeps it.
  await page.getByRole("button", { name: "GitHub URL" }).click();
  await expect(page.locator("#target")).toBeVisible();
  await page.getByRole("button", { name: "Docker image" }).click();
  await expect(page.locator("#target")).toBeVisible();

  // The settings pane keeps the project field and the generate button.
  await expect(page.locator("#project")).toBeVisible();
  await expect(page.getByRole("button", { name: /Run scan/i })).toBeVisible();
});

test("Recent menu re-opens a past scan from the top bar", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_1.0", project: "demo", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.goto("/?ui=next");

  // The top bar's Recent menu lists the past scan; opening it and clicking the
  // entry loads the result. (Recent moved from the rail to the top bar so the
  // rail stays purely the current scan's sections.)
  await page.getByRole("banner").getByRole("button", { name: "Scan management" }).click();
  const recent = page.getByRole("link", { name: /demo · 1.0/ });
  await expect(recent).toBeVisible();
  await recent.click();

  await expect(page.getByRole("link", { name: /^Overview/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("2 critical or high vulnerabilities")).toBeVisible();
});
test("Recent home renders the summary strip and the scan table", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_1.0", project: "demo", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, componentType: "application", generatedAt: 1700000000 },
      { id: "model_1.0", project: "model", version: "1.0", components: 1, maxSeverity: null, isAiScan: true, componentType: "machine-learning-model", generatedAt: 1700000100 },
    ]) }),
  );
  await page.goto("/?ui=next");

  // The home screen leads with the Recent heading and the three summary cards.
  await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();
  await expect(page.getByText("Total scans")).toBeVisible();
  await expect(page.getByText("At risk")).toBeVisible();
  await expect(page.getByText("Projects")).toBeVisible();

  // Both stored scans appear as table rows (scoped to the `@version` table link,
  // distinct from the sidebar rail's `· version` link).
  await expect(page.getByRole("link", { name: /demo @1.0/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /model @1.0/ })).toBeVisible();
  // The AI row carries the AI-model type badge.
  await expect(page.getByText("AI model").first()).toBeVisible();
});

test("Recent home opens a past scan from the table row", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_1.0", project: "demo", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.goto("/?ui=next");

  await page.getByRole("link", { name: /demo @1.0/ }).click();
  await expect(page.getByRole("link", { name: /^Overview/ })).toHaveAttribute("aria-current", "page");
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("#/scan/demo_1.0");
});

test("Recent home deletes a scan from its row", async ({ page }) => {
  let deleted = false;
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(deleted ? [] : [
      { id: "demo_1.0", project: "demo", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan-delete**", (r) => {
    deleted = true;
    return r.fulfill({ status: 200, body: "" });
  });
  await page.goto("/?ui=next");

  const row = page.getByRole("link", { name: /demo @1.0/ });
  await expect(row).toBeVisible();
  // The row's trash button deletes the scan; the list refreshes to empty.
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(row).toHaveCount(0);
  await expect(page.getByText("Generate your first SBOM")).toBeVisible();
});

test("Recent home empty state offers a New scan CTA", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.goto("/?ui=next");

  await expect(page.getByText("Generate your first SBOM")).toBeVisible();
  // The CTA links to the New scan screen; following it lands there.
  const cta = page.getByRole("main").getByRole("link", { name: "New scan" });
  await expect(cta).toHaveAttribute("href", "#/new");
  await cta.click();
  await expect(page.locator("#project")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("#/new");
});

test("a deep link to a scan section restores that scan and section (open-in-new-tab)", async ({ page }) => {
  // Stub the past-scan endpoints, then open the section URL directly — as a new
  // tab would. The hash router must load the scan and select Components.
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_1.0", project: "demo", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );

  await page.goto("/?ui=next#/scan/demo_1.0/components");

  // Components is the active section, restored straight from the URL.
  await expect(page.getByRole("link", { name: /^Components/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();

  // Section nav links carry hash hrefs so they open in a new tab.
  await expect(page.getByRole("link", { name: /^Vulnerabilities/ })).toHaveAttribute("href", "#/scan/demo_1.0/vulnerabilities");
  await expect(page.getByRole("link", { name: /^Overview/ })).toHaveAttribute("href", "#/scan/demo_1.0");
});

test("the rail spells out the way back to the scan list", async ({ page }) => {
  // The logo and the top bar's clock icon are unlabelled, so a result screen
  // needs a named exit. The rail carries both global links above its sections.
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_1.0", project: "demo", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );

  await page.goto("/?ui=next#/scan/demo_1.0");

  const rail = page.getByRole("navigation", { name: "Sections" });
  // Real hash links, so both open in a new tab like every other rail row.
  await expect(rail.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "#/new");
  const home = rail.getByRole("link", { name: "Scan management" });
  await expect(home).toHaveAttribute("href", "#/");

  await home.click();
  await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();
});

test("an unknown scan id falls back to the Recent scans home screen", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  // A gone scan: /scan?id returns 404.
  await page.route("**/scan?id=**", (r) => r.fulfill({ status: 404, body: "" }));

  await page.goto("/?ui=next#/scan/missing_1.0/components");

  // Falls back to the idle Recent scans home screen and the hash resets to home.
  // The list is empty here, but the heading is shown either way.
  await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("#/");
});

test("Scan running shows the pipeline stages while scanning", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  // Delay the stream so the running view is observable before the done event.
  await page.route("**/scan-stream**", async (r) => {
    await new Promise((res) => setTimeout(res, 2500));
    await r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` });
  });
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();

  // Running view: the headline and the pipeline stage stepper.
  await expect(page.getByText("Scanning…")).toBeVisible();
  await expect(page.getByText("Generate SBOM")).toBeVisible();
  await expect(page.getByText("Security", { exact: true })).toBeVisible();

  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);

  // The scan then completes into the result sections.
  await expect(page.getByRole("link", { name: /^Overview/ })).toBeVisible();
});

test("a failed scan surfaces the error with recovery actions", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  // Connection drops with no `done` — the stranded "Scan failed" case (a launch
  // failure or dropped stream), which lands on the Scan-running error view.
  await page.route("**/scan-stream**", (r) => r.abort());
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();

  // The failure is surfaced in an alert with a way out, not a bare log.
  const alert = page.getByRole("alert");
  await expect(alert).toBeVisible();
  // The current-folder source carries no upload token, so retry is offered…
  await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
  // …alongside an always-available New scan escape hatch.
  await expect(
    page.getByRole("main").getByRole("link", { name: "New scan" }),
  ).toHaveAttribute("href", "#/new");
});

test("global search routes to a component with the term applied", async ({ page }) => {
  await stubAndRun(page);
  await expect(page.getByRole("link", { name: /^Overview/ })).toBeVisible();

  const box = page.getByPlaceholder("Search components, CVEs…");
  await box.click();
  await box.fill("openssl");
  // The popover lists the matching component; pick it (the CVE row starts "CVE-").
  await page.getByRole("listbox").getByRole("button", { name: /^openssl/ }).click();

  // Lands on Components, filtered to openssl (the transitive zlib is gone).
  await expect(page.getByRole("link", { name: /^Components/ })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
  await expect(page.getByText("zlib", { exact: true })).toHaveCount(0);
});

test("cancelling a running scan returns to New scan", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  // Hold the stream open so the running view (and its Cancel button) is present.
  await page.route("**/scan-stream**", async (r) => {
    await new Promise((res) => setTimeout(res, 5000));
    await r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` });
  });
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();

  await expect(page.getByText("Scanning…")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  // Cancel drops back to the New scan screen.
  await expect(
    page.getByRole("heading", { name: "What do you want to scan?" }),
  ).toBeVisible();
});

// A finished scan with an SBOM, a ScanCode artifact and vulnerabilities — enough
// to exercise data-gated rail sections (Dependencies, Source tree) and counts.
const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [
    { name: "demo_1.0_bom.json", size: 100 },
    { name: "demo_1.0_scancode.json", size: 50 },
  ],
  security: {
    CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 2,
    vulnerabilities: [
      { id: "CVE-2024-0001", severity: "CRITICAL", pkg: "openssl", installed: "3.0.0", fixed: "3.0.1", title: "buffer overflow", cvss: 9.8, cvssVector: "CVSS:3.1/AV:N/AC:L", description: "A heap buffer overflow in the TLS handshake.", url: "https://example.test/CVE-2024-0001", epss: 0.972, kev: true },
      { id: "CVE-2024-0002", severity: "HIGH", pkg: "zlib", installed: "1.2.0", fixed: "1.2.1", title: "oob read", cvss: 7.5, epss: 0.004 },
    ],
  },
  conformance: null,
  sbom: {
    // readline is here to keep a copyleft license in frame. Without one, every
    // row in the license distribution is permissive and renders neutral, so the
    // tier colouring and the badge beside a flagged row are invisible to the
    // visual baseline — which is how a highlight nobody could see survived.
    components: 3,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], scope: "direct", maxSeverity: "CRITICAL", vulnCount: 1 },
      { name: "zlib", version: "1.2.0", group: "", purl: "pkg:github/madler/zlib", type: "library", licenses: ["Zlib"], scope: "transitive" },
      { name: "readline", version: "8.2", group: "", purl: "pkg:generic/readline@8.2", type: "library", licenses: ["GPL-3.0-only"], scope: "transitive" },
    ],
  },
};

// Raw SBOM served by /file for the dependency views: openssl (direct,
// vulnerable per the component join) → zlib (transitive).
const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "1.0" } },
  components: [
    { "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o", licenses: [{ license: { id: "Apache-2.0" } }] },
    { "bom-ref": "z", name: "zlib", version: "1.2.0", type: "library", purl: "z" },
  ],
  dependencies: [
    { ref: "root", dependsOn: ["o"] },
    { ref: "o", dependsOn: ["z"] },
  ],
};

async function stubAndRun(page: Page, theme: Theme = "light", lang: Lang = "en") {
  await seedThemeLang(page, theme, lang);
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
}

test("scan results render in the rail sections, adapted to scan type", async ({ page }) => {
  await stubAndRun(page);

  // Result sections appear in the rail; AI-only ones stay hidden for a SOURCE scan.
  await expect(page.getByRole("link", { name: /^Overview/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Components/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Vulnerabilities/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Dependencies/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Source tree/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Artifacts/ })).toBeVisible();
  await expect(page.getByRole("navigation").getByRole("link", { name: /Models & datasets/ })).toHaveCount(0);
  await expect(page.getByRole("navigation").getByRole("link", { name: /conformance/i })).toHaveCount(0);

  // Overview leads; switching to Components shows the table content.
  await page.getByRole("link", { name: /^Components/ }).first().click();
  await expect(page.getByRole("link", { name: /^Components/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();

  // Vulnerabilities section shows the CVE rows.
  await page.getByRole("link", { name: /^Vulnerabilities/ }).first().click();
  await expect(page.getByText("CVE-2024-0001").first()).toBeVisible();
});

test("end-of-life surfaces as a KPI tile, a badge and a filter chip", async ({ page }) => {
  // A scan whose SBOM flagged an end-of-life component (openssl, also
  // vulnerable → at-risk) alongside a still-supported one (zlib).
  const EOL_DONE = {
    ...DONE,
    sbom: {
      components: 2,
      eolCount: 1,
      atRiskCount: 1,
      componentList: [
        { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], scope: "direct", maxSeverity: "CRITICAL", vulnCount: 1, eol: "true", eolDate: "2023-09-11" },
        { name: "zlib", version: "1.2.0", group: "", purl: "pkg:github/madler/zlib", type: "library", licenses: ["Zlib"], scope: "transitive", eol: "false" },
      ],
    },
  };
  await seedThemeLang(page, "light", "en");
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(EOL_DONE)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();

  // Overview KPI tile links into Components; the at-risk hint is present.
  const tile = page.getByRole("link", { name: "View End of life" });
  await expect(tile).toBeVisible();
  await expect(tile.getByText("1 also vulnerable")).toBeVisible();
  await tile.click();
  await expect(page.getByRole("link", { name: /^Components/ })).toHaveAttribute("aria-current", "page");

  // The EOL component carries the badge; the supported one does not.
  await expect(page.getByText("End of life · since 2023-09-11")).toBeVisible();

  // The filter chip narrows the table to end-of-life rows only.
  await page.getByRole("button", { name: "End of life", exact: true }).click();
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("zlib", { exact: true })).toHaveCount(0);
});

test("Overview leads with needs-attention and jumps into sections", async ({ page }) => {
  await stubAndRun(page);

  // Needs-attention surfaces the critical/high vulnerabilities (1+1) and links out.
  const attention = page.getByRole("link", { name: /critical or high vulnerabilities/ });
  await expect(attention).toBeVisible();
  await attention.click();
  await expect(page.getByRole("link", { name: /^Vulnerabilities/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("CVE-2024-0001").first()).toBeVisible();

  // Back to Overview; a jump card navigates into Components.
  await page.getByRole("link", { name: /^Overview/ }).first().click();
  await page.getByRole("link", { name: "View Components" }).first().click();
  await expect(page.getByRole("link", { name: /^Components/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
});

test("Overview severity bar routes into filtered Vulnerabilities", async ({ page }) => {
  await stubAndRun(page);
  await expect(page.getByRole("link", { name: /^Overview/ })).toBeVisible();

  // Click the High band in the Overview severity axis.
  await page.getByRole("button", { name: "High 1" }).first().click();

  // Lands on Vulnerabilities filtered to HIGH — the HIGH CVE stays, the CRITICAL one is gone.
  await expect(page.getByRole("link", { name: /^Vulnerabilities/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("CVE-2024-0002")).toBeVisible();
  await expect(page.getByText("CVE-2024-0001")).toHaveCount(0);
});

test("Overview license bar routes into filtered Licenses", async ({ page }) => {
  await stubLicensesAndRun(page);
  await expect(page.getByRole("link", { name: /^Overview/ })).toBeVisible();

  // LIC_DONE is 2 review-needed + 1 permissive (MIT); click the Permissive band.
  await page.getByRole("button", { name: "Permissive 1" }).first().click();

  // Lands on Licenses filtered to permissive — the AI-restrictive review card is
  // gone, and the classification band stays selected so the filter is visible.
  await expect(page.getByRole("link", { name: /^Licenses/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("License review needed")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Permissive 1" }).first(),
  ).toHaveAttribute("aria-pressed", "true");
});

test("dependency graph is labelled and the tree view is keyboard-reachable", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("navigation").locator('a[href$="/dependencies"]').first().click();

  // The canvas region carries an accessible label (it's a visual; the tree is
  // the keyboard path).
  await expect(page.getByRole("img", { name: /Dependency graph/ })).toBeVisible();

  // The Tree toggle is a real button: focus it and activate with the keyboard.
  const tree = page.getByTestId("deps-view-tree");
  await tree.focus();
  await expect(tree).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByText("openssl").first()).toBeVisible();
});

test("section navigation moves focus to the section heading", async ({ page }) => {
  await stubAndRun(page);
  // Switching sections from the rail should move focus onto the new section's
  // heading, so keyboard/screen-reader users follow the content.
  await page.getByRole("navigation").locator('a[href$="/components"]').first().click();
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
  await expect(page.locator("main h1")).toBeFocused();
});

test("overview has no axe violations", async ({ page }) => {
  await stubAndRun(page);
  await expect(page.getByText(/critical or high vulnerabilities/)).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("Overview warns when the SBOM degraded to syft (disk space)", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  const degraded = { ...DONE, sbom: { ...DONE.sbom, sbomToolDegraded: "disk-space" } };
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(degraded)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();

  // The degraded banner explains the thin graph and how to fix it.
  await expect(page.getByText("Direct dependencies only", { exact: false })).toBeVisible();
  await expect(page.getByText(/docker system prune/)).toBeVisible();

  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});

// Result-section visuals run across light/dark × en/ko. The setup navigates and
// waits on language-agnostic anchors — section links by href, the Tree toggle by
// test id, and data values (package names, scores, licence ids) that don't
// translate — so the same flow drives every locale.
for (const { theme, lang } of COMBOS) {
  test(`overview section matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await stubAndRun(page, theme, lang);
    // The result Overview renders its h1 only once loaded (locale-agnostic anchor).
    await expect(page.locator("main h1")).toBeVisible();
    await waitForMainSettled(page);
    await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
    await expect(page.locator("main")).toHaveScreenshot(`overview-${theme}-${lang}.png`, {
      animations: "disabled",
    });
  });
}

// An AI scan: the SBOM carries a machine-learning-model component, so the rail
// exposes Models & Datasets. /file returns the matching ML-BOM (CycloneDX 1.7).
const AI_DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "model_1.0",
  results: [{ name: "model_1.0_bom.json", size: 200 }],
  security: null,
  conformance: {
    result: "pass",
    format: "CycloneDX",
    checks: [
      { id: "timestamp", label: "Timestamp present", required: true, status: "pass", detail: "1 found" },
      { id: "license", label: "License coverage (recommended)", required: false, status: "warn", detail: "0%" },
      { id: "g7-meta-author", label: "SBOM author", required: false, status: "pass", detail: "author present", cluster: "metadata", source: "auto" },
      { id: "g7-meta-timestamp", label: "SBOM timestamp", required: false, status: "pass", detail: "1 found", cluster: "metadata", source: "auto" },
      { id: "g7-slp-data-flow", label: "System data flow", required: false, status: "warn", detail: "no automated source", cluster: "slp", source: "na" },
      { id: "g7-model-id", label: "Model identifier", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto", evidence: ["pkg:huggingface/google-bert/bert-base-uncased@86b5e093"], regulations: [{ framework: "eu-ai-act", short: "EU AI Act", short_ko: "EU 인공지능법", ref: "Annex IV(1)", basis: "general description of the AI system" }] },
      { id: "g7-model-license", label: "Model license", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto", evidence: ["Apache-2.0"], regulations: [{ framework: "kr-ai-framework-act", short: "AI Framework Act", short_ko: "AI 기본법", ref: "제31조", basis: "documentation of the AI system" }] },
      { id: "g7-model-card", label: "Model properties (model card)", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto" },
      { id: "g7-model-hash-value", label: "Model hash value", required: false, status: "warn", detail: "0/1 model component(s)", cluster: "models", source: "auto" },
      { id: "g7-model-openness", label: "Model license — openness (weight/architecture/data/training)", required: false, status: "warn", detail: "not declared in the SBOM", cluster: "models", source: "inferred" },
      { id: "g7-ds-name", label: "Dataset name", required: false, status: "pass", detail: "2 dataset reference(s)", cluster: "dp", source: "auto" },
    ],
    // Detailed crosswalk (present only for AI SBOMs) — per-framework element
    // rollup with the mapped documentation obligations. source + elements[] are
    // the detail view (unlike the aiProfile card view below).
    regulatoryCrosswalk: {
      disclaimer: "Documentation-preparation aid, not a compliance verdict.",
      frameworks: [
        {
          id: "eu-ai-act", title: "EU AI Act — Annex IV", source: "Regulation (EU) 2024/1689",
          total: 2, present: 1, gap: 1, review: 0,
          elements: [
            { label: "Model identifier", status: "pass", source: "auto", refs: ["Annex IV(1)"] },
            { label: "Model hash value", status: "warn", source: "auto", refs: ["Annex IV(2)(d)"] },
          ],
        },
        {
          id: "kr-ai-framework-act", title: "Korean AI Framework Act", source: "AI Framework Act",
          total: 1, present: 1, gap: 0, review: 0,
          elements: [
            { label: "Model license", status: "pass", source: "auto", refs: ["제31조"] },
          ],
        },
      ],
    },
  },
  // AI compliance profile card rollup (summary view: no per-element detail).
  aiProfile: {
    conformanceResult: "warn",
    g7: {
      total: 9, auto: 8, present: 6, gap: 2, review: 1,
      clusters: [
        { cluster: "metadata", total: 2, present: 2, gap: 0, review: 0 },
        { cluster: "models", total: 4, present: 3, gap: 1, review: 0 },
      ],
    },
    licenseReview: { total: 2, behavioral: 1, nonCommercial: 1 },
    regulatoryCrosswalk: {
      disclaimer: "Documentation-preparation aid, not a compliance verdict.",
      frameworks: [
        { id: "eu-ai-act", title: "EU AI Act — Annex IV", total: 2, present: 1, gap: 1, review: 0 },
        { id: "kr-ai-framework-act", title: "Korean AI Framework Act", total: 1, present: 1, gap: 0, review: 0 },
      ],
    },
  },
  sbom: {
    components: 1,
    componentList: [
      { name: "bert-base-uncased", version: "86b5e093", group: "google-bert", purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093", type: "machine-learning-model", licenses: ["Apache-2.0"] },
    ],
  },
};
const AI_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  metadata: { component: { "bom-ref": "root", name: "model", version: "1.0" } },
  components: [
    {
      type: "machine-learning-model", "bom-ref": "m", name: "bert-base-uncased", version: "86b5e093", group: "google-bert",
      purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093", description: "A BERT model.",
      licenses: [{ license: { id: "Apache-2.0" } }], supplier: { name: "google-bert" }, authors: [{ name: "google-bert" }],
      externalReferences: [{ type: "distribution", url: "https://huggingface.co/google-bert/bert-base-uncased/tree/main" }],
      modelCard: {
        modelParameters: {
          task: "fill-mask", modelArchitecture: "bert",
          datasets: [
            { type: "dataset", name: "bookcorpus", contents: { url: "https://huggingface.co/datasets/bookcorpus" } },
            { type: "dataset", name: "wikipedia", contents: { url: "https://huggingface.co/datasets/wikipedia" } },
          ],
        },
        considerations: { technicalLimitations: ["Intended to be fine-tuned."] },
      },
    },
  ],
};

async function stubAiAndRun(page: Page, theme: Theme = "light", lang: Lang = "en") {
  await seedThemeLang(page, theme, lang);
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(AI_SBOM) }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(AI_DONE)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "model");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
}

test("AI scan exposes Models & Datasets with the model card", async ({ page }) => {
  await stubAiAndRun(page);
  await expect(page.getByRole("navigation").getByRole("link", { name: /Models & datasets/ })).toBeVisible();
  await page.getByRole("navigation").getByRole("link", { name: /Models & datasets/ }).click();

  await expect(page.getByText("bert-base-uncased").first()).toBeVisible();
  await expect(page.getByText("bert", { exact: true })).toBeVisible(); // architecture
  await expect(page.getByText("fill-mask")).toBeVisible(); // task
  await expect(page.getByText("bookcorpus").first()).toBeVisible();
  await expect(page.getByText("wikipedia").first()).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

for (const { theme, lang } of COMBOS) {
  test(`models section matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await stubAiAndRun(page, theme, lang);
    await page.getByRole("navigation").locator('a[href$="/models"]').first().click();
    await expect(page.getByText("bert-base-uncased").first()).toBeVisible();
    await waitForMainSettled(page);
    await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
    await expect(page.locator("main")).toHaveScreenshot(`models-${theme}-${lang}.png`, {
      animations: "disabled",
    });
  });
}

test("AI scan exposes G7 conformance with present/advisory split", async ({ page }) => {
  await stubAiAndRun(page);
  // The coverage figure surfaces before entering the section: as the rail badge
  // and as the overview jump-card value (both from conformanceCount).
  await expect(page.getByRole("navigation").getByRole("link", { name: /conformance/i })).toContainText("6/8");
  await expect(page.locator("main").getByText("6/8")).toBeVisible();
  await page.getByRole("navigation").getByRole("link", { name: /conformance/i }).click();

  // Headline tally comes straight from the check statuses: 6 of 8 auto-covered,
  // 2 advisory and 1 needing human review (the source:"na" element).
  await expect(page.getByText("6/8 present")).toBeVisible();
  await expect(page.getByText(/2 advisory/)).toBeVisible();
  await expect(page.getByText(/1 need review/)).toBeVisible();
  // G7 checks are grouped into their clusters (headers rendered).
  await expect(page.getByText("Models", { exact: true })).toBeVisible();
  // The na element carries a "Review needed" provenance badge.
  await expect(page.getByText("Review needed").first()).toBeVisible();
  // Base checks are split out under their own heading.
  await expect(page.getByText("Format conformance")).toBeVisible();
  await expect(page.getByText("Model license — openness (weight/architecture/data/training)")).toBeVisible();

  // AI compliance summary card (from aiProfile) is at the top of the section.
  await expect(page.getByText("AI compliance profile")).toBeVisible();
  await expect(page.getByText("G7 minimum elements", { exact: true })).toBeVisible();
  await expect(page.getByText("License review flags")).toBeVisible();
  await expect(page.getByText("Regulatory coverage")).toBeVisible();

  // Regulatory crosswalk sub-block (from conformance.regulatoryCrosswalk). Exact,
  // so it matches the block heading and not the panel intro, which also mentions
  // the regulatory crosswalk.
  await expect(page.getByText("Regulatory crosswalk", { exact: true })).toBeVisible();
  await expect(page.getByText("EU AI Act — Annex IV").first()).toBeVisible();
  await expect(page.getByText("Korean AI Framework Act").first()).toBeVisible();
  await expect(page.getByText("Annex IV(1)")).toBeVisible(); // a mapped regulation ref

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

// The rail is a fixed width, so a label plus its count badge has a hard budget.
// "SBOM conformance" overran it once and rendered as "SBOM conforma…". Nothing
// else would catch that: it clips silently, and the section screenshots crop to
// <main>.
//
// This fixture's badges are narrow (6/8), so every badge is first widened to the
// widest shape a real scan produces — a two-digit pair like 13/16, seen on the
// demo's own conformance count. Testing the labels against the badges that
// happen to be in the fixture would pass while the app clips.
const WIDEST_BADGE = "13/16";

for (const lang of ["en", "ko"] as const) {
  test(`rail labels survive the widest count badge — ${lang}`, async ({ page }) => {
    await stubAiAndRun(page, "light", lang);
    await page.getByRole("navigation").locator('a[href$="/conformance"]').first().waitFor();

    const clipped = await page.evaluate((badge) => {
      for (const b of document.querySelectorAll("nav a span.tabular-nums")) {
        b.textContent = badge;
      }
      // Read a layout property to flush the mutations before measuring.
      void document.body.offsetHeight;
      return [...document.querySelectorAll("nav a span.truncate")]
        .filter((s) => s.scrollWidth > (s as HTMLElement).clientWidth)
        .map((s) => `${s.textContent} (${(s as HTMLElement).clientWidth}/${s.scrollWidth})`);
    }, WIDEST_BADGE);
    expect(clipped).toEqual([]);
  });
}

// A conformance report that has G7 checks but no aiProfile and no crosswalk (a
// plain re-open of an older AI scan, or a non-AI SBOM path): neither the summary
// card nor the crosswalk sub-block renders — only the G7 and format checks do.
test("conformance without a profile or crosswalk omits the AI card and crosswalk", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  const bare = {
    ...AI_DONE,
    aiProfile: null,
    conformance: { result: AI_DONE.conformance.result, format: AI_DONE.conformance.format, checks: AI_DONE.conformance.checks },
  };
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(AI_SBOM) }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(bare)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "model");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
  await page.getByRole("navigation").getByRole("link", { name: /conformance/i }).click();

  // The G7 section still renders (proves we reached the conformance panel)…
  await expect(page.getByText("6/8 present")).toBeVisible();
  // …but neither the AI card nor the crosswalk sub-block is present.
  await expect(page.getByText("AI compliance profile")).toHaveCount(0);
  // Exact — the panel intro mentions the regulatory crosswalk, so a substring
  // match would find it even when the crosswalk block itself is absent.
  await expect(page.getByText("Regulatory crosswalk", { exact: true })).toHaveCount(0);
});

for (const { theme, lang } of COMBOS) {
  test(`conformance section matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await stubAiAndRun(page, theme, lang);
    await page.getByRole("navigation").locator('a[href$="/conformance"]').first().click();
    // "6/8" and the CycloneDX label are the same in every locale. Scoped to
    // <main> — the rail's conformance badge carries the same 6/8 figure.
    await expect(page.getByText("CycloneDX")).toBeVisible();
    await expect(page.locator("main").getByText(/6\s*\/\s*8/)).toBeVisible();
    // <main> mounts with `animate-fade-in` (translateY(4px) -> 0) on every section
    // switch. With `animations: "disabled"`, Playwright freezes the transform to a
    // non-deterministic frame, so the whole tall section is sometimes captured 4px
    // low — a constant ~3% diff. Wait for main's own animations to finish so the
    // transform has settled to translateY(0) before the screenshot.
    await waitForMainSettled(page);
    await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
    await expect(page.locator("main")).toHaveScreenshot(`conformance-${theme}-${lang}.png`, {
      animations: "disabled",
    });
  });
}

// A scan with AI-restrictive licenses, for the Licenses review section.
const LIC_DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "lic_1.0",
  results: [{ name: "lic_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: {
    components: 4,
    componentList: [
      { name: "some-llama-model", version: "1", group: "", purl: "", type: "machine-learning-model", licenses: ["LLaMA-3.1"], licenseReview: "behavioral-use" },
      { name: "some-nc-dataset", version: "1", group: "", purl: "", type: "data", licenses: ["CC-BY-NC-4.0"], licenseReview: "non-commercial" },
      { name: "ordinary-lib", version: "1", group: "", purl: "", type: "library", licenses: ["MIT"] },
      // A copyleft row, so the distribution's tier colouring and its badge are
      // in this section's baseline. The others are AI-restrictive or permissive
      // and all render neutral, which left the flagged styling uncovered.
      { name: "copyleft-lib", version: "1", group: "", purl: "", type: "library", licenses: ["GPL-3.0-only"] },
    ],
  },
};

async function stubLicensesAndRun(page: Page, theme: Theme = "light", lang: Lang = "en") {
  await seedThemeLang(page, theme, lang);
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(LIC_DONE)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "lic");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
}

test("Licenses section flags AI-restrictive licenses for review", async ({ page }) => {
  await stubLicensesAndRun(page);
  await page.getByRole("link", { name: /^Licenses/ }).first().click();

  await expect(page.getByText("License review needed")).toBeVisible();
  await expect(page.getByText("Behavioral-use")).toBeVisible();
  await expect(page.getByText("Non-commercial")).toBeVisible();
  await expect(page.getByText("some-llama-model")).toBeVisible();
  await expect(page.getByText("some-nc-dataset")).toBeVisible();
  // The section names the licenses it counted — the rail badge promises that
  // number, so the list has to be here and not one section away.
  const distribution = page.getByRole("list", { name: "Licenses" });
  for (const id of ["LLaMA-3.1", "CC-BY-NC-4.0", "MIT", "GPL-3.0-only"]) {
    await expect(distribution.getByText(id, { exact: true })).toBeVisible();
  }

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("a classification narrows the license distribution, and a license opens its components", async ({ page }) => {
  await stubLicensesAndRun(page);
  await page.getByRole("link", { name: /^Licenses/ }).first().click();

  const distribution = page.getByRole("list", { name: "Licenses" });
  await expect(distribution.getByRole("listitem")).toHaveCount(4);

  // Picking a classification has to change what is listed — LIC_DONE has one
  // strong-copyleft component, so only GPL-3.0-only survives.
  await page.getByRole("button", { name: "Strong copyleft 1" }).first().click();
  await expect(distribution.getByRole("listitem")).toHaveCount(1);
  await expect(distribution.getByText("GPL-3.0-only", { exact: true })).toBeVisible();

  // The row leads to that license's components, with the filter applied.
  await distribution.getByRole("button").first().click();
  await expect(page.getByRole("link", { name: /^Components/ })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await expect(page.getByText("copyleft-lib", { exact: true })).toBeVisible();
  await expect(page.getByText("ordinary-lib", { exact: true })).toHaveCount(0);
});

// A scan whose SBOM carries a known-malicious package. The Overview must lead
// with it and the component row must carry the badge — neither is covered by a
// screenshot, since the attention list and the table sit at different scroll
// positions.
const MALICIOUS_DONE = {
  ok: true,
  mode: "SOURCE",
  id: "mal_1.0",
  results: [{ name: "mal_1.0_bom.json", size: 100 }],
  security: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 1, vulnerabilities: [
    { id: "CVE-2024-9999", severity: "CRITICAL", pkg: "honest", installed: "2.0", fixed: "2.1", title: "flaw" },
  ] },
  conformance: null,
  sbom: {
    components: 2,
    maliciousCount: 1,
    componentList: [
      { name: "evil", version: "1.0", group: "", purl: "pkg:npm/evil@1.0", type: "library", licenses: ["MIT"], malicious: true, maliciousId: "MAL-2024-1", maliciousSource: "osv.dev@2026-01-02" },
      { name: "honest", version: "2.0", group: "", purl: "pkg:npm/honest@2.0", type: "library", licenses: ["MIT"], maxSeverity: "CRITICAL", vulnCount: 1 },
    ],
  },
};

async function stubMaliciousAndRun(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(MALICIOUS_DONE)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "mal");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
}

test("Overview leads with malicious packages, above critical vulnerabilities", async ({ page }) => {
  await stubMaliciousAndRun(page);

  const attention = page.locator("main ul li a");
  // Ordering is the assertion: a package already running in the build outranks
  // a vulnerability waiting to be patched.
  await expect(attention.first()).toContainText(/known-malicious/i);
  await expect(attention.first()).toContainText(/remove and rotate/i);

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("Components table badges the malicious package", async ({ page }) => {
  await stubMaliciousAndRun(page);
  await page.getByRole("link", { name: /^Components/ }).first().click();

  const row = page.locator("main li, main tr").filter({ hasText: "evil" }).first();
  // Spelled out in words, so the badge does not rely on colour alone.
  await expect(row.getByText("Malicious package")).toBeVisible();
  // The honest component keeps its severity and gains no malicious badge.
  await expect(page.locator("main").getByText("Malicious package")).toHaveCount(1);
});

// A scan that declared an outbound license, so the conflict check ran. The
// verdicts here are the ones the scanner produces (see license-flags.jq); this
// fixture pins how the section presents them.
const CONFLICT_DONE = {
  ok: true,
  mode: "SOURCE",
  id: "conf_1.0",
  results: [{ name: "conf_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    outboundLicense: "Apache-2.0",
    conflictCounts: { incompatible: 1, conditional: 1, unknown: 0, compatible: 1 },
    componentList: [
      { name: "gpl-dep", version: "1", group: "", purl: "", type: "library", licenses: ["GPL-3.0-only"], licenseConflict: "incompatible", licenseConflictWhy: "Distributing a combined work requires the whole work to be offered under the copyleft license." },
      { name: "epl-dep", version: "1", group: "", purl: "", type: "library", licenses: ["EPL-2.0"], licenseConflict: "conditional", licenseConflictWhy: "File-level reciprocity: check how you link and distribute." },
      { name: "mit-dep", version: "1", group: "", purl: "", type: "library", licenses: ["MIT"], licenseConflict: "compatible", licenseConflictWhy: "Both are permissive." },
    ],
  },
};

async function stubConflictAndRun(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(CONFLICT_DONE)}\n\n` }),
  );
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "conf");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
}

// The conflict block sits below the fold of the licenses screenshot, so the
// visual baseline cannot police it — these assertions are what guard it.
test("Licenses section lists outbound-license conflicts worst first", async ({ page }) => {
  await stubConflictAndRun(page);
  await page.getByRole("link", { name: /^Licenses/ }).first().click();

  // The heading names the license the dependencies were judged against, so the
  // reader knows what "conflict" is relative to.
  await expect(page.getByText("Conflicts with your outbound license (Apache-2.0)")).toBeVisible();

  // Worst first, and the verdict is spelled out in words — the badge colour is
  // never the only carrier of meaning.
  const badges = page.locator("main").getByText(/Cannot be met|Depends on how you ship/);
  await expect(badges.first()).toHaveText("Cannot be met");
  await expect(page.getByText("gpl-dep")).toBeVisible();
  await expect(
    page.getByText("Distributing a combined work requires the whole work"),
  ).toBeVisible();

  // A compatible dependency is not listed: the block is what needs a look.
  await expect(page.locator("main").getByText("mit-dep")).toHaveCount(0);

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("Licenses section says so when no outbound license was declared", async ({ page }) => {
  // LIC_DONE carries no outboundLicense — an empty conflict table would read as
  // an all-clear, so the section states the check never ran and how to turn it on.
  await stubLicensesAndRun(page);
  await page.getByRole("link", { name: /^Licenses/ }).first().click();

  await expect(page.getByText("Outbound-license conflicts were not checked")).toBeVisible();
  await expect(page.getByText(/--license/)).toBeVisible();
  await expect(page.getByText(/Conflicts with your outbound license/)).toHaveCount(0);
});

for (const { theme, lang } of COMBOS) {
  test(`licenses section matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await stubLicensesAndRun(page, theme, lang);
    await page.getByRole("navigation").locator('a[href$="/licenses"]').first().click();
    await expect(page.getByText("some-llama-model")).toBeVisible();
    await waitForMainSettled(page);
    await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
    await expect(page.locator("main")).toHaveScreenshot(`licenses-${theme}-${lang}.png`, {
      animations: "disabled",
    });
  });
}

test("Dependencies tree marks vulnerable packages and direct deps", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("link", { name: /^Dependencies/ }).first().click();
  await page.getByRole("button", { name: "Tree", exact: true }).click();

  // openssl is a direct dependency and vulnerable → Critical + Direct badges.
  const opensslRow = page.locator("li", { hasText: "openssl" }).first();
  await expect(opensslRow.getByText("Critical", { exact: true })).toBeVisible();
  await expect(opensslRow.getByText("Direct", { exact: true })).toBeVisible();

  // The tree view has no axe violations.
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

for (const { theme, lang } of COMBOS) {
  test(`dependencies tree matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await stubAndRun(page, theme, lang);
    await page.getByRole("navigation").locator('a[href$="/dependencies"]').first().click();
    await page.getByTestId("deps-view-tree").click();
    await expect(page.getByText("openssl").first()).toBeVisible();
    await waitForMainSettled(page);
    await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
    await expect(page.locator("main")).toHaveScreenshot(`dependencies-tree-${theme}-${lang}.png`, {
      animations: "disabled",
    });
  });
}

test("Vulnerabilities table shows CVSS, sorts, and expands a row", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("link", { name: /^Vulnerabilities/ }).first().click();

  // CVSS is a column now, with the scores visible (default: most severe first).
  await expect(page.getByRole("button", { name: "CVSS", exact: true })).toBeVisible();
  await expect(page.getByText("9.8", { exact: true })).toBeVisible();
  await expect(page.getByText("7.5", { exact: true })).toBeVisible();

  // EPSS column (enriched run) and the KEV badge on the actively-exploited CVE.
  await expect(page.getByRole("button", { name: "EPSS", exact: true })).toBeVisible();
  await expect(page.getByText("97.2%")).toBeVisible();
  await expect(page.getByText("KEV", { exact: true })).toBeVisible();

  // Sorting by CVSS toggles the column's aria-sort.
  const cvssTh = page.locator("th", {
    has: page.getByRole("button", { name: "CVSS", exact: true }),
  });
  await expect(cvssTh).toHaveAttribute("aria-sort", "none");
  await page.getByRole("button", { name: "CVSS", exact: true }).click();
  await expect(cvssTh).toHaveAttribute("aria-sort", /ascending|descending/);

  // A row expands in place to show the vector, description and references.
  await page.getByText("CVE-2024-0001").click();
  await expect(page.getByText(/heap buffer overflow/)).toBeVisible();
  await expect(page.getByText("CVSS:3.1/AV:N/AC:L")).toBeVisible();
});

for (const { theme, lang } of COMBOS) {
  test(`vulnerabilities section matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await stubAndRun(page, theme, lang);
    await page.getByRole("navigation").locator('a[href$="/vulnerabilities"]').first().click();
    await expect(page.getByText("9.8", { exact: true })).toBeVisible();
    await waitForMainSettled(page);
    await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
    await expect(page.locator("main")).toHaveScreenshot(`vulnerabilities-${theme}-${lang}.png`, {
      animations: "disabled",
    });
  });
}

test("Components table shows Scope/Risk and filters on the full set", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("link", { name: /^Components/ }).first().click();
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();

  // Scope + Risk columns render from the joined data.
  await expect(page.getByRole("button", { name: "Scope", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Risk", exact: true })).toBeVisible();
  await expect(page.getByText("zlib", { exact: true })).toBeVisible();

  // "Has vulnerabilities" narrows to the component with a CVE (openssl only).
  await page.getByRole("button", { name: "Has vulnerabilities" }).click();
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
  await expect(page.getByText("zlib", { exact: true })).toHaveCount(0);

  // Clearing it brings zlib back; "Direct only" then also excludes the transitive zlib.
  await page.getByRole("button", { name: "Has vulnerabilities" }).click();
  await page.getByRole("button", { name: "Direct only" }).click();
  await expect(page.getByText("zlib", { exact: true })).toHaveCount(0);
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
});

for (const { theme, lang } of COMBOS) {
  test(`components section matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await stubAndRun(page, theme, lang);
    await page.getByRole("navigation").locator('a[href$="/components"]').first().click();
    await expect(page.getByText("openssl", { exact: true })).toBeVisible();
    await waitForMainSettled(page);
    await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
    await expect(page.locator("main")).toHaveScreenshot(`components-${theme}-${lang}.png`, {
      animations: "disabled",
    });
  });
}

test("results view has no axe violations", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("link", { name: /^Components/ }).first().click();
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
