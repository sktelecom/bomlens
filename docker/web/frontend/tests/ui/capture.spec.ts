import { test, type Page } from "@playwright/test";

// Screenshot capture for the docs (run on demand: `npm run capture:ui`, excluded
// from the normal `test:ui` run via the @capture tag). Renders the shell states
// deterministically with stubbed API responses and writes PNGs into
// docs/images/, so the guide screenshots are reproducible.
//
// Two capture shapes, matching the existing files:
//  - Full-window page screenshots at a 1040x664 viewport (top bar + rail +
//    content), for the New scan and Overview guide images.
//  - `main`-element screenshots at the default 1280x720 viewport, where the
//    rail (15rem) + top bar (3.5rem) make `main` exactly 1040x664 — the
//    content-only section images (Components, Vulnerabilities, …).
const IMAGES = "../../../docs/images";

type Lang = "en" | "ko";
type Caps = { firmware: boolean; scanoss?: boolean; docker: boolean; aibom?: boolean };

// Disable fade-in/slide animations so screenshots are crisp and stable.
async function killAnim(page: Page) {
  await page.addStyleTag({
    content:
      "*,*::before,*::after{animation:none!important;transition:none!important;opacity:1!important}",
  });
}

function seedLang(page: Page, lang: Lang) {
  return page.addInitScript((l) => {
    localStorage.setItem("sbom.theme", "light");
    localStorage.setItem("sbom.lang", l);
  }, lang);
}

// Stub the backend the shell talks to: capabilities, the legacy results list, the
// recent-scans list, an optional /file SBOM (dependency/source-tree views) and an
// optional scan-stream `done` event.
async function stub(page: Page, caps: Caps, opts: { done?: unknown; sbom?: unknown } = {}) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  if (opts.sbom) {
    await page.route("**/file**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(opts.sbom) }),
    );
  }
  if (opts.done) {
    await page.route("**/scan-stream**", (r) =>
      r.fulfill({
        contentType: "text/event-stream",
        body: `event: done\ndata: ${JSON.stringify(opts.done)}\n\n`,
      }),
    );
  }
}

// Open the New scan screen and run a stubbed scan, landing on the result sections.
async function runScan(page: Page, project: string, version: string) {
  await page.goto("/#/new");
  await page.fill("#project", project);
  await page.fill("#version", version);
  await page.getByTestId("run-scan").click();
}

// Reset `main` (the scroll container) to the top and let its fade-in settle, so
// the section title sits right under the top bar — not a mid-panel slice.
async function settleMain(page: Page) {
  await page.locator("main").evaluate(async (el) => {
    await Promise.all(el.getAnimations().map((a) => a.finished.catch(() => undefined)));
    el.scrollTop = 0;
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
  await page.mouse.move(0, 0); // neutral pointer — avoid hover-state leak
}

// ---------------------------------------------------------------------------
// Stubbed scan payloads (mirrors tests/ui/shell.spec.ts).
// ---------------------------------------------------------------------------

// A vendored C/C++ source scan, for the --identify-vendored guide images.
const VENDORED_DONE = {
  ok: true,
  mode: "SOURCE",
  id: "trelay_26.4.0",
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

// A finished source scan with an SBOM, a ScanCode artifact and vulnerabilities —
// enough to exercise the rail sections (Overview, Components, Vulnerabilities,
// Dependencies) and the counts.
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
    components: 2,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], scope: "direct", maxSeverity: "CRITICAL", vulnCount: 1 },
      { name: "zlib", version: "1.2.0", group: "", purl: "pkg:github/madler/zlib", type: "library", licenses: ["Zlib"], scope: "transitive" },
    ],
  },
};

// Raw SBOM served by /file for the dependency views: openssl (direct) → zlib.
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

// An AI scan: a machine-learning-model component, so the rail exposes Models &
// datasets. /file returns the matching ML-BOM (CycloneDX 1.7).
const AI_DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "model_1.0",
  results: [{ name: "model_1.0_bom.json", size: 200 }],
  security: null,
  conformance: null,
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

// A scan with AI-restrictive licenses, for the Licenses review section + bar.
const LIC_DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "lic_1.0",
  results: [{ name: "lic_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    componentList: [
      { name: "some-llama-model", version: "1", group: "", purl: "", type: "machine-learning-model", licenses: ["LLaMA-3.1"], licenseReview: "behavioral-use" },
      { name: "some-nc-dataset", version: "1", group: "", purl: "", type: "data", licenses: ["CC-BY-NC-4.0"], licenseReview: "non-commercial" },
      { name: "ordinary-lib", version: "1", group: "", purl: "", type: "library", licenses: ["MIT"] },
    ],
  },
};

const NAV = (page: Page, section: string) =>
  page.getByRole("navigation").locator(`a[href$="/${section}"]`).first();

// ===========================================================================
// Guide images: New scan + Overview, full-window 1040x664 (en + ko).
// ===========================================================================

for (const lang of ["en", "ko"] as Lang[]) {
  const suffix = lang === "en" ? "-en" : "";

  test(`@capture new scan screen — ${lang}`, async ({ page }) => {
    await page.setViewportSize({ width: 1040, height: 664 });
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: true, docker: true });
    await page.goto("/#/new");
    await page.locator("#project").waitFor();
    // SCANOSS is the same token in every locale — a stable anchor that the
    // advanced-options section has rendered.
    await page.getByText(/SCANOSS/).first().waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.screenshot({ path: `${IMAGES}/web-ui${suffix}.png` });
  });

  test(`@capture result overview (full window) — ${lang}`, async ({ page }) => {
    await page.setViewportSize({ width: 1040, height: 664 });
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
    await runScan(page, "demo", "1.0");
    await page.locator("main h1").waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.screenshot({ path: `${IMAGES}/web-ui-scan${suffix}.png` });
  });
}

// ===========================================================================
// Section images: content-only `main` screenshots (1040x664 at default vp), en.
// ===========================================================================

test("@capture overview section (content)", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
  await runScan(page, "demo", "1.0");
  await page.locator("main h1").waitFor();
  await page.getByText(/critical or high vulnerabilities/).first().waitFor();
  await killAnim(page);
  await settleMain(page);
  await page.locator("main").screenshot({ path: `${IMAGES}/app-results.png` });
});

test("@capture components section (content)", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
  await runScan(page, "demo", "1.0");
  await NAV(page, "components").click();
  await page.getByText("openssl", { exact: true }).first().waitFor();
  await killAnim(page);
  await settleMain(page);
  await page.locator("main").screenshot({ path: `${IMAGES}/web-ui-components.png` });
});

test("@capture vulnerabilities section (content)", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
  await runScan(page, "demo", "1.0");
  await NAV(page, "vulnerabilities").click();
  await page.getByText("9.8", { exact: true }).waitFor();
  await killAnim(page);
  await settleMain(page);
  await page.locator("main").screenshot({ path: `${IMAGES}/web-ui-vulns.png` });
});

test("@capture dependencies section (content)", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
  await runScan(page, "demo", "1.0");
  await NAV(page, "dependencies").click();
  // The tree view shows the openssl → zlib relationship deterministically (the
  // graph is a Cytoscape canvas that does not snapshot stably).
  await page.getByTestId("deps-view-tree").click();
  await page.getByText("openssl").first().waitFor();
  await killAnim(page);
  await settleMain(page);
  await page.locator("main").screenshot({ path: `${IMAGES}/web-ui-dependencies.png` });
});

test("@capture licenses section (content)", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: false, docker: true }, { done: LIC_DONE });
  await runScan(page, "lic", "1.0");
  await NAV(page, "licenses").click();
  await page.getByText("some-llama-model").waitFor();
  await killAnim(page);
  await settleMain(page);
  await page.locator("main").screenshot({ path: `${IMAGES}/web-ui-licenses.png` });
});

test("@capture models section (content)", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: false, docker: true }, { done: AI_DONE, sbom: AI_SBOM });
  await runScan(page, "model", "1.0");
  await NAV(page, "models").click();
  await page.getByText("bert-base-uncased").first().waitFor();
  await killAnim(page);
  await settleMain(page);
  await page.locator("main").screenshot({ path: `${IMAGES}/web-ui-models.png` });
});

// ===========================================================================
// --identify-vendored guide images (unchanged content; route fixed to #/new).
// ===========================================================================

test("@capture advanced toggle", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: true, docker: true });
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await killAnim(page);
  // The vendored-ID toggle sits inline under "Advanced scan options" for a
  // source scan — capture that whole section (heading + toggle) so the guide
  // shows users where to find it, not just the bare switch.
  const toggle = page.getByText("Detect copied-in open source");
  await toggle.waitFor({ state: "visible" });
  const section = toggle.locator(
    "xpath=ancestor::div[contains(@class,'border-t')][1]",
  );
  await section.screenshot({
    path: `${IMAGES}/web-ui-identify-vendored-en.png`,
  });
});

test("@capture result banner", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: true, docker: true }, { done: VENDORED_DONE });
  await runScan(page, "trelay", "26.4.0");
  // The banner is the amber rounded-md box that holds the suggestion text.
  const banner = page
    .locator("div.rounded-md")
    .filter({ hasText: "is this C/C++ embedded source" })
    .first();
  await banner.waitFor({ state: "visible" });
  await killAnim(page);
  await settleMain(page);
  await banner.screenshot({ path: `${IMAGES}/web-ui-vendored-banner-en.png` });
});

test("@capture vendored badge in components table", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: true, docker: true }, { done: VENDORED_DONE });
  await runScan(page, "trelay", "26.4.0");
  await NAV(page, "components").click();
  const table = page.locator("table").first();
  await table.waitFor({ state: "visible" });
  await killAnim(page);
  await table.screenshot({ path: `${IMAGES}/web-ui-vendored-badge-en.png` });
});

// An analyzed AI SBOM whose conformance report carries the base + G7 checks, so
// the Conformance section shows the verdict with the G7 advisory sub-block.
// Full-window 1040x664, matching the other guide screenshots.
const CONFORMANCE_DONE = {
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
      { id: "g7-model-id", label: "Model identifier", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto", evidence: ["pkg:huggingface/google-bert/bert-base-uncased@86b5e093"] },
      { id: "g7-model-license", label: "Model license", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto", evidence: ["Apache-2.0"] },
      { id: "g7-model-card", label: "Model properties (model card)", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto" },
      { id: "g7-model-hash-value", label: "Model hash value", required: false, status: "warn", detail: "0/1 model component(s)", cluster: "models", source: "auto" },
      { id: "g7-model-openness", label: "Model license — openness (weight/architecture/data/training)", required: false, status: "warn", detail: "not declared in the SBOM", cluster: "models", source: "inferred" },
      { id: "g7-ds-name", label: "Dataset name", required: false, status: "pass", detail: "2 dataset reference(s)", cluster: "dp", source: "auto" },
    ],
  },
  sbom: {
    components: 1,
    componentList: [
      { name: "bert-base-uncased", version: "86b5e093", group: "google-bert", purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093", type: "machine-learning-model", licenses: ["Apache-2.0"] },
    ],
  },
};

test("@capture conformance section", async ({ page }) => {
  await page.setViewportSize({ width: 1040, height: 664 });
  await seedLang(page, "en");
  await stub(page, { firmware: false, scanoss: false, docker: true }, { done: CONFORMANCE_DONE });
  await runScan(page, "model", "1.0");
  await NAV(page, "conformance").click();
  await page.getByText(/present/).first().waitFor({ state: "visible" });
  await killAnim(page);
  await settleMain(page);
  await page.screenshot({ path: `${IMAGES}/web-ui-g7.png` });
});
