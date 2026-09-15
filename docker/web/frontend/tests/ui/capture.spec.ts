// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, type Page } from "@playwright/test";

// `npm run test:ui` already excludes this file by tag (--grep-invert
// "@capture|..."), but that only holds if every invocation remembers the
// flag: a bare `playwright test` (no grep) still discovers and runs it,
// overwriting docs/images. This env-var gate is the backstop: it skips
// every test in this file unless CAPTURE=1, which only `capture:ui` and
// `capture:og` set (mirrors electron/tests/capture.spec.ts's SBOM_CAPTURE
// gate for the same reason).
test.skip(process.env.CAPTURE !== "1", "opt-in via CAPTURE=1 (npm run capture:ui)");

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
type Caps = { firmware: boolean; scanoss?: boolean; docker: boolean; aibom?: boolean; spdxExport?: boolean };

// UI copy a capture needs to locate on screen, kept in one place so it stays in
// sync with src/locales/{en,ko}/common.json instead of being retyped per test.
// Values are substrings (not full interpolated strings), chosen to survive a
// count or version number changing inside the sentence.
const STR: Record<Lang, {
  scanOptions: string; // scanOptions
  identifyVendored: string; // identifyVendored
  vendoredHint: string; // substring of vendoredHintTitle
  spdxExport: string; // substring of spdxExport
  vulnCount: string; // substring of attnVulns
}> = {
  en: {
    scanOptions: "Advanced scan options",
    identifyVendored: "Detect copied-in open source",
    vendoredHint: "C/C++ embedded source",
    spdxExport: "Export as SPDX",
    vulnCount: "critical or high vulnerabilities",
  },
  ko: {
    scanOptions: "고급 스캔 옵션",
    identifyVendored: "복사해 넣은 오픈소스 탐지",
    vendoredHint: "C/C++ 임베디드 소스",
    spdxExport: "SPDX",
    vulnCount: "취약점",
  },
};

// The EN file keeps its already-published name so no existing doc reference
// breaks. The KO file is the same name with a trailing "-en" (if any) swapped
// for "-ko", or "-ko" appended before the extension otherwise.
function withLang(base: string, lang: Lang): string {
  if (lang === "en") return base;
  return base.replace(/(-en)?\.png$/, "-ko.png");
}

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
    components: 3,
    componentList: [
      { name: "bert-base-uncased", version: "86b5e093", group: "google-bert", purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093", type: "machine-learning-model", licenses: ["Apache-2.0"], assessment: "review", assessmentAxes: "license,security,datasets", hfScanStatus: "safe", weightFormats: "safetensors" },
      { name: "wikipedia", version: "", group: "", purl: "", type: "data", licenses: ["cc-by-sa-4.0"], assessment: "conditional" },
      { name: "bookcorpus", version: "", group: "", purl: "", type: "data", licenses: [], assessment: "review" },
    ],
    assessCounts: { ok: 0, conditional: 0, caution: 0, review: 1 },
  },
};
// A resolved ML-BOM the way enrich-aibom.sh + assess-ai-risk.sh leave it: the
// model carries its file-security scan result and its assessment verdicts, and
// each referenced dataset is a standalone `data` component with its own grade.
// bert-base-uncased is Apache-2.0 (license ok) with safe, safetensors weights
// (security ok); one dataset declares no license, so the datasets axis — and
// therefore the overall verdict — is review, the guide's own worked point.
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
      properties: [
        { name: "openness:weights", value: "open-weight" },
        { name: "openness:training-data", value: "declared-unverified" },
        { name: "bomlens:hf:scan:status", value: "safe" },
        { name: "bomlens:weights:formats", value: "safetensors" },
        { name: "bomlens:assessment:axes", value: "license,security,datasets" },
        { name: "bomlens:assessment:license", value: "ok" },
        { name: "bomlens:assessment:security", value: "ok" },
        { name: "bomlens:assessment:datasets", value: "review" },
        { name: "bomlens:assessment:overall", value: "review" },
        { name: "bomlens:assessment:reasons", value: "license Apache-2.0: Permissive open-source license (ok); file security: HuggingFace scan reports all files safe (ok); datasets: 2 referenced, worst review (bookcorpus)" },
      ],
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
    {
      type: "data", "bom-ref": "dataset:huggingface/wikipedia", name: "wikipedia",
      licenses: [{ license: { name: "cc-by-sa-4.0" } }], hashes: [{ alg: "SHA-256", content: "b".repeat(64) }],
      externalReferences: [{ type: "distribution", url: "https://huggingface.co/datasets/wikipedia" }],
      data: [{ type: "dataset", name: "wikipedia", contents: { url: "https://huggingface.co/datasets/wikipedia" } }],
      properties: [
        { name: "bomlens:dataset:collectedBy", value: "huggingface" },
        { name: "bomlens:assessment:license", value: "conditional" },
        { name: "bomlens:assessment:overall", value: "conditional" },
      ],
    },
    {
      type: "data", "bom-ref": "dataset:huggingface/bookcorpus", name: "bookcorpus",
      externalReferences: [{ type: "distribution", url: "https://huggingface.co/datasets/bookcorpus" }],
      data: [{ type: "dataset", name: "bookcorpus", contents: { url: "https://huggingface.co/datasets/bookcorpus" } }],
      properties: [
        { name: "bomlens:dataset:collectedBy", value: "huggingface" },
        { name: "bomlens:assessment:license", value: "review" },
        { name: "bomlens:assessment:overall", value: "review" },
      ],
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
    // advanced-options section has rendered. It sits inside the collapsed
    // disclosure (the default state the guide should show), so wait for
    // attachment, not visibility.
    await page.getByText(/SCANOSS/).first().waitFor({ state: "attached" });
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
// Section images: content-only `main` screenshots (1040x664 at default vp).
// ===========================================================================

for (const lang of ["en", "ko"] as Lang[]) {
  const s = STR[lang];

  test(`@capture overview section (content) - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
    await runScan(page, "demo", "1.0");
    await page.locator("main h1").waitFor();
    await page.getByText(new RegExp(s.vulnCount)).first().waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.locator("main").screenshot({ path: `${IMAGES}/${withLang("app-results.png", lang)}` });
  });

  test(`@capture components section (content) - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
    await runScan(page, "demo", "1.0");
    await NAV(page, "components").click();
    await page.getByText("openssl", { exact: true }).first().waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.locator("main").screenshot({ path: `${IMAGES}/${withLang("web-ui-components.png", lang)}` });
  });

  test(`@capture vulnerabilities section (content) - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
    await runScan(page, "demo", "1.0");
    await NAV(page, "vulnerabilities").click();
    await page.getByText("9.8", { exact: true }).waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.locator("main").screenshot({ path: `${IMAGES}/${withLang("web-ui-vulns.png", lang)}` });
  });

  test(`@capture dependencies section (content) - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: DONE, sbom: SBOM });
    await runScan(page, "demo", "1.0");
    await NAV(page, "dependencies").click();
    // The tree view shows the openssl → zlib relationship deterministically (the
    // graph is a Cytoscape canvas that does not snapshot stably).
    await page.getByTestId("deps-view-tree").click();
    await page.getByText("openssl").first().waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.locator("main").screenshot({ path: `${IMAGES}/${withLang("web-ui-dependencies.png", lang)}` });
  });

  test(`@capture licenses section (content) - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: LIC_DONE });
    await runScan(page, "lic", "1.0");
    await NAV(page, "licenses").click();
    await page.getByText("some-llama-model").waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.locator("main").screenshot({ path: `${IMAGES}/${withLang("web-ui-licenses.png", lang)}` });
  });

  test(`@capture artifacts section (content) - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    // spdxExport on and no `.spdx.json` in the results, so the SBOM card shows the
    // export action the guide points UI users at.
    await stub(page, { firmware: false, scanoss: false, docker: true, spdxExport: true }, { done: DONE });
    await runScan(page, "demo", "1.0");
    await NAV(page, "artifacts").click();
    await page.getByRole("button", { name: new RegExp(s.spdxExport) }).waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.locator("main").screenshot({ path: `${IMAGES}/${withLang("web-ui-artifacts.png", lang)}` });
  });

  test(`@capture models section (content) - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: AI_DONE, sbom: AI_SBOM });
    await runScan(page, "model", "1.0");
    await NAV(page, "models").click();
    await page.getByText("bert-base-uncased").first().waitFor();
    await killAnim(page);
    await settleMain(page);
    await page.locator("main").screenshot({ path: `${IMAGES}/${withLang("web-ui-models.png", lang)}` });
  });
}

// ===========================================================================
// --identify-vendored guide images (route fixed to #/new).
// ===========================================================================

for (const lang of ["en", "ko"] as Lang[]) {
  const s = STR[lang];

  test(`@capture advanced toggle - ${lang}`, async ({ page }) => {
    // The expanded disclosure below can run taller than the default 720px
    // viewport (it already does in English). An element screenshot taller
    // than the viewport makes Playwright scroll and stitch the capture, and
    // that stitching has come out with a blank band at the bottom for this
    // element before, so a plain height bump avoids needing more than one
    // scroll position in the first place.
    await page.setViewportSize({ width: 1280, height: 1400 });
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: true, docker: true });
    await page.goto("/#/new");
    await page.locator("#project").waitFor();
    await killAnim(page);
    // The vendored-ID toggle lives inside the collapsed "Advanced scan options"
    // disclosure, expand it and capture the whole open section (summary +
    // toggle) so the guide shows users where to find it, not just the switch.
    await page.getByText(s.scanOptions).click();
    const toggle = page.getByText(s.identifyVendored);
    await toggle.waitFor({ state: "visible" });
    const section = toggle.locator("xpath=ancestor::details[1]");
    await section.screenshot({
      path: `${IMAGES}/${withLang("web-ui-identify-vendored-en.png", lang)}`,
    });
  });

  test(`@capture result banner - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: true, docker: true }, { done: VENDORED_DONE });
    await runScan(page, "trelay", "26.4.0");
    // The banner is the amber rounded-md box that holds the suggestion text.
    const banner = page
      .locator("div.rounded-md")
      .filter({ hasText: s.vendoredHint })
      .first();
    await banner.waitFor({ state: "visible" });
    await killAnim(page);
    await settleMain(page);
    await banner.screenshot({ path: `${IMAGES}/${withLang("web-ui-vendored-banner-en.png", lang)}` });
  });

  test(`@capture vendored badge in components table - ${lang}`, async ({ page }) => {
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: true, docker: true }, { done: VENDORED_DONE });
    await runScan(page, "trelay", "26.4.0");
    await NAV(page, "components").click();
    const table = page.locator("table").first();
    await table.waitFor({ state: "visible" });
    await killAnim(page);
    await table.screenshot({ path: `${IMAGES}/${withLang("web-ui-vendored-badge-en.png", lang)}` });
  });
}

// An analyzed AI SBOM whose conformance report carries the base + G7 checks, so
// the Conformance section shows the verdict with the G7 advisory sub-block.
// Full-window 1040x664, matching the other guide screenshots.
const CONFORMANCE_DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "model_1.0",
  // The Conformance section only exists for a submitted document under
  // review (nav.ts gates it on this artifact, not on `mode`).
  results: [
    { name: "model_1.0_bom.json", size: 200 },
    { name: "model_1.0_input.json", size: 100 },
  ],
  security: null,
  conformance: {
    result: "pass",
    format: "CycloneDX",
    // labelKo/detailKo mirror what the real pipeline ships: g7-* labels come
    // from docker/lib/g7-registry.json's label_ko (verified present for every
    // element there); detailKo for the base checks and the "N found" / "N/N
    // model component(s)" shapes matches docker/lib/i18n/report-strings.ko.json's
    // ldetail() vocabulary in validate-sbom.sh. Without these two fields the KO
    // capture would render this section in English, same as EN.
    checks: [
      { id: "timestamp", label: "Timestamp present", labelKo: "타임스탬프 있음", required: true, status: "pass", detail: "1 found", detailKo: "1개 발견" },
      { id: "license", label: "License coverage (recommended)", labelKo: "라이선스 포함률 (권장)", required: false, status: "warn", detail: "0%" },
      { id: "g7-meta-author", label: "SBOM author", labelKo: "SBOM 작성자", required: false, status: "pass", detail: "author present", detailKo: "작성자 있음", cluster: "metadata", source: "auto" },
      { id: "g7-meta-timestamp", label: "SBOM timestamp", labelKo: "SBOM 타임스탬프", required: false, status: "pass", detail: "1 found", detailKo: "1개 발견", cluster: "metadata", source: "auto" },
      { id: "g7-slp-data-flow", label: "System data flow", labelKo: "시스템 데이터 흐름", required: false, status: "warn", detail: "no automated source", detailKo: "자동 확인 수단 없음", cluster: "slp", source: "na" },
      { id: "g7-model-id", label: "Model identifier", labelKo: "모델 식별자", required: false, status: "pass", detail: "1/1 model component(s)", detailKo: "모델 구성요소 1/1개", cluster: "models", source: "auto", evidence: ["pkg:huggingface/google-bert/bert-base-uncased@86b5e093"] },
      { id: "g7-model-license", label: "Model license", labelKo: "모델 라이선스", required: false, status: "pass", detail: "1/1 model component(s)", detailKo: "모델 구성요소 1/1개", cluster: "models", source: "auto", evidence: ["Apache-2.0"] },
      { id: "g7-model-card", label: "Model properties (model card)", labelKo: "모델 속성 (모델 카드)", required: false, status: "pass", detail: "1/1 model component(s)", detailKo: "모델 구성요소 1/1개", cluster: "models", source: "auto" },
      { id: "g7-model-hash-value", label: "Model hash value", labelKo: "모델 해시 값", required: false, status: "warn", detail: "0/1 model component(s)", detailKo: "모델 구성요소 0/1개", cluster: "models", source: "auto" },
      { id: "g7-model-openness", label: "Model license — openness (weight/architecture/data/training)", labelKo: "모델 라이선스 — 공개성 (가중치/구조/데이터/학습)", required: false, status: "warn", detail: "not declared in the SBOM", detailKo: "SBOM에 선언되지 않음", cluster: "models", source: "inferred" },
      { id: "g7-ds-name", label: "Dataset name", labelKo: "데이터셋 이름", required: false, status: "pass", detail: "2 dataset reference(s)", detailKo: "데이터셋 참조 2개", cluster: "dp", source: "auto" },
    ],
  },
  sbom: {
    components: 1,
    componentList: [
      { name: "bert-base-uncased", version: "86b5e093", group: "google-bert", purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093", type: "machine-learning-model", licenses: ["Apache-2.0"] },
    ],
  },
};

// docs/reference/ui.md's "SBOM Validation" paragraph describes this screen as
// showing the verdict, the base CycloneDX checks, and the G7 sub-block
// "grouped by the seven G7 clusters" as one whole, not a subset filtered
// down to what still needs fixing. The panel itself opens filtered to
// "actionable" whenever any check qualifies (ConformancePanel.tsx), so the
// capture has to reset that filter to match what the doc describes.
const G7_WAIT: Record<Lang, string> = { en: "SBOM author", ko: "SBOM 작성자" };

for (const lang of ["en", "ko"] as Lang[]) {
  test(`@capture conformance section - ${lang}`, async ({ page }) => {
    await page.setViewportSize({ width: 1040, height: 664 });
    await seedLang(page, lang);
    await stub(page, { firmware: false, scanoss: false, docker: true }, { done: CONFORMANCE_DONE });
    await runScan(page, "model", "1.0");
    await NAV(page, "conformance").click();
    // Reset the default "actionable" filter to "all" (the chip toggles off
    // when clicked a second time). Scoped to main: the top bar's EN/KO
    // toggle is also a pressed button. The chip only exists once the
    // conformance data has rendered, so wait for it before deciding whether
    // to click it (count() alone does not wait).
    const activeKindChip = page.locator("main").getByRole("button", { pressed: true }).first();
    try {
      await activeKindChip.waitFor({ state: "visible", timeout: 5000 });
      await activeKindChip.click();
    } catch {
      // No kind filter defaulted on (no actionable check in this stub); nothing to toggle.
    }
    // A cluster with no actionable check of its own (metadata, holding "SBOM
    // author") stays collapsed even under the "all" filter, since each
    // CheckGroup only auto-opens when the filter is non-null or it contains
    // an actionable check. Force every disclosure open directly so the
    // screenshot shows every cluster, matching what the doc describes.
    await page.getByText(G7_WAIT[lang]).first().waitFor({ state: "attached" });
    await page.locator("main details").evaluateAll((els) => {
      for (const el of els) (el as HTMLDetailsElement).open = true;
    });
    await page.getByText(G7_WAIT[lang]).first().waitFor({ state: "visible" });
    await killAnim(page);
    await settleMain(page);
    await page.screenshot({ path: `${IMAGES}/${withLang("web-ui-g7.png", lang)}` });
  });
}
