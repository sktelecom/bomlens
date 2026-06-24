import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * Shell gates for the new UI behind `?ui=next`:
 *  - accessibility (axe) + visual regression for the idle "New scan" screen,
 *    across light/dark × en/ko;
 *  - a stubbed end-to-end scan that proves the result content moved from tabs
 *    into the left-rail sections (Phase 1), with scan-type/data adaptation.
 *
 * Theme and language are seeded into localStorage before the app boots so each
 * combination is deterministic. Visual snapshots are tagged @visual and run in
 * the pinned Playwright container so pixels are stable.
 */

type Theme = "light" | "dark";
type Lang = "en" | "ko";

async function openShell(page: Page, theme: Theme, lang: Lang) {
  await page.addInitScript(
    ([t, l]) => {
      localStorage.setItem("sbom.theme", t);
      localStorage.setItem("sbom.lang", l);
    },
    [theme, lang],
  );
  await page.goto("/?ui=next");
  await page.getByRole("navigation").first().waitFor();
}

const COMBOS: Array<{ theme: Theme; lang: Lang }> = [
  { theme: "light", lang: "en" },
  { theme: "dark", lang: "en" },
  { theme: "light", lang: "ko" },
  { theme: "dark", lang: "ko" },
];

for (const { theme, lang } of COMBOS) {
  test(`idle shell has no axe violations — ${theme}/${lang}`, async ({ page }) => {
    await openShell(page, theme, lang);
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

// A finished scan with an SBOM, a ScanCode artifact and vulnerabilities — enough
// to exercise data-gated rail sections (Dependencies, Source tree) and counts.
const DONE = {
  ok: true,
  mode: "SOURCE",
  results: [
    { name: "demo_1.0_bom.json", size: 100 },
    { name: "demo_1.0_scancode.json", size: 50 },
  ],
  security: {
    CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 2,
    vulnerabilities: [
      { id: "CVE-2024-0001", severity: "CRITICAL", pkg: "openssl", installed: "3.0.0", fixed: "3.0.1", title: "buffer overflow", cvss: 9.8, cvssVector: "CVSS:3.1/AV:N/AC:L", description: "A heap buffer overflow in the TLS handshake.", url: "https://example.test/CVE-2024-0001" },
      { id: "CVE-2024-0002", severity: "HIGH", pkg: "zlib", installed: "1.2.0", fixed: "1.2.1", title: "oob read", cvss: 7.5 },
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

async function stubAndRun(page: Page) {
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
  await page.goto("/?ui=next");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("scan results render in the rail sections, adapted to scan type", async ({ page }) => {
  await stubAndRun(page);

  // Result sections appear in the rail; AI-only ones stay hidden for a SOURCE scan.
  await expect(page.getByRole("button", { name: /^Overview/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Components/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Vulnerabilities/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Dependencies/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Source tree/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Artifacts/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Models & datasets/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /G7 conformance/ })).toHaveCount(0);

  // Overview leads; switching to Components shows the table content.
  await page.getByRole("button", { name: /^Components/ }).click();
  await expect(page.getByRole("button", { name: /^Components/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();

  // Vulnerabilities section shows the CVE rows.
  await page.getByRole("button", { name: /^Vulnerabilities/ }).click();
  await expect(page.getByText("CVE-2024-0001").first()).toBeVisible();
});

test("Overview leads with needs-attention and jumps into sections", async ({ page }) => {
  await stubAndRun(page);

  // Needs-attention surfaces the critical/high vulnerabilities (1+1) and links out.
  const attention = page.getByRole("button", { name: /critical or high vulnerabilities/ });
  await expect(attention).toBeVisible();
  await attention.click();
  await expect(page.getByRole("button", { name: /^Vulnerabilities/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("CVE-2024-0001").first()).toBeVisible();

  // Back to Overview; a jump card navigates into Components.
  await page.getByRole("button", { name: /^Overview/ }).click();
  await page.getByRole("button", { name: "View Components" }).click();
  await expect(page.getByRole("button", { name: /^Components/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
});

test("overview has no axe violations", async ({ page }) => {
  await stubAndRun(page);
  await expect(page.getByText(/critical or high vulnerabilities/)).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("overview section matches baseline — light/en @visual", async ({ page }) => {
  await stubAndRun(page);
  await expect(page.getByText(/critical or high vulnerabilities/)).toBeVisible();
  await expect(page.locator("main")).toHaveScreenshot("overview-light-en.png", {
    animations: "disabled",
  });
});

// An AI scan: the SBOM carries a machine-learning-model component, so the rail
// exposes Models & Datasets. /file returns the matching ML-BOM (CycloneDX 1.7).
const AI_DONE = {
  ok: true,
  mode: "ANALYZE",
  results: [{ name: "model_1.0_bom.json", size: 200 }],
  security: null,
  conformance: {
    result: "pass",
    format: "CycloneDX",
    checks: [
      { id: "timestamp", label: "Timestamp present", required: true, status: "pass", detail: "1 found" },
      { id: "license", label: "License coverage (recommended)", required: false, status: "warn", detail: "0%" },
      { id: "g7-model-id", label: "G7 model identifier (PURL/CPE)", required: false, status: "pass", detail: "1/1 model component(s)" },
      { id: "g7-model-license", label: "G7 model license", required: false, status: "pass", detail: "1/1 model component(s)" },
      { id: "g7-model-card", label: "G7 model card (architecture/training parameters)", required: false, status: "pass", detail: "1/1 model component(s)" },
      { id: "g7-model-hash", label: "G7 model integrity (hashes)", required: false, status: "warn", detail: "0/1 model component(s)" },
      { id: "g7-datasets", label: "G7 dataset provenance (datasets referenced)", required: false, status: "pass", detail: "2 dataset reference(s)" },
      { id: "g7-openness", label: "G7 model openness (weight/architecture/data/training)", required: false, status: "warn", detail: "not declared in the SBOM" },
    ],
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

async function stubAiAndRun(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(AI_SBOM) }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(AI_DONE)}\n\n` }),
  );
  await page.goto("/?ui=next");
  await page.fill("#project", "model");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("AI scan exposes Models & Datasets with the model card", async ({ page }) => {
  await stubAiAndRun(page);
  await expect(page.getByRole("button", { name: /Models & datasets/ })).toBeVisible();
  await page.getByRole("button", { name: /Models & datasets/ }).click();

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

test("models section matches baseline — light/en @visual", async ({ page }) => {
  await stubAiAndRun(page);
  await page.getByRole("button", { name: /Models & datasets/ }).click();
  await expect(page.getByText("bert-base-uncased").first()).toBeVisible();
  await expect(page.locator("main")).toHaveScreenshot("models-light-en.png", {
    animations: "disabled",
  });
});

test("AI scan exposes G7 conformance with present/advisory split", async ({ page }) => {
  await stubAiAndRun(page);
  await expect(page.getByRole("button", { name: /G7 conformance/ })).toBeVisible();
  await page.getByRole("button", { name: /G7 conformance/ }).click();

  // Headline tally comes straight from the check statuses: 4 of 6 present.
  await expect(page.getByText("4/6 present")).toBeVisible();
  await expect(page.getByText(/2 advisory/)).toBeVisible();
  // Base checks are split out under their own heading.
  await expect(page.getByText("Format conformance")).toBeVisible();
  await expect(page.getByText("G7 model openness (weight/architecture/data/training)")).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("g7 section matches baseline — light/en @visual", async ({ page }) => {
  await stubAiAndRun(page);
  await page.getByRole("button", { name: /G7 conformance/ }).click();
  await expect(page.getByText("4/6 present")).toBeVisible();
  await expect(page.locator("main")).toHaveScreenshot("g7-light-en.png", {
    animations: "disabled",
  });
});

test("Dependencies tree marks vulnerable packages and direct deps", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Dependencies/ }).click();
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

test("dependencies tree matches baseline — light/en @visual", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Dependencies/ }).click();
  await page.getByRole("button", { name: "Tree", exact: true }).click();
  await expect(page.getByText("openssl").first()).toBeVisible();
  await expect(page.locator("main")).toHaveScreenshot("dependencies-tree-light-en.png", {
    animations: "disabled",
  });
});

test("Vulnerabilities table shows CVSS, sorts, and expands a row", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Vulnerabilities/ }).click();

  // CVSS is a column now, with the scores visible (default: most severe first).
  await expect(page.getByRole("button", { name: "CVSS", exact: true })).toBeVisible();
  await expect(page.getByText("9.8", { exact: true })).toBeVisible();
  await expect(page.getByText("7.5", { exact: true })).toBeVisible();

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

test("vulnerabilities section matches baseline — light/en @visual", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Vulnerabilities/ }).click();
  await expect(page.getByText("9.8", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toHaveScreenshot("vulnerabilities-light-en.png", {
    animations: "disabled",
  });
});

test("Components table shows Scope/Risk and filters on the full set", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Components/ }).click();
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

test("components section matches baseline — light/en @visual", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Components/ }).click();
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toHaveScreenshot("components-light-en.png", {
    animations: "disabled",
  });
});

test("results view has no axe violations", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Components/ }).click();
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
