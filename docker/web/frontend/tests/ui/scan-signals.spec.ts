// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// Signals a result carries about its own trustworthiness. Both of these are
// things the reader cannot infer from the numbers on screen:
//
//   - a scan that found nothing looks like "nothing to worry about" when it
//     almost always means the scan had nothing to read (measured: the same
//     folder yields 39 components with a requirements.txt and 0 without it);
//   - versions the resolver picked at scan time look exactly like versions
//     someone installed, and the vulnerability count inherits that basis.

type Caps = { firmware: boolean; scanoss: boolean; docker: boolean };

async function stub(page: Page, caps: Caps, done?: unknown) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  if (done) {
    await page.route("**/scan-stream**", (r) =>
      r.fulfill({
        contentType: "text/event-stream",
        body: `event: done\ndata: ${JSON.stringify(done)}\n\n`,
      }),
    );
  }
}

const base = {
  ok: true,
  id: "testapp_1.0",
  results: [{ name: "testapp_1.0_bom.json", size: 1234 }],
  security: null,
  conformance: null,
};

/** A source scan that read no manifest: zero components, nothing else wrong. */
const EMPTY_SOURCE = {
  ...base,
  mode: "SOURCE",
  sbom: { components: 0, componentList: [] },
};

/** The same scan with a manifest present — the banner must stay away. */
const NORMAL_SOURCE = {
  ...base,
  mode: "SOURCE",
  sbom: {
    components: 1,
    componentList: [
      { name: "flask", version: "3.0.0", group: "", purl: "pkg:pypi/flask", type: "library", licenses: ["BSD-3-Clause"] },
    ],
  },
};

/** An AI model SBOM. The server folds a model root into the component list, so
 *  what the UI receives carries the model itself — the warning would be wrong
 *  here even though the source SBOM's components[] was empty. */
const AI_MODEL = {
  ...base,
  mode: "AIBOM",
  id: "bert_1.0",
  sbom: {
    components: 1,
    componentType: "machine-learning-model",
    componentList: [
      { name: "bert-base-uncased", version: "86b5e093", group: "google-bert", purl: "pkg:huggingface/google-bert/bert-base-uncased", type: "machine-learning-model", licenses: ["Apache-2.0"] },
    ],
  },
};

/** A dataset scan: no model anywhere, and the item sits in the document root. */
const DATASET = {
  ...base,
  mode: "DATASET",
  id: "figshare_1.0",
  sbom: {
    components: 1,
    componentType: "data",
    componentList: [
      { name: "SS-Cu-Ti study dataset", version: "v1", group: "", purl: "", type: "data", licenses: ["CC-BY-4.0"] },
    ],
  },
};

async function fillAndRun(page: Page) {
  await page.fill("#project", "testapp");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("a scan with no components warns instead of reading as clean", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, EMPTY_SOURCE);
  await page.goto("/#/new");
  await fillAndRun(page);

  const banner = page.getByTestId("zero-components");
  await expect(banner).toBeVisible();
  // The wording has to say it is a warning, and say what to check — a bare
  // "0 components" is what the reader already saw.
  await expect(banner).toContainText(/warning, not a clean result/i);
  await expect(banner).toContainText(/requirements\.txt/);
});

test("a scan that found components shows no such warning", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, NORMAL_SOURCE);
  await page.goto("/#/new");
  await fillAndRun(page);

  await expect(page.getByTestId("zero-components")).toHaveCount(0);
});

test("a dataset scan opens the AI section instead of warning about it", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, DATASET);
  await page.goto("/#/new");
  await fillAndRun(page);

  await expect(page.getByTestId("zero-components")).toHaveCount(0);
  // The rail's AI group is what makes the dataset reachable at all.
  await expect(page.getByRole("link", { name: /Models/ }).first()).toBeVisible();
});

test("an AI model scan is not warned about its empty component list", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, AI_MODEL);
  await page.goto("/#/new");
  await fillAndRun(page);

  await expect(page.getByTestId("zero-components")).toHaveCount(0);
});

// 20-b: versions the resolver chose, not versions anyone installed. Measured on
// a real repository: 113 components all resolved to the newest release, and the
// 3 vulnerabilities found were measured against those, not against whatever an
// older checkout has installed.
const UNPINNED = {
  ...base,
  mode: "SOURCE",
  sbom: {
    components: 2,
    versionPinning: "unpinned",
    componentList: [
      { name: "torch", version: "2.12.1", group: "", purl: "pkg:pypi/torch", type: "library", licenses: ["BSD-3-Clause"] },
      { name: "numpy", version: "2.5.2", group: "", purl: "pkg:pypi/numpy", type: "library", licenses: ["BSD-3-Clause"] },
    ],
  },
};

const PINNED = {
  ...base,
  mode: "SOURCE",
  sbom: {
    components: 1,
    versionPinning: "pinned",
    componentList: [
      { name: "flask", version: "3.0.0", group: "", purl: "pkg:pypi/flask", type: "library", licenses: ["BSD-3-Clause"] },
    ],
  },
};

test("a scan of an unpinned tree says its versions were resolved at scan time", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, UNPINNED);
  await page.goto("/#/new");
  await fillAndRun(page);

  const notice = page.getByTestId("version-pinning");
  await expect(notice).toBeVisible();
  // It has to say the vulnerability result inherits the same basis — that is the
  // part a reader acts on.
  await expect(notice).toContainText(/vulnerability result/i);
});

test("a pinned tree gets no such notice", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, PINNED);
  await page.goto("/#/new");
  await fillAndRun(page);

  await expect(page.getByTestId("version-pinning")).toHaveCount(0);
});

test("a scan that could not be judged says nothing about pinning", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, NORMAL_SOURCE);
  await page.goto("/#/new");
  await fillAndRun(page);

  await expect(page.getByTestId("version-pinning")).toHaveCount(0);
});
