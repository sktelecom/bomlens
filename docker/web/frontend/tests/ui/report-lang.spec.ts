// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

/**
 * The scan request carries whichever language the shell is showing right now
 * (`lang`, read server-side as REPORT_LANG), so a web UI scan's own generated
 * prose (conformance/security/AI-profile reports, model/dataset risk
 * assessment reasons) renders in that language, the same as `--lang` on the
 * CLI. The backend is stubbed; server.py's own REPORT_LANG wiring (both the
 * in-process env and the sibling docker-run path) is covered by
 * tests/test-web-ui.sh.
 */

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

async function stub(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
}

function seedLang(page: Page, lang: "en" | "ko") {
  return page.addInitScript((l) => {
    localStorage.setItem("sbom.lang", l);
  }, lang);
}

test("running with the shell in Korean sends lang=ko on the scan request", async ({ page }) => {
  await seedLang(page, "ko");
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /스캔 실행/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("lang")).toBe("ko");
});

test("running with the shell in English sends lang=en on the scan request", async ({ page }) => {
  await seedLang(page, "en");
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("lang")).toBe("en");
});
