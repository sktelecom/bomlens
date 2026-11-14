// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * The Artifacts screen (one row per kind of generated file) and the file
 * viewer dialog. The backend is stubbed, so each control is checked against
 * what it sends and what the screen shows afterwards.
 */

const ID = "demo_1.0";

const RESULTS = [
  { name: "demo_1.0_risk-report.html", size: 7100 },
  { name: "demo_1.0_risk-report.md", size: 1900 },
  { name: "demo_1.0_bom.json", size: 2048 },
  { name: "demo_1.0_bom.json.sig", size: 512 },
  { name: "demo_1.0_NOTICE.txt", size: 1200 },
  { name: "demo_1.0_security.json", size: 900 },
  { name: "demo_1.0_security_epss.json", size: 300 },
  { name: "demo_1.0_component-versions.template.csv", size: 80 },
];

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: ID,
  results: RESULTS,
  security: null,
  conformance: null,
  sbom: {
    components: 1,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"] },
    ],
  },
};

const REPORT_HTML =
  "<html><body><h1 id='report-title'>Risk report</h1><p>Body of the report</p>" +
  "<a id='jump' href='#lic-1'>Jump to licence</a><a id='ext' href='http://example.test/ref' target='_blank'>Reference</a>" +
  "<div style='height:3000px'></div><h2 id='lic-1'>Licence one</h2></body></html>";

async function stub(page: Page, done: Record<string, unknown> = DONE, caps: Record<string, unknown> = {}) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdxExport: true, spdx3: false, ...caps }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${ID}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }),
  );
  await page.route("**/file?**", (r) => {
    const name = new URL(r.request().url()).searchParams.get("name") ?? "";
    if (name.endsWith(".html")) return r.fulfill({ contentType: "text/html", body: REPORT_HTML });
    if (name.endsWith(".json")) return r.fulfill({ contentType: "application/json", body: '{"bomFormat":"CycloneDX","components":[]}' });
    return r.fulfill({ contentType: "text/plain", body: "NOTICE text body" });
  });
}

async function openScreen(page: Page, lang: "en" | "ko" = "en", theme: "light" | "dark" = "light") {
  await page.addInitScript(
    ([l, th]) => {
      localStorage.setItem("sbom.lang", l);
      localStorage.setItem("i18nextLng", l);
      localStorage.setItem("sbom.theme", th);
    },
    [lang, theme],
  );
  await page.goto(`/?ui=next#/scan/${ID}/artifacts`);
  await page.getByTestId("result-meta").waitFor();
  await waitForSettled(page.locator("main"));
}

test("one row per kind, with a download button per format and the signature", async ({ page }) => {
  await stub(page);
  await openScreen(page);

  const rows = page.locator('[data-testid^="artifact-"]:not([data-testid="artifact-summary"]):not([data-testid="artifact-unlisted"])');
  await expect(rows.first()).toBeVisible();
  // Risk report first (rank order), then the SBOM, notice, security, version template.
  await expect(rows.locator("h2")).toHaveText([
    "Open-source risk report",
    "SBOM (CycloneDX)",
    "Open-source notice",
    "Security report",
    "Component versions template",
  ]);

  const risk = page.getByTestId("artifact-riskReport");
  await expect(risk.getByRole("link", { name: /^HTML/ })).toHaveAttribute("href", `/file?id=${ID}&name=demo_1.0_risk-report.html`);
  await expect(risk.getByRole("link", { name: /^HTML/ })).toHaveAttribute("download", "demo_1.0_risk-report.html");
  await expect(risk.getByRole("link", { name: /^MD/ })).toContainText("1.9 KB");
  await expect(risk).toContainText("demo_1.0_risk-report");

  const sbom = page.getByTestId("artifact-sbom");
  await expect(sbom.getByText("Signed", { exact: true })).toBeVisible();
  await expect(sbom.getByRole("link", { name: /^SIG/ })).toHaveAttribute("href", `/file?id=${ID}&name=demo_1.0_bom.json.sig`);
  await expect(sbom.getByRole("link", { name: /^JSON/ })).toBeVisible();
});

test("the header line counts rows, size and files, and names the files no row offers", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const line = page.getByTestId("artifact-summary");
  await expect(line).toContainText("5 artifacts");
  await expect(line).toContainText("(8 files)");
  const rest = page.getByTestId("artifact-unlisted");
  await expect(rest).toContainText("1 file only in the ZIP");
  await rest.locator("summary").click();
  await expect(rest).toContainText("demo_1.0_security_epss.json");
  await expect(rest).not.toContainText("demo_1.0_bom.json.sig");
});

test("Download all sits in the page header and downloads the ZIP", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const all = page.getByRole("link", { name: "Download all (ZIP)" });
  await expect(all).toHaveAttribute("href", `/download-all?id=${ID}`);
  await all.evaluate((a) => a.addEventListener("click", (e) => e.preventDefault()));
  await all.click();
  await expect(page.getByText("Download started")).toBeVisible();
});

test("a download button says so with a notice", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const link = page.getByTestId("artifact-notice").getByRole("link", { name: /^TXT/ });
  await link.evaluate((a) => a.addEventListener("click", (e) => e.preventDefault()));
  await link.click();
  await expect(page.getByText("Download started")).toBeVisible();
});

test("a CSV template offers View CSV", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const row = page.getByTestId("artifact-componentVersions");
  await expect(row.getByRole("button", { name: "View CSV" })).toBeVisible();
});

test("Copy link puts the file address on the clipboard", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await stub(page);
  await openScreen(page);
  await page.getByTestId("artifact-riskReport").getByRole("button", { name: "Copy link to Open-source risk report" }).click();
  await expect(page.getByText("Link copied")).toBeVisible();
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  expect(clip).toBe(`http://localhost:4192/file?id=${ID}&name=demo_1.0_risk-report.html`);
});

test("Export as SPDX converts, downloads, and adds the file to the row", async ({ page }) => {
  await stub(page);
  let calls = 0;
  await page.route("**/spdx-export?**", (r) => {
    calls += 1;
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: "demo_1.0_bom.spdx.json", results: [...RESULTS, { name: "demo_1.0_bom.spdx.json", size: 4000 }] }),
    });
  });
  await openScreen(page);
  const sbom = page.getByTestId("artifact-sbom");
  const downloaded = page.waitForEvent("download");
  await sbom.getByRole("button", { name: "Export as SPDX 2.3" }).click();
  expect((await downloaded).suggestedFilename()).toBe("demo_1.0_bom.spdx.json");
  expect(calls).toBe(1);
  await expect(sbom.getByRole("link", { name: /^SPDX/ })).toBeVisible();
  // Once the file exists the convert button is gone.
  await expect(sbom.getByRole("button", { name: "Export as SPDX 2.3" })).toHaveCount(0);
  await expect(page.getByTestId("artifact-summary")).toContainText("(9 files)");
});

test("a failed SPDX export says so and keeps the button", async ({ page }) => {
  await stub(page);
  await page.route("**/spdx-export?**", (r) => r.fulfill({ status: 500, body: "x" }));
  await openScreen(page);
  const btn = page.getByTestId("artifact-sbom").getByRole("button", { name: "Export as SPDX 2.3" });
  await btn.click();
  await expect(page.getByText("Could not export SPDX.")).toBeVisible();
  await expect(btn).toBeEnabled();
});

test("the SPDX button is not offered when this server cannot convert", async ({ page }) => {
  await stub(page, DONE, { spdxExport: false });
  await openScreen(page);
  await expect(page.getByRole("button", { name: "Export as SPDX 2.3" })).toHaveCount(0);
});

const AI_DONE = {
  ...DONE,
  mode: "AIBOM",
  results: [
    { name: "demo_1.0_bom.json", size: 2048 },
    { name: "demo_1.0_bom.spdx3.json", size: 3000 },
    { name: "demo_1.0_spdx3-check.json", size: 600 },
    { name: "demo_1.0_ai-declaration.json", size: 700 },
  ],
  spdx3: { draft: true, counts: { missingRequired: 3 }, name: "demo_1.0_bom.spdx3.json", check: "demo_1.0_spdx3-check.json", upToDate: false },
};

test("SPDX 3.0.1 row: draft label, missing count, rebuild and declaration upload", async ({ page }) => {
  await stub(page, AI_DONE, { spdx3: true });
  let rebuilt = 0;
  await page.route("**/spdx3-export?**", (r) => {
    rebuilt += 1;
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: "demo_1.0_bom.spdx3.json", results: AI_DONE.results, spdx3: { ...AI_DONE.spdx3, upToDate: true, draft: false } }),
    });
  });
  await page.route("**/ai-declaration?**", async (r) => {
    const body = r.request().postDataJSON();
    if (body.refuse) {
      return r.fulfill({ status: 422, contentType: "application/json", body: JSON.stringify({ error: "refused", reasons: ["wrong model"] }) });
    }
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: "demo_1.0_bom.spdx3.json", results: AI_DONE.results, spdx3: { ...AI_DONE.spdx3, upToDate: true, draft: false } }),
    });
  });
  await openScreen(page);

  const row = page.getByTestId("artifact-spdx3");
  await expect(row.getByText("Draft", { exact: true })).toBeVisible();
  await expect(row).toContainText("3 required");
  await expect(row.getByRole("link", { name: /^Check/ }).first()).toBeVisible();

  const down = page.waitForEvent("download");
  await row.getByRole("button", { name: /Rebuild/ }).click();
  await down;
  expect(rebuilt).toBe(1);
  await expect(row.getByText("Complete", { exact: true })).toBeVisible();
  await expect(row.getByRole("button", { name: /Rebuild/ })).toHaveCount(0);

  const decl = page.getByTestId("artifact-aiDeclaration");
  const chooser = page.waitForEvent("filechooser");
  await decl.getByRole("button", { name: "Upload declaration" }).click();
  (await chooser).setFiles({ name: "d.json", mimeType: "application/json", buffer: Buffer.from("not json") });
  await expect(page.getByText("That file is not JSON.")).toBeVisible();

  const chooser2 = page.waitForEvent("filechooser");
  await decl.getByRole("button", { name: "Upload declaration" }).click();
  (await chooser2).setFiles({ name: "d.json", mimeType: "application/json", buffer: Buffer.from('{"refuse":true}') });
  await expect(page.getByText("The declaration was refused: wrong model")).toBeVisible();
});

test("no results shows the empty state", async ({ page }) => {
  await stub(page, { ...DONE, results: [] });
  await openScreen(page);
  await expect(page.getByTestId("empty-state")).toContainText("No artifacts were generated.");
  await expect(page.getByRole("link", { name: "Download all (ZIP)" })).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// The viewer
// ---------------------------------------------------------------------------

test("an HTML report opens in a frame that runs no script", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const opener = page.getByTestId("artifact-riskReport").getByRole("button", { name: "View HTML" });
  await opener.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog).toHaveAccessibleName("demo_1.0_risk-report.html");
  const frame = dialog.locator("iframe");
  await expect(frame).toHaveAttribute("sandbox", "allow-popups allow-popups-to-escape-sandbox");
  await expect(frame).toHaveAttribute("src", `/file?id=${ID}&name=demo_1.0_risk-report.html`);
  await expect(page.frameLocator('iframe[title="demo_1.0_risk-report.html"]').getByText("Body of the report")).toBeVisible();
  // The dialog scales in; measure it once it has settled.
  await waitForSettled(dialog);
  const box = await dialog.boundingBox();
  const vp = page.viewportSize()!;
  expect(Math.round(box!.width)).toBe(Math.min(1200, Math.round(vp.width * 0.95)));
  expect(Math.round(box!.height)).toBe(Math.round(vp.height * 0.8));
  // The report gets the dialog's whole body, not a default 150px frame.
  const frameBox = await frame.boundingBox();
  expect(frameBox!.height).toBeGreaterThan(400);
});

test("in an HTML report an anchor stays in the report and a new-tab link opens", async ({ page, context }) => {
  await stub(page);
  await context.route("http://example.test/**", (r) => r.fulfill({ contentType: "text/html", body: "<p>ref</p>" }));
  await openScreen(page);
  await page.getByTestId("artifact-riskReport").getByRole("button", { name: "View HTML" }).click();
  const frame = page.frameLocator('iframe[title="demo_1.0_risk-report.html"]');
  await frame.locator("#jump").click();
  await expect(frame.locator("#report-title")).toBeAttached();
  await expect(page).toHaveURL(new RegExp("#/scan/demo_1.0/artifacts$"));
  await expect(page.getByRole("dialog")).toBeVisible();
  const popup = context.waitForEvent("page");
  await frame.locator("#ext").click();
  const opened = await popup;
  await expect.poll(() => opened.url()).toContain("example.test");
});

test("a very large file is not read and offers the download", async ({ page }) => {
  await stub(page, { ...DONE, results: [{ name: "demo_1.0_bom.json", size: 40 * 1024 * 1024 }] });
  let read = false;
  await page.route("**/file?**", (r) => {
    read = true;
    return r.fulfill({ contentType: "application/json", body: "{}" });
  });
  await openScreen(page);
  await page.getByTestId("artifact-sbom").getByRole("button", { name: "View JSON" }).click();
  const big = page.getByTestId("viewer-too-big");
  await expect(big).toContainText("too large to preview (40.0 MB)");
  await expect(big.getByRole("link", { name: "Download" })).toBeVisible();
  await expect(page.getByRole("dialog").locator("pre")).toHaveCount(0);
  expect(read).toBe(true);
});

test("reopening shows no content of the file seen before", async ({ page }) => {
  await stub(page);
  await page.route("**/file?**name=demo_1.0_NOTICE.txt", async (r) => {
    await new Promise((res) => setTimeout(res, 600));
    await r.fulfill({ contentType: "text/plain", body: "slow notice" });
  });
  await openScreen(page);
  await page.getByTestId("artifact-sbom").getByRole("button", { name: "View JSON" }).click();
  await expect(page.getByRole("dialog").locator("pre")).toContainText("bomFormat");
  await page.keyboard.press("Escape");
  await page.getByTestId("artifact-notice").getByRole("button", { name: "View TXT" }).click();
  await expect(page.getByRole("dialog").locator("pre")).toHaveCount(0);
  await expect(page.getByRole("dialog").locator("pre")).toHaveText("slow notice");
});

test("JSON is indented and plain text is shown as it is", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  await page.getByTestId("artifact-sbom").getByRole("button", { name: "View JSON" }).click();
  const pre = page.getByRole("dialog").locator("pre");
  await expect(pre).toContainText('"bomFormat": "CycloneDX"');
  await expect(pre).toContainText('\n  "components": []');
  await page.keyboard.press("Escape");
  await page.getByTestId("artifact-notice").getByRole("button", { name: "View TXT" }).click();
  await expect(page.getByRole("dialog").locator("pre")).toHaveText("NOTICE text body");
});

test("the viewer keeps focus inside, closes on Escape, Close, X and an outside click, and gives focus back", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const opener = page.getByTestId("artifact-sbom").getByRole("button", { name: "View JSON" });
  const dialog = page.getByRole("dialog");

  await opener.click();
  await expect(dialog.locator(":focus")).toHaveCount(1);
  for (let i = 0; i < 8; i += 1) await page.keyboard.press("Tab");
  await expect(dialog.locator(":focus")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(opener).toBeFocused();

  await opener.click();
  await dialog.getByRole("button", { name: "Close" }).last().click();
  await expect(dialog).toHaveCount(0);
  await expect(opener).toBeFocused();

  await opener.click();
  await dialog.getByRole("button", { name: "Close" }).first().click();
  await expect(dialog).toHaveCount(0);

  await opener.click();
  await expect(dialog).toBeVisible();
  await page.mouse.click(5, 5);
  await expect(dialog).toHaveCount(0);
  await expect(opener).toBeFocused();

  // A drag that starts inside and ends on the backdrop does not close it.
  await opener.click();
  const pre = dialog.locator("pre");
  await expect(pre).toBeVisible();
  await waitForSettled(dialog);
  const box = (await pre.boundingBox())!;
  await page.mouse.move(box.x + 20, box.y + 10);
  await page.mouse.down();
  await page.mouse.move(5, 5);
  await page.mouse.up();
  await expect(dialog).toBeVisible();
});

test("a click inside the viewer does not close it", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  await page.getByTestId("artifact-sbom").getByRole("button", { name: "View JSON" }).click();
  await page.getByRole("dialog").locator("pre").click();
  await expect(page.getByRole("dialog")).toBeVisible();
});

test("the viewer's Download is a real download of the same file", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  await page.getByTestId("artifact-sbom").getByRole("button", { name: "View JSON" }).click();
  const link = page.getByRole("dialog").getByRole("link", { name: "Download" });
  await expect(link).toHaveAttribute("href", `/file?id=${ID}&name=demo_1.0_bom.json`);
  await expect(link).toHaveAttribute("download", "demo_1.0_bom.json");
});

test("a file that cannot be read says so, offers Retry, and never shows the error body as the file", async ({ page }) => {
  await stub(page);
  let fail = true;
  await page.route("**/file?**name=demo_1.0_NOTICE.txt", (r) =>
    fail ? r.fulfill({ status: 404, contentType: "text/plain", body: "Traceback secret" }) : r.fulfill({ contentType: "text/plain", body: "NOTICE recovered" }),
  );
  await openScreen(page);
  await page.getByTestId("artifact-notice").getByRole("button", { name: "View TXT" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("The file could not be opened")).toBeVisible();
  await expect(dialog).not.toContainText("Traceback secret");
  fail = false;
  await dialog.getByRole("button", { name: "Retry" }).click();
  await expect(dialog.locator("pre")).toHaveText("NOTICE recovered");
});

test("a slow file shows a loading line first", async ({ page }) => {
  await stub(page);
  await page.route("**/file?**name=demo_1.0_NOTICE.txt", async (r) => {
    await new Promise((res) => setTimeout(res, 800));
    await r.fulfill({ contentType: "text/plain", body: "late" });
  });
  await openScreen(page);
  await page.getByTestId("artifact-notice").getByRole("button", { name: "View TXT" }).click();
  await expect(page.getByRole("dialog").getByRole("status")).toContainText("Opening the file");
  await expect(page.getByRole("dialog").locator("pre")).toHaveText("late");
});

// ---------------------------------------------------------------------------
// Layout and accessibility
// ---------------------------------------------------------------------------

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`rows fit without clipping at ${width}px, ${lang}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await stub(page);
      await openScreen(page, lang);
      const overflow = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        clipped: [...document.querySelectorAll("main li *")].filter((e) => {
          const s = getComputedStyle(e);
          return s.textOverflow === "ellipsis" || e.scrollWidth > e.clientWidth + 1 && s.overflow !== "visible";
        }).length,
      }));
      expect(overflow.page).toBeLessThanOrEqual(0);
      expect(overflow.clipped).toBe(0);
      // Every action stays inside its row.
      const outside = await page.evaluate(() =>
        [...document.querySelectorAll("main li.bl-art-row")].filter((li) => {
          const r = li.getBoundingClientRect();
          return [...li.querySelectorAll("a,button")].some((b) => {
            const q = b.getBoundingClientRect();
            return q.right > r.right + 1 || q.left < r.left - 1;
          });
        }).length,
      );
      expect(outside).toBe(0);
    });
  }
}

for (const lang of ["en", "ko"] as const) {
  for (const theme of ["light", "dark"] as const) {
    test(`the screen and the open viewer clear axe, ${lang} ${theme}`, async ({ page }) => {
      await stub(page);
      await openScreen(page, lang, theme);
      const run = () => new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect((await run()).violations).toEqual([]);
      await page.getByTestId("artifact-sbom").getByRole("button", { name: lang === "en" ? "View JSON" : "JSON 보기" }).click();
      await expect(page.getByRole("dialog").locator("pre")).toContainText("bomFormat");
      await waitForSettled(page.getByRole("dialog"));
      expect((await run()).violations).toEqual([]);
    });
  }
}
