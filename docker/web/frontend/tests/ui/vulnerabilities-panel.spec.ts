// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { waitForSettled } from "./settle";
import { hashOf, ID, openerOf, openVulns, rowOf, security, type Vuln } from "./vulnerabilities-helpers";
import { seedThemeLang } from "./visual";

/**
 * The detail of one vulnerability: a side panel opened from the row's title (or
 * a link with `open=`), one at a time, closed with Escape or the button, with the
 * focus put back on the row. It holds the CVSS and vector, dates, description,
 * references, the links into Components and Dependencies, the supplier's VEX and
 * the editable judgement.
 */

const FULL: Vuln = {
  id: "CVE-2024-0001",
  severity: "CRITICAL",
  pkg: "org.example:lib",
  installed: "3.0.0",
  fixed: "3.0.1",
  title: "Heap buffer overflow in the TLS handshake",
  cvss: 9.8,
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  publishedDate: "2024-03-02T00:00:00Z",
  description: "A heap buffer overflow in the TLS handshake lets a remote peer crash the process.",
  url: "https://example.test/CVE-2024-0001",
  refs: ["https://example.test/a", "https://example.test/b", "https://example.test/c", "https://example.test/d", "https://example.test/e"],
  purl: "pkg:maven/org.example/lib@3.0.0",
  aliases: ["GHSA-aaaa-bbbb-cccc"],
  status: "fixed",
  nvdSeverity: "HIGH",
  kev: true,
};
const OTHER: Vuln = { id: "CVE-2024-0002", severity: "HIGH", pkg: "zlib", installed: "1.2.0", fixed: "1.2.1", title: "Out-of-bounds read", cvss: 7.5 };
const BARE: Vuln = { id: "CVE-2024-0003", severity: "LOW", pkg: "bare", installed: "1", fixed: "", title: "No detail at all" };

const sec = () => security([FULL, OTHER, BARE]);
const dialog = (page: import("@playwright/test").Page) => page.getByRole("dialog");

test("clicking the title opens the panel, the URL carries it, and the row is marked", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  const opener = openerOf(page, FULL.id);
  await expect(opener).toHaveAttribute("aria-expanded", "false");
  await opener.click();
  await expect(dialog(page)).toBeVisible();
  await expect(dialog(page)).toHaveAccessibleName(FULL.title as string);
  await expect(opener).toHaveAttribute("aria-expanded", "true");
  await expect(rowOf(page, FULL.id)).toHaveAttribute("data-open", "true");
  await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/vulnerabilities?open=${FULL.id}`);
});

test("clicking a row cell opens the panel, and Escape closes it", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  await rowOf(page, OTHER.id).getByRole("cell").first().click();
  await expect(dialog(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog(page)).toHaveCount(0);
});

test("the panel is keyboard reachable: Enter and Space on the title open it, Escape closes it and focus returns", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  const opener = openerOf(page, OTHER.id);
  await opener.focus();
  await page.keyboard.press("Enter");
  await expect(dialog(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog(page)).toHaveCount(0);
  await expect(opener).toBeFocused();
  await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/vulnerabilities`);

  await page.keyboard.press("Space");
  await expect(dialog(page)).toBeVisible();
  await page.getByRole("button", { name: "Close" }).click();
  await expect(dialog(page)).toHaveCount(0);
  await expect(opener).toBeFocused();
});

test("only one panel is open at a time: opening another by link replaces the first", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  await openerOf(page, FULL.id).click();
  await expect(dialog(page)).toHaveAccessibleName(FULL.title as string);
  await page.evaluate((h) => { window.location.hash = h; }, `#/scan/${ID}/vulnerabilities?open=${OTHER.id}`);
  await expect(dialog(page)).toHaveCount(1);
  await expect(dialog(page)).toHaveAccessibleName(OTHER.title as string);
  await page.keyboard.press("Escape");
  await expect(openerOf(page, FULL.id)).toHaveAttribute("aria-expanded", "false");
});

test("a link with open= opens that panel; an id that matches no row is dropped from the URL", async ({ page }) => {
  await openVulns(page, `open=${OTHER.id}`, { security: sec() });
  await expect(dialog(page)).toHaveAccessibleName(OTHER.title as string);
  await page.evaluate((h) => { window.location.hash = h; }, `#/scan/${ID}/vulnerabilities?open=CVE-0000-0000`);
  await expect(dialog(page)).toHaveCount(0);
  await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/vulnerabilities`);
});

test("a stale open= link opens nothing and takes no focus", async ({ page }) => {
  await openVulns(page, "open=CVE-0000-0000", { security: sec() });
  await expect(dialog(page)).toHaveCount(0);
  await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/vulnerabilities`);
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => document.activeElement?.closest(".bl-v-table") != null)).toBe(false);
});

test("the same CVE in two packages gets two ids the URL can tell apart", async ({ page }) => {
  const twice = [
    { ...OTHER, pkg: "alpha", title: "alpha copy" },
    { ...OTHER, pkg: "beta", title: "beta copy" },
  ];
  await openVulns(page, "open=CVE-2024-0002:beta", { security: security(twice) });
  await expect(dialog(page)).toHaveAccessibleName("beta copy");
});

test("the panel header uses Primer's defaults and its close button is translated", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("sbom.lang", "ko"));
  await openVulns(page, "", { security: sec() });
  await openerOf(page, FULL.id).click();
  const header = dialog(page).locator("[class*='Dialog'][class*='Header']").first();
  await expect(header).toBeVisible();
  expect(await header.evaluate((e) => getComputedStyle(e).paddingTop)).toBe("8px");
  await expect(dialog(page).getByRole("button", { name: "닫기" })).toBeVisible();
});

test("the panel holds the package, CVSS with its vector, dates, description, references and the fixed versions", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  await openerOf(page, FULL.id).click();
  const d = dialog(page);
  await expect(d.getByTestId("vuln-detail")).toContainText("pkg:maven/org.example/lib@3.0.0");
  await expect(d).toContainText("9.8");
  await expect(d).toContainText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  await expect(d).toContainText("Mar 2, 2024");
  await expect(d).toContainText("A heap buffer overflow in the TLS handshake");
  await expect(d.getByText("GHSA-aaaa-bbbb-cccc")).toBeVisible();
  // Every status, including the one the table leaves out ("fixed"), is here.
  await expect(d.getByText("Fix available", { exact: true }).first()).toBeVisible();
  await expect(d.getByText("KEV")).toBeVisible();
  await expect(d.getByText("3.0.1")).toBeVisible();
  // The first three references show; the rest fold behind "N more".
  await expect(d.locator(".bl-vp-refs a")).toHaveCount(6);
  await expect(d.locator(".bl-vp-refs").first().locator("a")).toHaveCount(3);
  await expect(d.locator(".bl-vp-more .bl-vp-refs a").first()).toBeHidden();
  await d.getByText("3 more").click();
  await expect(d.locator(".bl-vp-more .bl-vp-refs a").first()).toBeVisible();
});

test("the panel reads head, facts, description, references, then your judgement last", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  await openerOf(page, FULL.id).click();
  const y = async (loc: import("@playwright/test").Locator) => (await loc.first().boundingBox())!.y;
  const d = dialog(page);
  const facts = await y(d.getByText("CVSS:3.1/AV:N"));
  const desc = await y(d.getByText("A heap buffer overflow in the TLS handshake lets"));
  const refs = await y(d.locator(".bl-vp-refs a"));
  const judge = await y(d.getByRole("heading", { name: "Your judgement" }));
  expect(facts).toBeLessThan(desc);
  expect(desc).toBeLessThan(refs);
  expect(refs).toBeLessThan(judge);
  // The external-link icon sits on the same line as the start of its URL.
  const icon = await d.locator(".bl-vp-refs a svg").first().boundingBox();
  const text = await d.locator(".bl-vp-refs a span").first().boundingBox();
  expect(Math.abs(icon!.y + icon!.height / 2 - (text!.y + text!.height / 2))).toBeLessThan(10);
});

test("a vulnerability with no detail says so", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  await openerOf(page, BARE.id).click();
  await expect(dialog(page)).toContainText("No additional details available.");
});

test("the panel links into Components and Dependencies for the package", async ({ page }) => {
  await openVulns(page, "", { security: sec() });
  await openerOf(page, FULL.id).click();
  await dialog(page).getByRole("button", { name: "View org.example:lib in Dependencies" }).click();
  await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/dependencies?q=org.example%3Alib&version=3.0.0`);
  await page.goBack();
  await expect(dialog(page)).toBeVisible();
  await dialog(page).getByRole("button", { name: "View org.example:lib in Components" }).click();
  await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/components?q=org.example%3Alib`);
});

test.describe("the judgement", () => {
  test("choosing a state and a note and saving sends them, labels the row and shows the time", async ({ page }) => {
    let posted: Record<string, unknown> | null = null;
    await page.route("**/vex-verdict**", async (route) => {
      posted = route.request().postDataJSON();
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ ok: true, verdict: { state: "not_affected", detail: "never called", updatedAt: "2026-11-01T09:00:00Z" } }),
      });
    });
    await openVulns(page, "", { security: sec() });
    await expect(page.getByRole("button", { name: "Export VEX" })).toHaveCount(0);
    await openerOf(page, FULL.id).click();
    const d = dialog(page);
    await expect(d.getByRole("button", { name: "Save" })).toBeDisabled();
    await d.getByLabel("Judgement", { exact: true }).selectOption("not_affected");
    await d.getByLabel("Notes (optional)").fill("never called");
    await d.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Judgement saved")).toBeVisible();
    expect(posted).toMatchObject({ cve: FULL.id, state: "not_affected", detail: "never called", purl: FULL.purl });
    await expect(d).toContainText("Judgement: Not affected");
    await expect(d).toContainText("Nov 1, 2026");
    await page.keyboard.press("Escape");
    await expect(rowOf(page, FULL.id)).toContainText("Judgement: Not affected");
    // A judgement now exists, so the export appears.
    await expect(page.getByRole("button", { name: "Export VEX" })).toBeVisible();
  });

  test("the note takes 2000 characters and no more", async ({ page }) => {
    await openVulns(page, "", { security: sec() });
    await openerOf(page, FULL.id).click();
    const note = dialog(page).getByLabel("Notes (optional)");
    await expect(note).toHaveAttribute("maxlength", "2000");
    await note.fill("x".repeat(2100));
    expect((await note.inputValue()).length).toBe(2000);
  });

  test("a failed save says so and keeps the form", async ({ page }) => {
    await page.route("**/vex-verdict**", (route) => route.fulfill({ status: 500, contentType: "application/json", body: "{}" }));
    await openVulns(page, "", { security: sec() });
    await openerOf(page, OTHER.id).click();
    await dialog(page).getByLabel("Judgement", { exact: true }).selectOption("affected");
    await dialog(page).getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("could not save (500)")).toBeVisible();
    await expect(dialog(page).getByLabel("Judgement", { exact: true })).toHaveValue("affected");
  });

  test("a judgement that came with the scan fills the form and labels the row", async ({ page }) => {
    const judged = { ...OTHER, vexState: "affected", vexDetail: "we use it", vexUpdatedAt: "2026-10-01T00:00:00Z" };
    await openVulns(page, "", { security: { ...security([judged]), vexCount: 1 } });
    await expect(rowOf(page, OTHER.id)).toContainText("Judgement: Affected");
    await expect(page.getByRole("button", { name: "Export VEX" })).toBeVisible();
    await openerOf(page, OTHER.id).click();
    await expect(dialog(page).getByLabel("Judgement", { exact: true })).toHaveValue("affected");
    await expect(dialog(page).getByLabel("Notes (optional)")).toHaveValue("we use it");
  });

  test("a statement received from a supplier is shown apart from the judgement", async ({ page }) => {
    const received = { ...OTHER, vexReceived: { state: "fixed", source: "Acme VEX", justification: "code_not_present", detail: "patched upstream" } };
    await openVulns(page, "", { security: security([received]) });
    await expect(rowOf(page, OTHER.id)).toContainText("Supplier VEX: Fixed");
    await openerOf(page, OTHER.id).click();
    const box = dialog(page).getByTestId("vex-received");
    await expect(box).toContainText("Acme VEX");
    await expect(box).toContainText("patched upstream");
    await expect(box).toContainText("code_not_present");
  });
});

test("the row labels: known exploited, reached, no fix and the vendor status", async ({ page }) => {
  const labelled: Vuln[] = [
    { ...FULL, status: "fixed" },
    { ...OTHER, reachability: { state: "exploitable", justification: "", detail: "called from main" }, status: "will_not_fix" },
    BARE,
  ];
  await openVulns(page, "", { security: security(labelled) });
  const first = rowOf(page, FULL.id);
  await expect(first.getByText("KEV", { exact: true })).toBeVisible();
  // The "fixed" status is what the Fixed column already says, so the row leaves it out.
  await expect(first).not.toContainText("Fix available");
  await expect(rowOf(page, OTHER.id)).toContainText("Reached");
  await expect(rowOf(page, OTHER.id)).toContainText("Will not fix");
  await expect(rowOf(page, BARE.id)).toContainText("No fix yet");
});

for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    test(`an open panel on a highlighted row passes axe: ${theme}/${lang}`, async ({ page }) => {
      await seedThemeLang(page, theme, lang);
      await openVulns(page, `open=${FULL.id}`, { security: sec() });
      await expect(dialog(page)).toBeVisible();
      await waitForSettled(dialog(page));
      const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(axe.violations).toEqual([]);
    });
  }
}
