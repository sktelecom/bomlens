// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";

import { waitForSettled } from "./settle";
import { hashOf, ID, openerOf, openVulns, security, VULNS } from "./vulnerabilities-helpers";
import { seedThemeLang } from "./visual";

/**
 * Every state the screen can be in other than "a normal list": no report, a
 * failed engine, partial results, nothing found, nothing found but parts not
 * checked, the blocks under and over the table, the search and severity filter,
 * the sort, the three file actions (CSV, VEX import, VEX export).
 */

const empty = (extra: Record<string, unknown> = {}) => security([], extra);

test.describe("empty and error states", () => {
  test("a scan with no security report says nothing was checked", async ({ page }) => {
    await openVulns(page, "", { security: null });
    const box = page.getByTestId("no-security-report");
    await expect(box).toContainText("Security report was not generated");
    await expect(box).toContainText("An empty section is not the same as a clean result.");
  });

  test("a failed engine run is an error, with the engine's own words", async ({ page }) => {
    await openVulns(page, "", { security: empty({ scanError: "trivy: DB download failed" }) });
    const box = page.getByTestId("engine-failed");
    await expect(box).toContainText("Security scan failed");
    await expect(box).toContainText("trivy: DB download failed");
  });

  test("nothing found is a clean result, with the way to the checked components", async ({ page }) => {
    await openVulns(page, "", { security: empty() });
    await expect(page.getByTestId("no-vulnerabilities")).toContainText("No vulnerabilities found");
    await page.getByRole("link", { name: "See the components that were checked" }).click();
    await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/components`);
  });

  test("nothing found in an unreliable result is not called clean, and shows the grade and reasons", async ({ page }) => {
    await openVulns(page, "", {
      security: empty(),
      completeness: {
        grade: "unreliable",
        gradeLabel: { en: "Unreliable", ko: "신뢰 불가" },
        componentCount: 0,
        reasons: [
          {
            code: "no-components",
            grade: "unreliable",
            detail: "",
            message: { en: "The scan found no component.", ko: "컴포넌트를 찾지 못했습니다." },
            fix: { en: "Check the scan log and scan again.", ko: "로그를 확인하고 다시 스캔하세요." },
          },
        ],
      },
    });
    const box = page.getByTestId("vulns-incomplete");
    await expect(box).toContainText("Not a clean result: completeness is Unreliable");
    await expect(box).toContainText("The scan found no component.");
    await expect(page.getByTestId("no-vulnerabilities")).toHaveCount(0);
    await expect(page.getByText("No vulnerabilities found")).toHaveCount(0);
  });

  test("nothing found but components not checked is not called clean, and lists them", async ({ page }) => {
    await openVulns(page, "", {
      security: empty({
        uncheckedCount: 3,
        uncheckedComponents: [
          { name: "foo", version: "1.0", reason: "no-identifier", purl: "" },
          { name: "bar", version: "2.0", reason: "repository-purl", purl: "pkg:x/bar@2.0" },
          { name: "baz", version: "", reason: "no-version" },
        ],
      }),
    });
    const box = page.getByTestId("unchecked-components");
    await expect(box).toContainText("3 components could not be checked for vulnerabilities");
    await expect(page.getByTestId("no-vulnerabilities")).toHaveCount(0);
    await expect(page.getByText("No vulnerabilities were found in the components that were checked.")).toBeVisible();
    await box.getByText("Show the components").click();
    await expect(box.getByRole("row")).toHaveCount(4);
    await expect(box.getByRole("cell", { name: "foo" })).toBeVisible();
  });

  test("a cut-off unchecked list says how many of how many", async ({ page }) => {
    await openVulns(page, "", {
      security: empty({ uncheckedCount: 900, uncheckedComponents: [{ name: "foo", version: "1.0", reason: "no-version" }] }),
    });
    await page.getByTestId("unchecked-components").getByText("Show the components").click();
    await expect(page.getByTestId("unchecked-components")).toContainText("Showing the first 1 of 900.");
  });

  test("findings judged not reachable are listed, with why, and not counted", async ({ page }) => {
    await openVulns(page, "", {
      security: empty({
        notReachableCount: 1,
        notReachable: [
          { id: "CVE-2024-1111", severity: "HIGH", pkg: "golang.org/x/net", installed: "0.1.0", fixed: "0.2.0", purl: "pkg:golang/golang.org/x/net@0.1.0", title: "t", reachability: { state: "not_reachable", justification: "vulnerable_code_not_in_execute_path", detail: "no call path" } },
        ],
      }),
    });
    const box = page.getByTestId("not-reachable-findings");
    await expect(box).toContainText("1 finding is not reachable and is not counted above");
    await box.getByText("Show the findings").click();
    await expect(box).toContainText("CVE-2024-1111");
    await expect(box).toContainText("no call path");
  });

  test("advisories with no CVE keep the clean result and are listed after it", async ({ page }) => {
    await openVulns(page, "", {
      security: empty({ advisoryCount: 2, advisories: [{ id: "DLA-1234-1", severity: "MEDIUM", pkg: "libx", installed: "1.0", fixed: "1.1", target: "debian 11", title: "libx update" }] }),
    });
    await expect(page.getByTestId("no-vulnerabilities")).toBeVisible();
    // With advisories on the page, the "view components" link is not offered.
    await expect(page.getByRole("link", { name: "See the components that were checked" })).toHaveCount(0);
    const box = page.getByTestId("advisories-without-cve");
    await expect(box).toContainText("2 advisories with no CVE");
    await box.getByText("Show the advisories").click();
    await expect(box.getByText("DLA-1234-1")).toBeVisible();
    await expect(box).toContainText("Showing the first 1 of 2.");
  });

  test("advisories also follow a list of findings", async ({ page }) => {
    await openVulns(page, "", { security: security(VULNS, { advisoryCount: 1, advisories: [{ id: "SUSE-SU-1", severity: "LOW", pkg: "p", installed: "1", fixed: "2", target: "sles" }] }) });
    await expect(page.getByTestId("advisories-without-cve")).toBeVisible();
    await expect(openerOf(page, "CVE-2024-4001")).toBeVisible();
  });

  test("partial results: the list is there, with a banner saying the primary engine failed", async ({ page }) => {
    await openVulns(page, "", { security: security(VULNS, { scanError: "trivy exited 2" }) });
    await expect(page.getByText("The security scanner reported an error; these results may be incomplete.")).toBeVisible();
    await expect(page.getByText("trivy exited 2")).toBeVisible();
    await expect(openerOf(page, "CVE-2024-4001")).toBeVisible();
  });

  test("kernel advisories are a one-line note with the reason folded away", async ({ page }) => {
    await openVulns(page, "", { security: security(VULNS, { kernelCount: 851 }) });
    const note = page.getByTestId("kernel-advisories-notice");
    await expect(note).toContainText("851 kernel advisories are in the security report");
    await expect(note).toHaveAttribute("role", "note");
    await expect(note.locator("p")).toBeHidden();
    await note.locator("summary").click();
    await expect(note.locator("p")).toBeVisible();
  });

  test("a search that matches nothing says so and the CSV export is off", async ({ page }) => {
    await openVulns(page, "q=zzzzzz");
    await expect(page.getByTestId("vuln-no-match")).toContainText("No matching rows.");
    await expect(page.getByRole("button", { name: "Export CSV" })).toBeDisabled();
    await expect(page.getByText("0 of 10 shown")).toBeVisible();
    await page.getByRole("button", { name: "Clear filters" }).click();
    await expect(openerOf(page, "CVE-2024-4001")).toBeVisible();
    await expect(page.getByRole("button", { name: "Export CSV" })).toBeEnabled();
  });

  for (const theme of ["light", "dark"] as const) {
    test(`the blocks and states pass axe: ${theme}`, async ({ page }) => {
      await seedThemeLang(page, theme, "en");
      await openVulns(page, "", {
        security: security(VULNS, {
          kernelCount: 3,
          scanError: "partial",
          TOTAL: 50,
          uncheckedCount: 1,
          uncheckedComponents: [{ name: "foo", version: "1.0", reason: "no-version" }],
          notReachableCount: 1,
          notReachable: [{ id: "CVE-2024-1", severity: "HIGH", pkg: "p", installed: "1", fixed: "2", reachability: { state: "not_reachable", justification: "x" } }],
          advisoryCount: 1,
          advisories: [{ id: "DLA-1", severity: "LOW", pkg: "p", installed: "1", fixed: "2", target: "t" }],
        }),
      });
      for (const s of await page.locator("main details > summary").all()) await s.click();
      await waitForSettled(page.locator("main"));
      const axe = await new AxeBuilder({ page }).include("main").withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(axe.violations).toEqual([]);
    });
  }
});

test.describe("search, severity and sort", () => {
  test("search matches the CVE, an alias, the package and the title, and shows M of N", async ({ page }) => {
    const rows = [
      { id: "CVE-2025-1", severity: "HIGH", pkg: "alpha", installed: "1", fixed: "2", title: "first thing", aliases: ["GHSA-zzzz-0000-1111"] },
      { id: "CVE-2025-2", severity: "HIGH", pkg: "beta", installed: "1", fixed: "2", title: "second thing" },
      { id: "CVE-2025-3", severity: "LOW", pkg: "gamma", installed: "1", fixed: "2", title: "third item" },
    ];
    await openVulns(page, "", { security: security(rows) });
    const search = page.getByLabel("Search CVE, component, title");
    const shown = async (q: string) => {
      await search.fill(q);
      return page.locator("main tbody [data-open-id]").evaluateAll((els) => els.map((e) => e.getAttribute("data-open-id")));
    };
    expect(await shown("cve-2025-2")).toEqual(["CVE-2025-2"]);
    expect(await shown("ghsa-zzzz")).toEqual(["CVE-2025-1"]);
    expect(await shown("gamma")).toEqual(["CVE-2025-3"]);
    expect(await shown("thing")).toHaveLength(2);
    await expect(page.getByText("2 of 3 shown")).toBeVisible();
    await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/vulnerabilities?q=thing`);
  });

  test("a severity button filters, dims the bar, marks itself and clears on a second press", async ({ page }) => {
    await openVulns(page);
    const high = page.getByRole("group", { name: "Filter by severity" }).getByRole("button", { name: "High 4" });
    await high.click();
    await expect(high).toHaveAttribute("aria-pressed", "true");
    await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/vulnerabilities?severity=HIGH`);
    await expect(page.locator("main tbody [data-open-id]")).toHaveCount(4);
    await expect(page.getByRole("button", { name: "Remove filter: Severity: High" })).toBeVisible();
    // The other buttons are not dimmed; the distribution bar is.
    const siblingOpacity = await page.getByRole("button", { name: "Low 2" }).evaluate((e) => getComputedStyle(e).opacity);
    expect(siblingOpacity).toBe("1");
    const dimmed = await page.locator(".bl-v-bar > span").evaluateAll((els) => els.map((e) => getComputedStyle(e).opacity));
    expect(dimmed.filter((o) => o === "0.3")).toHaveLength(3);
    // The selection is a border and the focus ring is separate from it.
    expect(await high.evaluate((e) => getComputedStyle(e).borderTopColor)).not.toBe("rgba(0, 0, 0, 0)");
    await high.click();
    await expect(high).toHaveAttribute("aria-pressed", "false");
    await expect(page.locator("main tbody [data-open-id]")).toHaveCount(10);
  });

  test("a severity with no rows is disabled", async ({ page }) => {
    await openVulns(page);
    await expect(page.getByRole("button", { name: "Unknown 0" })).toBeDisabled();
  });

  test("each sortable header sorts, new columns start descending, and the sort is in the URL", async ({ page }) => {
    await openVulns(page);
    const order = () => page.locator("main tbody [data-open-id]").evaluateAll((els) => els.map((e) => e.getAttribute("data-open-id")));
    // Default: most severe first, highest CVSS within a band.
    expect((await order()).slice(0, 2)).toEqual(["CVE-2024-4001", "CVE-2024-4301"]);
    await page.getByRole("button", { name: "CVSS" }).click();
    await expect.poll(() => hashOf(page)).toBe(`#/scan/${ID}/vulnerabilities?dir=desc&sort=cvss`);
    await expect(page.getByRole("columnheader", { name: "CVSS" })).toHaveAttribute("aria-sort", "descending");
    await page.getByRole("button", { name: "CVSS" }).click();
    await expect(page.getByRole("columnheader", { name: "CVSS" })).toHaveAttribute("aria-sort", "ascending");
    expect((await order())[0]).toBe("CVE-2024-4006");
    await page.getByRole("button", { name: "Severity" }).click();
    await expect(page.getByRole("columnheader", { name: "Severity" })).toHaveAttribute("aria-sort", "descending");
  });

  test("a shared link carries search, severity and sort together", async ({ page }) => {
    await openVulns(page, "q=urllib3&severity=HIGH&sort=cvss&dir=asc");
    await expect(page.getByLabel("Search CVE, component, title")).toHaveValue("urllib3");
    await expect(page.locator("main tbody [data-open-id]")).toHaveCount(2);
    await expect(page.getByRole("columnheader", { name: "CVSS" })).toHaveAttribute("aria-sort", "ascending");
  });
});

test.describe("introduced by", () => {
  const rows = [
    {
      id: "CVE-2025-10",
      severity: "HIGH",
      pkg: "tomcat-embed-core",
      installed: "10.1.1",
      fixed: "10.1.2",
      title: "tomcat flaw",
      cvss: 7.5,
      introducedBy: [{ name: "spring-boot-starter-web", version: "3.2.0" }, { name: "tomcat-embed-core", version: "10.1.1", direct: true }],
    },
    { id: "CVE-2025-11", severity: "LOW", pkg: "rake", installed: "13.0", fixed: "13.1", title: "rake flaw", cvss: 3, buildTool: true },
  ];

  test("a column names the direct dependency behind a finding, a dash where none is known, and tags build tools", async ({ page }) => {
    await openVulns(page, "", { security: security(rows, { introducedByState: "ok" }) });
    await expect(page.getByRole("columnheader", { name: "Introduced by" })).toBeVisible();
    const cells = page.getByTestId("vuln-introduced-by");
    await expect(cells).toHaveCount(1);
    await expect(cells).toContainText("spring-boot-starter-web 3.2.0");
    await expect(cells).toContainText("tomcat-embed-core 10.1.1 (direct)");
    await expect(page.getByTestId("vuln-build-tool")).toHaveText("(build tool)");
    await expect(page.getByTestId("vuln-introduced-gap")).toHaveCount(0);
  });

  for (const [state, text] of [
    ["no-graph", "The SBOM has no dependency graph"],
    ["too-large", "The SBOM is too large to trace each finding"],
  ] as const) {
    test(`with no value in any row the reason (${state}) replaces the empty column`, async ({ page }) => {
      await openVulns(page, "", { security: security(VULNS, { introducedByState: state }) });
      await expect(page.getByRole("columnheader", { name: "Introduced by" })).toHaveCount(0);
      await expect(page.getByTestId("vuln-introduced-gap")).toContainText(text);
    });
  }

  test("CSV export ends each row with the dependencies that introduce it", async ({ page }) => {
    await openVulns(page, "", { security: security(rows, { introducedByState: "ok" }) });
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Export CSV" }).click()]);
    const text = readFileSync((await download.path()) as string, "utf8");
    expect(text).toContain("spring-boot-starter-web 3.2.0; tomcat-embed-core 10.1.1");
  });
});

test.describe("file actions", () => {
  test("CSV export hands over the visible rows in the table's order, with a BOM and formula-safe cells", async ({ page }) => {
    const rows = [
      { id: "CVE-2025-1", severity: "HIGH", pkg: "=cmd|calc", installed: "1", fixed: "2", title: "has, a comma", cvss: 7.5 },
      { id: "CVE-2025-2", severity: "LOW", pkg: "plain", installed: "1", fixed: "", title: "q", cvss: 2 },
    ];
    await openVulns(page, "severity=HIGH", { security: security(rows) });
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Export CSV" }).click()]);
    expect(download.suggestedFilename()).toBe(`${ID}-vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`);
    const text = readFileSync((await download.path()) as string, "utf8");
    expect(text.charCodeAt(0)).toBe(0xfeff);
    const lines = text.slice(1).split("\r\n");
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain("CVE-2025-1");
    expect(lines[1]).toContain("'=cmd|calc");
    expect(lines[1]).toContain('"has, a comma"');
    expect(text).not.toContain("CVE-2025-2");
  });

  test("a file larger than 4 MB is refused before it is sent", async ({ page }) => {
    let sent = false;
    await page.route("**/vex-import**", (r) => {
      sent = true;
      return r.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    });
    await openVulns(page);
    await page.locator('input[type="file"]').setInputFiles({ name: "big.json", mimeType: "application/json", buffer: Buffer.alloc(4 * 1024 * 1024 + 1, 32) });
    await expect(page.getByText("Not imported: the file or its statement list is too large")).toBeVisible();
    expect(sent).toBe(false);
  });

  for (const [status, text] of [
    [409, "Not imported: this VEX describes Other, but the scan is Mine"],
    [413, "Not imported: the file or its statement list is too large"],
    [422, "Not imported: no statement in this VEX applies to a component of this SBOM"],
    [400, "Not imported: the file is not a CycloneDX VEX document"],
    [500, "Could not import the VEX document"],
  ] as const) {
    test(`an import refused with ${status} says why`, async ({ page }) => {
      await page.route("**/vex-import**", (r) =>
        r.fulfill({ status, contentType: "application/json", body: JSON.stringify({ error: "x", vexProduct: "Other", scanProduct: "Mine" }) }),
      );
      await openVulns(page);
      await page.locator('input[type="file"]').setInputFiles({ name: "vex.json", mimeType: "application/json", buffer: Buffer.from("{}") });
      await expect(page.getByText(text)).toBeVisible();
    });
  }

  test("an accepted import labels the matching rows and says how many matched", async ({ page }) => {
    await page.route("**/vex-import**", (r) =>
      r.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          ok: true,
          imported: 1,
          unmatched: 0,
          source: "Acme",
          results: [{ name: `${ID}_bom.json`, size: 100 }],
          statements: [{ cve: "CVE-2024-4001", state: "not_affected", pkg: "urllib3", installed: "2.1.0", justification: "code_not_present" }],
        }),
      }),
    );
    await openVulns(page);
    await page.locator('input[type="file"]').setInputFiles({ name: "vex.json", mimeType: "application/json", buffer: Buffer.from("{}") });
    await expect(page.getByText("Imported 1 statement(s); 0 did not match a component in the SBOM")).toBeVisible();
    await expect(page.locator("tr", { has: page.locator('[data-open-id="CVE-2024-4001"]') })).toContainText("Supplier VEX: Not affected");
  });

  test("the VEX export hands over the file and the Artifacts list is refreshed", async ({ page }) => {
    await page.route("**/vex-export**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify({ name: `${ID}_vex.json`, exported: 1, skipped: 0, results: [{ name: `${ID}_bom.json`, size: 1 }, { name: `${ID}_vex.json`, size: 2 }] }) }),
    );
    await page.route("**/file?**vex**", (r) => r.fulfill({ contentType: "application/json", body: "{}" }));
    await openVulns(page, "", { security: security(VULNS, { vexCount: 2 }) });
    await page.getByRole("button", { name: "Export VEX" }).click();
    await expect(page.getByText("Download started")).toBeVisible();
  });
});
