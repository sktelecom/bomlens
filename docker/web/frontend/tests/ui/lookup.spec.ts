// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * External lookup (`#/lookup`): a CVE/GHSA id, a purl, or a package name +
 * version, checked live against OSV.dev through `GET /advisory` and
 * `GET /package-advisories`. The backend is fully stubbed, so these tests never
 * touch the real OSV.dev. They cover all three input shapes, the "not found"
 * and offline responses, the capability gate that hides every entry point,
 * the GlobalSearch row that routes here, and the shareable deep link.
 */

const ADVISORY_FOUND = {
  id: "CVE-2021-44228",
  found: true,
  severity: "CRITICAL",
  cvss: 10,
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  title: "Log4Shell",
  description: "Remote code execution in Apache Log4j2.",
  aliases: ["GHSA-jfh8-c2jp-5v3q"],
  withdrawn: false,
  modified: "2023-01-01T00:00:00Z",
  published: "2021-12-10T00:00:00Z",
  refs: ["https://logging.apache.org/log4j/2.x/security.html"],
  affected: [{ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" }],
  source: "osv",
};

const ADVISORY_NOT_FOUND = {
  id: "CVE-9999-00000",
  found: false,
  source: "osv",
};

const PACKAGE_FOUND = {
  found: true,
  truncated: false,
  items: [
    {
      id: "GHSA-35jh-r3h4-6jhm",
      found: true,
      severity: "HIGH",
      cvss: 7.4,
      cvssVector: "",
      title: "Prototype pollution in lodash",
      description: "Prototype pollution.",
      aliases: [],
      withdrawn: false,
      modified: "2022-01-01T00:00:00Z",
      published: "2021-06-01T00:00:00Z",
      refs: [],
      affected: [{ ecosystem: "npm", name: "lodash" }],
      source: "osv",
    },
  ],
};

const PACKAGE_CLEAN = { found: false, truncated: false, items: [] };

async function baseStubs(page: Page, capabilitiesOverride: Record<string, unknown> = {}) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        firmware: false,
        docker: true,
        externalLookup: true,
        ...capabilitiesOverride,
      }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
}

test.describe("id and purl lookups", () => {
  test("looking up a CVE id shows the found advisory's full detail", async ({ page }) => {
    await baseStubs(page);
    await page.route("**/advisory**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(ADVISORY_FOUND) }),
    );
    await page.goto("/?ui=next#/lookup");
    await page.getByLabel("CVE, GHSA, purl, or package name").fill("CVE-2021-44228");
    await page.getByRole("button", { name: "Look up" }).click();

    await expect(page.getByText("Log4Shell")).toBeVisible();
    await expect(page.getByText("Critical")).toBeVisible();
    await expect(page.getByText("10", { exact: true })).toBeVisible();
    await expect(page.getByText("GHSA-jfh8-c2jp-5v3q")).toBeVisible();
    await expect(
      page.getByRole("link", { name: /logging\.apache\.org/ }),
    ).toHaveAttribute("target", "_blank");

    // Neither the ecosystem picker nor the version field applies to an
    // advisory-id lookup.
    await expect(page.getByLabel("Ecosystem")).toHaveCount(0);
    await expect(page.getByLabel("Version")).toHaveCount(0);
  });

  test("a purl resolves its own ecosystem and version, so no extra fields show", async ({
    page,
  }) => {
    await baseStubs(page);
    let requested: URL | null = null;
    await page.route("**/package-advisories**", (r) => {
      requested = new URL(r.request().url());
      return r.fulfill({
        contentType: "application/json",
        body: JSON.stringify(PACKAGE_FOUND),
      });
    });
    await page.goto("/?ui=next#/lookup");
    await page
      .getByLabel("CVE, GHSA, purl, or package name")
      .fill("pkg:npm/lodash@4.17.21");
    await expect(page.getByLabel("Ecosystem")).toHaveCount(0);
    await expect(page.getByLabel("Version")).toHaveCount(0);
    await page.getByRole("button", { name: "Look up" }).click();

    await expect(page.getByText("Prototype pollution in lodash")).toBeVisible();
    expect(requested?.searchParams.get("ecosystem")).toBe("npm");
    expect(requested?.searchParams.get("name")).toBe("lodash");
    expect(requested?.searchParams.get("version")).toBe("4.17.21");
  });

  test("a bare package name asks for an ecosystem and a version", async ({ page }) => {
    await baseStubs(page);
    let requested: URL | null = null;
    await page.route("**/package-advisories**", (r) => {
      requested = new URL(r.request().url());
      return r.fulfill({
        contentType: "application/json",
        body: JSON.stringify(PACKAGE_CLEAN),
      });
    });
    await page.goto("/?ui=next#/lookup");
    await page.getByLabel("CVE, GHSA, purl, or package name").fill("lodash");

    const submit = page.getByRole("button", { name: "Look up" });
    await expect(submit).toBeDisabled();

    await page.getByLabel("Ecosystem").selectOption("npm");
    await expect(submit).toBeDisabled();
    await page.getByLabel("Version").fill("4.17.21");
    await expect(submit).toBeEnabled();
    await submit.click();

    await expect(page.getByText("No known advisories against this version")).toBeVisible();
    expect(requested?.searchParams.get("ecosystem")).toBe("npm");
    expect(requested?.searchParams.get("name")).toBe("lodash");
    expect(requested?.searchParams.get("version")).toBe("4.17.21");
  });
});

test.describe("not-found and failure responses", () => {
  test("an advisory id with nothing filed under it says so, without alarm", async ({
    page,
  }) => {
    await baseStubs(page);
    await page.route("**/advisory**", (r) =>
      r.fulfill({
        contentType: "application/json",
        body: JSON.stringify(ADVISORY_NOT_FOUND),
      }),
    );
    await page.goto("/?ui=next#/lookup?q=CVE-9999-00000");

    await expect(page.getByText("Not in the OSV.dev catalog")).toBeVisible();
    await expect(page.getByText(/doesn't mean it's safe/)).toBeVisible();
  });

  test("a 503 offline response reads as an environment note, not an error banner", async ({
    page,
  }) => {
    await baseStubs(page);
    await page.route("**/advisory**", (r) =>
      r.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ error: "offline" }),
      }),
    );
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");

    await expect(page.getByText(/can't reach OSV\.dev/)).toBeVisible();
  });

  test("a 502 upstream failure is distinguished from offline", async ({ page }) => {
    await baseStubs(page);
    await page.route("**/advisory**", (r) =>
      r.fulfill({
        status: 502,
        contentType: "application/json",
        body: JSON.stringify({ error: "upstream" }),
      }),
    );
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");

    await expect(page.getByText(/didn't answer usably/)).toBeVisible();
  });
});

test.describe("the capability gate", () => {
  test("every entry point is hidden when externalLookup is off", async ({ page }) => {
    await baseStubs(page, { externalLookup: false });
    await page.goto("/?ui=next#/");
    await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();
    await expect(page.getByTestId("external-lookup-link")).toHaveCount(0);
  });

  test("a direct #/lookup visit bounces home when the capability is off", async ({
    page,
  }) => {
    await baseStubs(page, { externalLookup: false });
    await page.goto("/?ui=next#/lookup");
    await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "External vulnerability lookup" })).toHaveCount(0);
  });

  test("the top-bar entry point is visible and opens the screen when enabled", async ({
    page,
  }) => {
    await baseStubs(page);
    await page.goto("/?ui=next#/");
    const link = page.getByTestId("external-lookup-link");
    await expect(link).toBeVisible();
    await link.click();
    await expect(
      page.getByRole("heading", { name: "External vulnerability lookup" }),
    ).toBeVisible();
    await expect(page).toHaveURL(/#\/lookup$/);
  });

  // Regression: the hash router bails out entirely while a scan is running
  // (it doesn't yet own an id, and run()'s own done handler sets the URL), so
  // the plain `<a href="#/lookup">` alone changed the address bar but left the
  // Scanning screen on-screen — the icon looked unresponsive. TopBar.onLookup
  // (NextApp.goToLookup) resets state imperatively first, the same way New
  // scan already does, so this reaches the screen instead of only the URL.
  test("the top-bar entry point works mid-scan, not just when idle", async ({ page }) => {
    await baseStubs(page);
    // Hold the stream open so the running view (and its Scanning screen) stays up.
    await page.route("**/scan-stream**", async (r) => {
      await new Promise((res) => setTimeout(res, 5000));
      await r.fulfill({ contentType: "text/event-stream", body: "event: done\ndata: {}\n\n" });
    });
    await page.goto("/?ui=next#/new");
    await page.fill("#project", "demo");
    await page.fill("#version", "1.0");
    await page.getByTestId("run-scan").click();
    await expect(page.getByText("Scanning…")).toBeVisible();

    await page.getByTestId("external-lookup-link").click();

    await expect(
      page.getByRole("heading", { name: "External vulnerability lookup" }),
    ).toBeVisible();
    await expect(page).toHaveURL(/#\/lookup$/);
  });
});

test.describe("GlobalSearch routing", () => {
  const SCANS = [
    {
      id: "demo_2.1",
      project: "demo",
      version: "2.1",
      components: 1,
      maxSeverity: null,
      isAiScan: false,
      componentType: "application",
      generatedAt: 1700000000,
    },
  ];
  const DONE = {
    ok: true,
    mode: "SOURCE",
    id: "demo_2.1",
    results: [{ name: "demo_2.1_bom.json", size: 100 }],
    security: null,
    conformance: null,
    sbom: {
      components: 1,
      componentList: [
        {
          name: "openssl",
          version: "3.0.0",
          group: "",
          purl: "pkg:github/openssl/openssl",
          type: "library",
          licenses: ["Apache-2.0"],
        },
      ],
    },
  };
  const SBOM = {
    bomFormat: "CycloneDX",
    metadata: { component: { "bom-ref": "root", name: "demo", version: "2.1" } },
    components: [
      { "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o" },
    ],
    dependencies: [],
  };

  async function openScan(page: Page, capabilitiesOverride: Record<string, unknown> = {}) {
    await baseStubs(page, capabilitiesOverride);
    await page.route("**/scan?id=demo_2.1", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
    );
    await page.route("**/file**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
    );
    await page.route("**/scans", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(SCANS) }),
    );
    await page.goto("/?ui=next#/scan/demo_2.1");
    await page.getByRole("navigation").first().waitFor();
  }

  test("typing a CVE-shaped term offers an external-lookup row that never fires a request", async ({
    page,
  }) => {
    await openScan(page);
    let advisoryCalls = 0;
    await page.route("**/advisory**", (r) => {
      advisoryCalls += 1;
      return r.fulfill({
        contentType: "application/json",
        body: JSON.stringify(ADVISORY_FOUND),
      });
    });

    const search = page.getByTestId("global-search");
    await search.fill("CVE-2021-44228");
    const row = page.getByRole("option", { name: /Look up "CVE-2021-44228"/ });
    await expect(row).toBeVisible();
    // Typing itself must never call the endpoint; only picking the row does.
    expect(advisoryCalls).toBe(0);

    await row.click();
    await expect(page).toHaveURL(/#\/lookup\?q=CVE-2021-44228$/);
    await expect(page.getByText("Log4Shell")).toBeVisible();
    expect(advisoryCalls).toBe(1);
  });

  test("the row is hidden when externalLookup is off, even for a CVE-shaped term", async ({
    page,
  }) => {
    await openScan(page, { externalLookup: false });
    const search = page.getByTestId("global-search");
    await search.fill("CVE-2021-44228");
    await expect(page.getByRole("option", { name: /Look up/ })).toHaveCount(0);
  });
});

test.describe("deep links and accessibility", () => {
  test("a shared #/lookup?q=… link auto-runs the lookup on arrival", async ({ page }) => {
    await baseStubs(page);
    await page.route("**/package-advisories**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_FOUND) }),
    );
    await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21");

    await expect(page.getByLabel("CVE, GHSA, purl, or package name")).toHaveValue(
      "pkg:npm/lodash@4.17.21",
    );
    await expect(page.getByText("Prototype pollution in lodash")).toBeVisible();
  });

  test("the lookup screen with a result has no axe violations", async ({ page }) => {
    await baseStubs(page);
    await page.route("**/advisory**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(ADVISORY_FOUND) }),
    );
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
    await expect(page.getByText("Log4Shell")).toBeVisible();
    await waitForSettled(page.locator("main"));
    await page.mouse.move(0, 0);

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  });
});
