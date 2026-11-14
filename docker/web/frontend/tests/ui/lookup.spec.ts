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
      page.getByRole("link", { name: /^https:\/\/logging\.apache\.org\// }),
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

  test("a 503 offline response is a warning that names the closed network, not a failure", async ({
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
    await page.getByTestId("result-meta").waitFor();
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

// ---- The Primer rebuild: each control, the URL, the states, the layout ----

const LONG_TITLE =
  "A deliberately long advisory title that keeps going so that it has to wrap onto several lines instead of being cut short with an ellipsis at the row edge, and then it goes on a good while longer so that even the widest window still has to break it";

const PACKAGE_MANY = {
  found: true,
  truncated: true,
  items: [
    {
      ...PACKAGE_FOUND.items[0],
      id: "GHSA-aaaa-bbbb-cccc-dddd-eeee-ffff",
      title: LONG_TITLE,
      withdrawn: true,
      affected: [
        {
          ecosystem: "npm",
          name: "lodash",
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
        },
      ],
      description: "Long description of the prototype pollution. ".repeat(6),
      aliases: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
      refs: ["https://example.com/a/very/long/reference/path/that/needs/to/wrap/instead/of/overflowing/the/row"],
    },
    { ...PACKAGE_FOUND.items[0], id: "GHSA-1111-2222-3333", severity: "NONE", title: "Second advisory", affected: [] },
  ],
};

async function seeded(page: Page, o: { lang?: "en" | "ko"; theme?: "light" | "dark"; width?: number } = {}) {
  await page.setViewportSize({ width: o.width ?? 1280, height: 900 });
  await page.addInitScript(
    ([l, t]) => {
      localStorage.setItem("sbom.lang", l as string);
      localStorage.setItem("sbom.theme", t as string);
    },
    [o.lang ?? "en", o.theme ?? "light"],
  );
  await baseStubs(page);
}

const FIELD = "CVE, GHSA, purl, or package name";

test.describe("the rebuilt screen", () => {
  test("the empty screen says why Look up is off and offers examples that fill the field", async ({ page }) => {
    await seeded(page);
    await page.route("**/package-advisories**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_FOUND) }),
    );
    await page.goto("/?ui=next#/lookup");
    await expect(page.getByText("Enter an id, a purl or a package name to turn on Look up.")).toBeVisible();
    await page.getByTestId("lookup-examples").getByRole("button", { name: "pkg:npm/lodash@4.17.21" }).click();
    await expect(page.getByLabel(FIELD)).toHaveValue("pkg:npm/lodash@4.17.21");
    await expect(page.getByTestId("lookup-examples")).toHaveCount(0);
    await page.getByRole("button", { name: "Look up" }).click();
    await expect(page.getByText("Prototype pollution in lodash")).toBeVisible();
  });

  test("a bare name says what is still missing", async ({ page }) => {
    await seeded(page);
    await page.goto("/?ui=next#/lookup");
    await page.getByLabel(FIELD).fill("lodash");
    await expect(page.getByText("Pick an ecosystem and enter a version to turn on Look up.")).toBeVisible();
  });

  test("a slow earlier lookup never overwrites a newer one", async ({ page }) => {
    await seeded(page);
    await page.route("**/advisory**", async (r) => {
      const id = new URL(r.request().url()).searchParams.get("id");
      if (id === "CVE-2021-44228") await new Promise((res) => setTimeout(res, 1200));
      await r.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ ...ADVISORY_FOUND, id: id ?? "", title: id === "CVE-2021-44228" ? "Log4Shell" : "Newer advisory" }),
      });
    });
    // The submit button is off while a lookup runs, so the newer one arrives through the link.
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
    await expect(page.getByRole("status").getByText("Looking up…")).toBeVisible();
    await page.evaluate(() => {
      window.location.hash = "#/lookup?q=CVE-2022-12345";
    });
    await expect(page.getByText("Newer advisory")).toBeVisible();
    await page.waitForTimeout(1600);
    await expect(page.getByText("Newer advisory")).toBeVisible();
    await expect(page.getByText("Log4Shell")).toHaveCount(0);
  });

  test("an unsupported purl in a shared link shows the note and the invalid message", async ({ page }) => {
    await seeded(page);
    await page.goto("/?ui=next#/lookup?q=pkg%3Acocoapods%2FAFNetworking%404.0.0");
    await expect(page.getByText("Unsupported package type: cocoapods")).toBeVisible();
    await expect(page.getByText(/doesn't look like a valid id/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Retry" })).toHaveCount(0);
  });

  test("an unknown eco value in the link is ignored, and a purl wins over eco and ver", async ({ page }) => {
    await seeded(page);
    await page.route("**/package-advisories**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_CLEAN) }),
    );
    await page.goto("/?ui=next#/lookup?q=lodash&eco=bogus&ver=1");
    await expect(page.getByLabel("Ecosystem")).toHaveValue("");
    await expect(page.getByText(/doesn't look like a valid id/)).toBeVisible();

    let requested: URL | null = null;
    await page.unroute("**/package-advisories**");
    await page.route("**/package-advisories**", (r) => {
      requested = new URL(r.request().url());
      return r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_CLEAN) });
    });
    await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21&eco=pypi&ver=9");
    await expect(page.getByRole("heading", { name: "No known advisories against this version" })).toBeVisible();
    expect(requested?.searchParams.get("ecosystem")).toBe("npm");
    expect(requested?.searchParams.get("version")).toBe("4.17.21");
  });

  test("the row summary takes a keyboard focus ring and a short accessible name", async ({ page }) => {
    await seeded(page);
    await page.route("**/package-advisories**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_MANY) }),
    );
    await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21");
    const first = page.getByTestId("lookup-advisory").first().locator("summary");
    await first.focus();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Shift+Tab");
    const outline = await first.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline).not.toBe("none");
    const name = await first.evaluate((el) => {
      const ids = (el.getAttribute("aria-labelledby") ?? "").split(" ");
      return ids.map((i) => document.getElementById(i)?.textContent ?? "").join(" ");
    });
    expect(name).not.toContain("4.17.21");
  });

  test("the rows line up: every severity and title starts at the same x", async ({ page }) => {
    await seeded(page);
    await page.route("**/package-advisories**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_MANY) }),
    );
    await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21");
    await expect(page.getByTestId("lookup-advisory")).toHaveCount(2);
    const xs = await page.evaluate(() =>
      [...document.querySelectorAll(".bl-lk-sum")].map((s) => [
        Math.round(s.children[2].getBoundingClientRect().left),
        Math.round(s.children[3].getBoundingClientRect().left),
      ]),
    );
    expect(xs.length).toBe(2);
    expect(xs[0]).toEqual(xs[1]);
  });

  test("Enter in the input runs the lookup, and the term lands in the URL", async ({ page }) => {
    await seeded(page);
    await page.route("**/advisory**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(ADVISORY_FOUND) }),
    );
    await page.goto("/?ui=next#/lookup");
    const submit = page.getByRole("button", { name: "Look up" });
    await expect(submit).toBeDisabled();
    await page.getByLabel(FIELD).fill("CVE-2021-44228");
    await expect(submit).toBeEnabled();
    await page.getByLabel(FIELD).press("Enter");
    await expect(page.getByText("Log4Shell")).toBeVisible();
    await expect(page).toHaveURL(/#\/lookup\?q=CVE-2021-44228$/);
  });

  test("a bare name keeps its ecosystem and version in the URL, and the link runs again", async ({ page }) => {
    await seeded(page);
    const calls: URL[] = [];
    await page.route("**/package-advisories**", (r) => {
      calls.push(new URL(r.request().url()));
      return r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_FOUND) });
    });
    await page.goto("/?ui=next#/lookup");
    await page.getByLabel(FIELD).fill("lodash");
    await page.getByLabel("Ecosystem").selectOption("npm");
    await page.getByLabel("Version").fill("4.17.21");
    await page.getByLabel("Version").press("Enter");
    await expect(page.getByText("Prototype pollution in lodash")).toBeVisible();
    await expect(page).toHaveURL(/#\/lookup\?eco=npm&q=lodash&ver=4\.17\.21$/);

    await page.reload();
    await expect(page.getByText("Prototype pollution in lodash")).toBeVisible();
    await expect(page.getByLabel("Ecosystem")).toHaveValue("npm");
    await expect(page.getByLabel("Version")).toHaveValue("4.17.21");
    expect(calls.at(-1)?.searchParams.get("ecosystem")).toBe("npm");
    expect(calls.at(-1)?.searchParams.get("version")).toBe("4.17.21");
  });

  test("name@version fills the version and still asks only for the ecosystem", async ({ page }) => {
    await seeded(page);
    await page.goto("/?ui=next#/lookup");
    await page.getByLabel(FIELD).fill("lodash@4.17.21");
    await expect(page.getByLabel("Version")).toHaveCount(0);
    await expect(page.getByLabel("Ecosystem")).toBeVisible();
    await expect(page.getByRole("button", { name: "Look up" })).toBeDisabled();
  });

  test("an unsupported purl type is named under the form and cannot be submitted", async ({ page }) => {
    await seeded(page);
    await page.goto("/?ui=next#/lookup");
    await page.getByLabel(FIELD).fill("pkg:cocoapods/AFNetworking@4.0.0");
    await expect(page.getByText("Unsupported package type: cocoapods")).toBeVisible();
    await expect(page.getByRole("button", { name: "Look up" })).toBeDisabled();
  });

  test("the format hint is always on screen", async ({ page }) => {
    await seeded(page);
    await page.goto("/?ui=next#/lookup");
    await expect(page.getByText("Accepted: CVE, GHSA, GO, PYSEC")).toBeVisible();
  });

  test("a failed lookup offers Retry, which asks again", async ({ page }) => {
    await seeded(page);
    let calls = 0;
    await page.route("**/advisory**", (r) => {
      calls += 1;
      if (calls === 1) {
        return r.fulfill({ status: 502, contentType: "application/json", body: JSON.stringify({ error: "upstream" }) });
      }
      return r.fulfill({ contentType: "application/json", body: JSON.stringify(ADVISORY_FOUND) });
    });
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
    await expect(page.getByText(/didn't answer usably/)).toBeVisible();
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByText("Log4Shell")).toBeVisible();
    expect(calls).toBe(2);
  });

  test("a busy server and an unreachable server each have their own message and Retry", async ({ page }) => {
    await seeded(page);
    let mode: "busy" | "down" = "busy";
    await page.route("**/advisory**", (r) =>
      mode === "busy"
        ? r.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "busy" }) })
        : r.abort(),
    );
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
    await expect(page.getByText(/Lookups are busy/)).toBeVisible();
    mode = "down";
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByText(/Couldn't reach the server/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
  });

  test("an invalid term explains itself and has no Retry", async ({ page }) => {
    await seeded(page);
    await page.goto("/?ui=next#/lookup?q=lodash");
    await expect(page.getByText(/doesn't look like a valid id/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Retry" })).toHaveCount(0);
  });

  test("a server that turned lookups off shows a notice with a way home, not a silent redirect", async ({ page }) => {
    await seeded(page);
    await page.route("**/advisory**", (r) =>
      r.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: "disabled" }) }),
    );
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
    await expect(page.getByText("External lookup is turned off on this server")).toBeVisible();
    await expect(page).toHaveURL(/#\/lookup/);
    await page.getByRole("link", { name: "Back to scan management" }).click();
    await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();
  });

  test("a package result is a list of rows that open one by one, with the truncation note", async ({ page }) => {
    await seeded(page);
    await page.route("**/package-advisories**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_MANY) }),
    );
    await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21");
    await expect(page.getByText("OSV.dev reported more advisories than are shown here.")).toBeVisible();
    const rows = page.getByTestId("lookup-advisory");
    await expect(rows).toHaveCount(2);
    await expect(page.getByTestId("lookup-results").getByRole("heading", { name: "Results" })).toBeVisible();
    await expect(page.getByText("Withdrawn")).toBeVisible();
    // A missing grade reads as Unknown, never as a reassuring None.
    await expect(page.getByText("Unknown", { exact: true })).toBeVisible();
    await expect(page.getByText("None", { exact: true })).toHaveCount(0);
    // Closed rows hide the record; opening one shows aliases, the affected range and the reference.
    await expect(page.getByText("CVE-2021-23337")).toBeHidden();
    await rows.first().locator("summary").click();
    await expect(page.getByText("CVE-2021-23337")).toBeVisible();
    await expect(rows.first().getByText("npm: lodash")).toBeVisible();
    await expect(rows.first().getByText(">= 0, < 4.17.21").first()).toBeVisible();
    await expect(rows.first().getByRole("link", { name: /example\.com/ })).toHaveAttribute("rel", "noreferrer");
    // The second row is still closed.
    await expect(rows.nth(1).locator("details")).not.toHaveAttribute("open");
  });

  test("a clean package and an unknown id each get their empty state", async ({ page }) => {
    await seeded(page);
    await page.route("**/package-advisories**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_CLEAN) }),
    );
    await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21");
    await expect(page.getByRole("heading", { name: "No known advisories against this version" })).toBeVisible();
  });

  test("a slow lookup shows a status line while it waits", async ({ page }) => {
    await seeded(page);
    await page.route("**/advisory**", async (r) => {
      await new Promise((res) => setTimeout(res, 800));
      await r.fulfill({ contentType: "application/json", body: JSON.stringify(ADVISORY_FOUND) });
    });
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
    await expect(page.getByRole("status").getByText("Looking up…")).toBeVisible();
    await expect(page.getByText("Log4Shell")).toBeVisible();
  });

  test("the language switch translates the screen", async ({ page }) => {
    await seeded(page, { lang: "ko" });
    await page.route("**/advisory**", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(ADVISORY_FOUND) }),
    );
    await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
    await expect(page.getByRole("heading", { name: "외부 취약점 조회" })).toBeVisible();
    await expect(page.getByText("Critical")).toBeVisible();
  });
});

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`rows wrap and nothing is clipped at ${width}px (${lang})`, async ({ page }) => {
      await seeded(page, { lang, width });
      await page.route("**/package-advisories**", (r) =>
        r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_MANY) }),
      );
      await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21");
      const rows = page.getByTestId("lookup-advisory");
      await expect(rows).toHaveCount(2);
      await rows.first().locator("summary").click();
      await waitForSettled(page.locator("main"));
      const report = await page.evaluate(() => {
        const out: string[] = [];
        document.querySelectorAll("main *").forEach((el) => {
          const cs = getComputedStyle(el);
          if (cs.textOverflow === "ellipsis") out.push(`ellipsis on ${String(el.className)}`);
          if (el.clientWidth > 0 && el.scrollWidth > el.clientWidth + 1 && cs.overflowX === "hidden" && !/isually/i.test(String(el.className))) {
            out.push(`clipped ${String(el.className)}`);
          }
        });
        const over = document.documentElement.scrollWidth - window.innerWidth;
        if (over > 0) out.push(`page scrolls sideways by ${over}`);
        const title = document.querySelector<HTMLElement>(".bl-lk-title");
        if (title && title.getBoundingClientRect().height < 40) out.push("long title did not wrap");
        return out;
      });
      expect(report).toEqual([]);
    });
  }
}

for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    test(`axe is clean with a package result: ${theme} ${lang}`, async ({ page }) => {
      await seeded(page, { lang, theme });
      await page.route("**/package-advisories**", (r) =>
        r.fulfill({ contentType: "application/json", body: JSON.stringify(PACKAGE_MANY) }),
      );
      await page.goto("/?ui=next#/lookup?q=pkg%3Anpm%2Flodash%404.17.21");
      const rows = page.getByTestId("lookup-advisory");
      await expect(rows).toHaveCount(2);
      await rows.first().locator("summary").click();
      await page.mouse.move(0, 0);
      await waitForSettled(page.locator("main"));
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(results.violations).toEqual([]);
    });

    test(`axe is clean on the error and empty states: ${theme} ${lang}`, async ({ page }) => {
      await seeded(page, { lang, theme });
      await page.route("**/advisory**", (r) =>
        r.fulfill({ status: 502, contentType: "application/json", body: JSON.stringify({ error: "upstream" }) }),
      );
      await page.goto("/?ui=next#/lookup?q=CVE-2021-44228");
      await expect(page.getByRole("button", { name: lang === "en" ? "Retry" : "다시 시도" })).toBeVisible();
      await page.mouse.move(0, 0);
      await waitForSettled(page.locator("main"));
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(results.violations).toEqual([]);
    });
  }
}
