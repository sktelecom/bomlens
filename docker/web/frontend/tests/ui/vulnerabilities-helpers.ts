// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Locator, Page } from "@playwright/test";

/**
 * Shared stubs for the Vulnerabilities specs: a scan whose security summary the
 * test supplies, opened on its Vulnerabilities section with the backend routes
 * stubbed.
 */

export const ID = "vulns_1.0";

export interface Vuln {
  id: string;
  severity: string;
  pkg: string;
  installed: string;
  fixed: string;
  title?: string;
  [key: string]: unknown;
}

/** urllib3: fixed at 2.5.0 (1 CVE), 2.6.0 (2 more) and 2.8.0 (2 more), one with
 *  no fix. Upgrading to 2.8.0 therefore resolves 5, to 2.6.0 resolves 3. */
export const VULNS: Vuln[] = [
  { id: "CVE-2024-4001", severity: "CRITICAL", pkg: "urllib3", installed: "2.1.0", fixed: "2.8.0", title: "urllib3 flaw one", cvss: 9.8 },
  { id: "CVE-2024-4002", severity: "HIGH", pkg: "urllib3", installed: "2.1.0", fixed: "2.8.0", title: "urllib3 flaw two", cvss: 7.5 },
  { id: "CVE-2024-4003", severity: "MEDIUM", pkg: "urllib3", installed: "2.1.0", fixed: "2.6.0", title: "urllib3 flaw three", cvss: 5.3 },
  { id: "CVE-2024-4004", severity: "LOW", pkg: "urllib3", installed: "2.1.0", fixed: "2.6.0", title: "urllib3 flaw four", cvss: 3.1 },
  { id: "CVE-2024-4005", severity: "HIGH", pkg: "urllib3", installed: "2.1.0", fixed: "2.5.0", title: "urllib3 flaw five", cvss: 7.1 },
  { id: "CVE-2024-4006", severity: "LOW", pkg: "urllib3", installed: "2.1.0", fixed: "", title: "urllib3 flaw six", cvss: 2.0 },
  { id: "CVE-2024-4101", severity: "HIGH", pkg: "qs", installed: "6.15.3", fixed: "6.16.0", title: "qs prototype pollution", cvss: 7.5 },
  { id: "CVE-2024-4102", severity: "MEDIUM", pkg: "qs", installed: "6.15.3", fixed: "6.16.0", title: "qs denial of service", cvss: 5.9 },
  { id: "CVE-2024-4201", severity: "HIGH", pkg: "lodash", installed: "4.17.20", fixed: "4.17.21", title: "lodash command injection", cvss: 7.2, kev: true },
  { id: "CVE-2024-4301", severity: "CRITICAL", pkg: "zlib", installed: "1.2.11", fixed: "", title: "zlib memory corruption", cvss: 9.8 },
];

export function security(vulns: Vuln[], extra: Record<string, unknown> = {}) {
  const n = (s: string) => vulns.filter((v) => v.severity === s).length;
  return {
    CRITICAL: n("CRITICAL"),
    HIGH: n("HIGH"),
    MEDIUM: n("MEDIUM"),
    LOW: n("LOW"),
    UNKNOWN: n("UNKNOWN"),
    TOTAL: vulns.length,
    vulnerabilities: vulns,
    ...extra,
  };
}

export interface OpenOptions {
  /** The scan's security summary; null for a scan with no security report. */
  security?: Record<string, unknown> | null;
  scanId?: string;
}

/** Open the Vulnerabilities section of a stubbed scan at `query` (no leading `?`). */
export async function openVulns(page: Page, query = "", opts: OpenOptions = {}) {
  const scanId = opts.scanId ?? ID;
  const sec = opts.security === undefined ? security(VULNS) : opts.security;
  const done = {
    ok: true,
    mode: "SOURCE",
    id: scanId,
    results: [{ name: `${scanId}_bom.json`, size: 100 }],
    conformance: null,
    security: sec,
    sbom: { components: 1, componentList: [{ name: "urllib3", version: "2.1.0", group: "", type: "library", licenses: ["MIT"], purl: "pkg:pypi/urllib3@2.1.0" }] },
  };
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${scanId}`, (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }));
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: "{}" }));
  await page.goto(`/?ui=next#/scan/${scanId}/vulnerabilities${query ? `?${query}` : ""}`);
  await page.getByTestId("result-meta").waitFor();
}

export const hashOf = (page: Page) => page.evaluate(() => window.location.hash);

/** The table row of a CVE: the row that holds its title button. */
export const rowOf = (page: Page, id: string): Locator =>
  page.getByRole("row").filter({ has: page.locator(`[data-open-id="${id}"]`) });

/** The button that opens a CVE's detail panel. */
export const openerOf = (page: Page, id: string): Locator => page.locator(`[data-open-id="${id}"]`);
