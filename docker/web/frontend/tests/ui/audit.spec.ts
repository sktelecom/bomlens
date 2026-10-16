// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

import { expect, test, type Page } from "@playwright/test";

// Before/after audit capture set, run on demand: `npm run capture:audit`.
//
// This is NOT a visual baseline. The PNGs are for a person to put side by side
// across a UI change, so nothing here is compared to a stored image. The scene
// list and the file names follow the October 2026 audit
// (`NN-name-width-theme-lang.png`), so a new run lines up with the old one.
//
// Data and build: the audit was taken on the read-only demo, so this spec
// builds the same demo bundle (VITE_DEMO_DATA_BASE set) into `dist-audit/`,
// serves it with `vite preview` on its own port, and answers the demo's data
// requests from the tracked capture in docs/demo/data. No server, Docker or
// network is involved, and the normal `dist/` is left alone.
//
// Safety: like capture.spec.ts it is skipped unless AUDIT=1 (the @audit tag is
// also excluded by `test:ui` and `test:visual`), and it refuses to write
// anywhere under the repository's docs/ folder.
test.skip(process.env.AUDIT !== "1", "opt-in via AUDIT=1 (npm run capture:audit)");

const FRONTEND = process.cwd(); // Playwright runs from docker/web/frontend
const REPO = resolve(FRONTEND, "..", "..", "..");
const DEMO_DATA = join(REPO, "docs", "demo", "data");
const DATA_BASE = "/demo-data";
const PORT = Number(process.env.AUDIT_PORT ?? 4174);
const ORIGIN = `http://localhost:${PORT}`;
const OUT = resolve(process.env.AUDIT_OUT ?? join(FRONTEND, "audit-out"));

if (!relative(join(REPO, "docs"), OUT).startsWith("..")) {
  throw new Error(`AUDIT_OUT must not be inside docs/ (got ${OUT})`);
}

type Theme = "light" | "dark";
type Lang = "en" | "ko";

// Scan ids in docs/demo/data. Note: the 2026-10 audit named its 03-09 files
// "source-*" and 14 "supplier-*", but the screens it holds are the received
// SBOM scan (FlaskDataService) and the source scan (SpringBootDemo). The scene
// numbers and file names are kept as they were; the data follows the pictures.
const FLASK = "FlaskDataService_3.2.0"; // received-SBOM scan
const SPRING = "SpringBootDemo_1.0.0"; // source scan
const NGINX = "NginxRuntimeImage_1.24-alpine"; // container image
const RASPI = "RaspberryPiOsLite_2026-06-18"; // firmware
const BERT = "BertBaseUncased_1.0"; // AI model

type Scene = {
  n: string;
  name: string;
  width: number;
  height: number;
  hash: string;
  combos: Array<{ theme: Theme; lang: Lang }>;
  /** Extra state to reach after the page has loaded. */
  act?: (page: Page) => Promise<void>;
  /** Grow the viewport to the content height (the app scrolls inside `main`, so
   *  Playwright's fullPage option would only capture the viewport). */
  fitHeight?: boolean;
  /** Extra settle time for canvas views (ms). */
  wait?: number;
};

const WIDE = [
  { theme: "dark" as Theme, lang: "en" as Lang },
  { theme: "light" as Theme, lang: "ko" as Lang },
];
const NARROW = [{ theme: "light" as Theme, lang: "en" as Lang }];

const wide = (n: string, name: string, hash: string, extra: Partial<Scene> = {}): Scene => ({
  n, name, width: 1440, height: 900, hash, combos: WIDE, ...extra,
});
const narrow = (n: string, name: string, hash: string, extra: Partial<Scene> = {}): Scene => ({
  n, name, width: 1024, height: 768, hash, combos: NARROW, ...extra,
});

const SCENES: Scene[] = [
  wide("01", "scan-list", "#/"),
  wide("02", "new-scan", "#/new"),
  wide("03", "source-overview", `#/scan/${FLASK}`),
  wide("04", "source-components", `#/scan/${FLASK}/components`),
  wide("05", "source-dependencies", `#/scan/${FLASK}/dependencies`, { wait: 2500 }),
  wide("06", "source-vulnerabilities", `#/scan/${FLASK}/vulnerabilities`),
  wide("07", "source-licenses", `#/scan/${FLASK}/licenses`),
  wide("08", "source-conformance", `#/scan/${FLASK}/conformance`),
  wide("09", "source-artifacts", `#/scan/${FLASK}/artifacts`),
  wide("10", "container-overview", `#/scan/${NGINX}`),
  wide("11", "firmware-overview", `#/scan/${RASPI}`),
  wide("12", "ai-overview", `#/scan/${BERT}`),
  wide("13", "ai-models", `#/scan/${BERT}/models`),
  wide("14", "supplier-overview", `#/scan/${SPRING}`),
  narrow("20", "scan-list", "#/"),
  narrow("21", "new-scan", "#/new"),
  narrow("22", "overview", `#/scan/${FLASK}`),
  narrow("23", "components", `#/scan/${FLASK}/components`),
  narrow("24", "vulnerabilities", `#/scan/${FLASK}/vulnerabilities`),
  narrow("25", "firmware-vulnerabilities", `#/scan/${RASPI}/vulnerabilities`),
  narrow("26", "container-components", `#/scan/${NGINX}/components`),
  // The whole page, with the advanced and upload disclosures opened.
  narrow("27", "new-scan-advanced-open", "#/new", {
    fitHeight: true,
    act: async (page) => {
      await page.locator("summary", { hasText: /advanced scan options/i }).click();
      await page.locator("summary", { hasText: /upload \(optional\)/i }).click();
    },
  }),
  narrow("28", "help-menu", `#/scan/${FLASK}`, {
    act: async (page) => {
      await page.getByTestId("help-menu").click();
      await page.getByText(/^Version /).waitFor();
    },
  }),
  // Tree view, reached by keyboard so the focus ring on the toggle shows.
  narrow("29", "dependency-tree", `#/scan/${FLASK}/dependencies`, {
    act: async (page) => {
      const tree = page.getByRole("button", { name: "Tree" });
      await tree.waitFor();
      await tree.focus();
      await page.keyboard.press("Enter");
      await page.getByText("pkg:pypi/app@latest").first().waitFor();
    },
  }),
  // Keyboard focus ring on the rail's Dependencies link.
  narrow("30", "focus-ring", `#/scan/${FLASK}`, {
    act: async (page) => {
      for (let i = 0; i < 40; i++) {
        await page.keyboard.press("Tab");
        const onDeps = await page.evaluate(
          () => (document.activeElement as HTMLAnchorElement | null)?.getAttribute("href")?.endsWith("/dependencies") ?? false,
        );
        if (onDeps) return;
      }
      throw new Error("Dependencies rail link never received keyboard focus");
    },
  }),
];

const MIME: Record<string, string> = {
  ".json": "application/json",
  ".html": "text/html",
  ".txt": "text/plain",
  ".zip": "application/zip",
};

// Answer the demo bundle's data requests from docs/demo/data, confined to that
// folder so a crafted path cannot read anything else.
async function serveDemoData(page: Page) {
  await page.route(`**${DATA_BASE}/**`, async (route) => {
    const rel = decodeURIComponent(new URL(route.request().url()).pathname.slice(DATA_BASE.length));
    const file = resolve(DEMO_DATA, "." + rel);
    const inside = relative(DEMO_DATA, file);
    if (inside.startsWith("..") || !existsSync(file) || !statSync(file).isFile()) {
      return route.fulfill({ status: 404, body: "not found" });
    }
    return route.fulfill({
      contentType: MIME[extname(file)] ?? "application/octet-stream",
      body: readFileSync(file),
    });
  });
}

let preview: ChildProcess | undefined;

test.describe.configure({ mode: "serial" }); // one worker, one demo build

test.beforeAll(async () => {
  test.setTimeout(240_000);
  mkdirSync(OUT, { recursive: true });
  execFileSync("npx", ["vite", "build", "--outDir", "dist-audit", "--emptyOutDir"], {
    cwd: FRONTEND,
    stdio: "ignore",
    env: { ...process.env, VITE_DEMO_DATA_BASE: DATA_BASE },
  });
  preview = spawn(
    "npx",
    ["vite", "preview", "--outDir", "dist-audit", "--port", String(PORT), "--strictPort"],
    { cwd: FRONTEND, stdio: "ignore" },
  );
  // Wait until the preview server answers.
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(ORIGIN)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("audit preview server did not start");
});

test.afterAll(() => {
  preview?.kill();
});

for (const scene of SCENES) {
  for (const { theme, lang } of scene.combos) {
    const file = `${scene.n}-${scene.name}-${scene.width}-${theme}-${lang}.png`;
    test(`@audit ${file}`, async ({ page }) => {
      await page.setViewportSize({ width: scene.width, height: scene.height });
      await page.addInitScript(
        ([t, l]) => {
          localStorage.setItem("sbom.theme", t);
          localStorage.setItem("sbom.lang", l);
        },
        [theme, lang],
      );
      await serveDemoData(page);
      await page.goto(`${ORIGIN}/${scene.hash}`);
      await page.locator("main h1").first().waitFor();
      if (scene.hash === "#/") await page.getByText("FlaskDataService").first().waitFor();
      await page.waitForLoadState("networkidle");
      await scene.act?.(page);
      if (scene.wait) await page.waitForTimeout(scene.wait);
      // Let fade-ins finish, then park the pointer so no hover state leaks in.
      await page.locator("main").evaluate(async (el) => {
        await Promise.all(el.getAnimations().map((a) => a.finished.catch(() => undefined)));
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      });
      if (scene.fitHeight) {
        const full = await page.locator("main").evaluate((el) => {
          el.scrollTop = 0;
          return Math.ceil(el.getBoundingClientRect().top + el.scrollHeight);
        });
        await page.setViewportSize({ width: scene.width, height: full });
        await page.locator("main").evaluate(
          () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))),
        );
      }
      if (scene.n !== "28") await page.mouse.move(0, 0);
      await page.screenshot({
        path: join(OUT, file),
        animations: "disabled",
      });
      expect(existsSync(join(OUT, file))).toBe(true);
    });
  }
}
