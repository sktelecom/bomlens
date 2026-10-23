// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Boots the packaged-source Electron app and checks it reaches its first screen
// in both languages, on whatever OS the runner is (Windows/macOS in CI). This
// catches the "app won't even start / white screen / crash on launch" class
// before a release, per platform. SBOM_SMOKE keeps the app on the status screen
// so it never tries to pull the multi-GB scanner image or talk to Docker.
const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const SUBTITLE: Record<"en" | "ko", string> = {
  en: "The first run downloads the scanner image once.",
  ko: "처음 실행에서는 스캐너 이미지를 한 번 내려받습니다.",
};

// Seeds the docker-missing screen (SBOM_SMOKE_SCREEN) and checks the rebranded
// title plus the "Check again" retry button, without touching Docker at all.
test("docker-missing screen renders the BomLens title and check-again button", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: {
      ...process.env,
      SBOM_SMOKE: "1",
      SBOM_SMOKE_SCREEN: "docker-missing",
      SBOM_LANG: "ko",
    },
  });
  try {
    const win = await app.firstWindow();
    await expect(win).toHaveTitle(/BomLens/);
    await expect(win.locator("#check-again")).toHaveText("다시 확인");
  } finally {
    await app.close();
  }
});

// Pull failures are the likeliest thing an attendee hits on a corporate network, and
// the proxy wording is the single most important string in the app for a venue demo.
// A real failure would need a broken multi-GB download, so the screen is seeded instead.
test("failed-pull renders proxy guidance, retry, and the log button in English", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: {
      ...process.env,
      SBOM_SMOKE: "1",
      SBOM_SMOKE_SCREEN: "failed-pull:proxy",
      SBOM_LANG: "en",
    },
  });
  try {
    const win = await app.firstWindow();
    const help = win.locator("#help");
    await expect(help).toBeVisible();
    // The core correction: the daemon pulls, so app-side proxy settings do nothing.
    await expect(help).toContainText("Docker daemon");
    await expect(help).toContainText("Rancher Desktop");
    await expect(win.locator("#retry")).toBeVisible();
    await expect(win.locator("#open-logs")).toBeVisible();
    // Nothing Korean may reach an English-locale attendee.
    await expect(help).not.toHaveText(/[가-힣]/);
    await expect(win.locator("#log")).not.toHaveText(/[가-힣]/);
    // The failure panel sits inside the failed step, so the cause and the next action read
    // as part of that step, and the detailed log opens by itself.
    await expect(win.locator('li[data-step="image"] #failure')).toBeVisible();
    await expect(win.locator('li[data-step="image"]')).toHaveAttribute("data-state", "failed");
    await expect(win.locator('li[data-step="docker"]')).toHaveAttribute("data-state", "done");
    await expect(win.locator("#copy-log")).toBeVisible();
    await expect(win.locator("#docker-help")).toHaveAttribute("href", /^docker-missing\.html\?/);
    await expect(win.locator("#log-details")).toHaveJSProperty("open", true);
  } finally {
    await app.close();
  }
});

// Each failure mode must give different advice — "check your connection" for a disk-full
// or DNS failure sends the attendee down the wrong path.
test("failed-pull swaps the guidance per reason", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: {
      ...process.env,
      SBOM_SMOKE: "1",
      SBOM_SMOKE_SCREEN: "failed-pull:disk",
      SBOM_LANG: "en",
    },
  });
  try {
    const win = await app.firstWindow();
    await expect(win.locator("#help")).toContainText("disk space");
  } finally {
    await app.close();
  }
});

// The status screen's top-right language toggle swaps only the lang query and
// reloads the same screen, so the copy switches without touching main-process state.
test("language toggle on the status screen switches the copy", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: "en" },
  });
  try {
    const win = await app.firstWindow();
    await expect(win.locator("#subtitle")).toHaveText(SUBTITLE.en);
    // The current language's button is disabled; the other one switches.
    await expect(win.locator('#lang-toggle button[data-lang="en"]')).toBeDisabled();
    await win.locator('#lang-toggle button[data-lang="ko"]').click();
    await expect(win.locator("#subtitle")).toHaveText(SUBTITLE.ko);
    await expect(win.locator('#lang-toggle button[data-lang="ko"]')).toBeDisabled();
  } finally {
    await app.close();
  }
});

for (const lang of ["en", "ko"] as const) {
  test(`desktop app boots and renders the start screen (${lang})`, async () => {
    const app = await electron.launch({
      args: [appRoot],
      env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: lang },
    });
    try {
      const win = await app.firstWindow();
      // Window opened with the real document, not a blank/crashed shell.
      await expect(win).toHaveTitle("BomLens");
      // Localized copy rendered from the ?lang= the main process passed in.
      await expect(win.locator("#subtitle")).toHaveText(SUBTITLE[lang]);
    } finally {
      await app.close();
    }
  });
}

// The status screen's footer must show the app's real version (main.mjs passes
// ?v=app.getVersion()). A broken query wiring renders an empty footer, which no
// other test would notice.
test("status screen displays the app version", async () => {
  const version = JSON.parse(
    fs.readFileSync(path.join(appRoot, "package.json"), "utf8"),
  ).version as string;
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: "en" },
  });
  try {
    const win = await app.firstWindow();
    await expect(win.locator("#version")).toHaveText(`BomLens v${version}`);
  } finally {
    await app.close();
  }
});

// Light/dark contract: the status screen's CSS must follow prefers-color-scheme
// with exactly the colors main.mjs paints the window background with (#fafafa
// light / #111113 dark, the computed shared --background token) — if either side
// drifts, the app flashes the wrong color on first paint. The scheme is emulated at the page level: overriding
// nativeTheme.themeSource in the main process does not reach a file:// page's
// media query in this Electron version, and the app itself never overrides it.
test("status screen styles both color schemes with the first-paint colors", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: "en" },
  });
  try {
    const win = await app.firstWindow();
    await win.waitForLoadState("domcontentloaded");
    await win.emulateMedia({ colorScheme: "light" });
    await expect
      .poll(() => win.evaluate(() => getComputedStyle(document.body).backgroundColor))
      .toBe("rgb(250, 250, 250)");
    await win.emulateMedia({ colorScheme: "dark" });
    await expect
      .poll(() => win.evaluate(() => getComputedStyle(document.body).backgroundColor))
      .toBe("rgb(17, 17, 19)");
  } finally {
    await app.close();
  }
});

// The startup log file must actually be written on boot (userData/startup.log,
// fresh per run) — it is what users attach to problem reports after the status
// screen is long gone. log.mjs is unit-tested, but nothing proved the file
// exists on a real boot until now.
test("startup log file is written and flushed on quit", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: "en" },
  });
  let logPath = "";
  try {
    const win = await app.firstWindow();
    await expect(win.locator("#subtitle")).toBeVisible();
    const userData = await app.evaluate(({ app: a }) => a.getPath("userData"));
    logPath = path.join(userData, "startup.log");
  } finally {
    await app.close();
  }
  // After quit the stream is closed, so the smoke-mode ready line is flushed.
  expect(fs.existsSync(logPath)).toBe(true);
  expect(fs.readFileSync(logPath, "utf8")).toContain("Ready. Opening the UI.");
});

// The start screen is a three-step list. SBOM_SMOKE_SCREEN=pulling seeds the image step
// mid-download with fixed numbers (3 of 7 layers, 94 s), so the layer count, the elapsed time
// and the first-run note are asserted without a real multi-minute pull. The state must be
// readable without colour: every step carries a text state, and the current one is
// aria-current.
const PULLING: Record<"en" | "ko", { layers: string; elapsed: string; note: RegExp; image: string }> = {
  en: {
    layers: "3 of 7 layers done",
    elapsed: "Elapsed 1:34",
    note: /Only on the first run/,
    image: "Download scanner image",
  },
  ko: {
    layers: "레이어 7개 중 3개 완료",
    elapsed: "경과 시간 1:34",
    note: /처음 한 번만 받습니다/,
    image: "스캐너 이미지 내려받기",
  },
};
for (const lang of ["en", "ko"] as const) {
  test(`start screen shows step list and pull progress (${lang})`, async () => {
    const app = await electron.launch({
      args: [appRoot],
      env: { ...process.env, SBOM_SMOKE: "1", SBOM_SMOKE_SCREEN: "pulling", SBOM_LANG: lang },
    });
    try {
      const win = await app.firstWindow();
      const want = PULLING[lang];
      const steps = win.locator("#steps > li");
      await expect(steps).toHaveCount(3);
      const image = win.locator('li[data-step="image"]');
      await expect(image).toHaveAttribute("data-state", "current");
      await expect(image).toHaveAttribute("aria-current", "step");
      await expect(image).toContainText(want.image);
      await expect(image).toContainText(want.layers);
      await expect(image).toContainText(want.elapsed);
      await expect(image).toContainText(want.note);
      const bar = image.getByRole("progressbar");
      await expect(bar).toHaveAttribute("aria-valuenow", "3");
      await expect(bar).toHaveAttribute("aria-valuemax", "7");
      await expect(win.locator('li[data-step="docker"]')).toHaveAttribute("data-state", "done");
      await expect(win.locator('li[data-step="ui"]')).toHaveAttribute("data-state", "pending");
      // Each state has a text label next to the marker.
      await expect(win.locator('li[data-step="docker"] .state-text')).toHaveText(lang === "en" ? "Done" : "완료");
      await expect(win.locator('li[data-step="ui"] .state-text')).toHaveText(lang === "en" ? "Waiting" : "대기 중");
      // The log is collapsed by default and holds the lines main sent.
      await expect(win.locator("#log-details")).toHaveJSProperty("open", false);
      await expect(win.locator("#failure")).toBeHidden();
    } finally {
      await app.close();
    }
  });
}

// The tokens must really reach the window. A packaged build gets the CSS through the
// electron-builder file set; a development run reads it from docker/shared. Either way the
// script sets the "tokens" class on <html>, which is what switches the screen off the
// fallback palette. If neither link resolved, the screen would silently use the fallback.
test("start screen loads the shared design tokens", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: "en" },
  });
  try {
    const win = await app.firstWindow();
    await expect(win.locator("html")).toHaveClass(/tokens/);
    const ring = await win.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--ring").trim());
    expect(ring).not.toBe("");
  } finally {
    await app.close();
  }
});

// The Docker guide shares the tokens and the language toggle with the start screen.
test("docker-missing screen loads the shared design tokens", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_SMOKE_SCREEN: "docker-missing", SBOM_LANG: "en" },
  });
  try {
    const win = await app.firstWindow();
    await expect(win.locator("html")).toHaveClass(/tokens/);
    await expect(win.locator("#check-again")).toHaveText("Check again");
  } finally {
    await app.close();
  }
});
