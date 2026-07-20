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
  en: "Getting ready. On the first run, downloading the scanner image can take a few minutes.",
  ko: "준비 중입니다. 처음 실행이면 스캐너 이미지를 내려받느라 수 분 걸릴 수 있어요.",
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
// with exactly the colors main.mjs paints the window background with (#f5f5f7
// light / #0a0a0c dark) — if either side drifts, the app flashes the wrong
// color on first paint. The scheme is emulated at the page level: overriding
// nativeTheme.themeSource in the main process does not reach a file:// page's
// media query in this Electron version, and the app itself never overrides it.
test("status screen styles both color schemes with the first-paint colors", async () => {
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: "en" },
  });
  try {
    const win = await app.firstWindow();
    await win.emulateMedia({ colorScheme: "light" });
    await expect
      .poll(() => win.evaluate(() => getComputedStyle(document.body).backgroundColor))
      .toBe("rgb(245, 245, 247)");
    await win.emulateMedia({ colorScheme: "dark" });
    await expect
      .poll(() => win.evaluate(() => getComputedStyle(document.body).backgroundColor))
      .toBe("rgb(10, 10, 12)");
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
