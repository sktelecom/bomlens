import { test, expect, _electron as electron } from "@playwright/test";
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
