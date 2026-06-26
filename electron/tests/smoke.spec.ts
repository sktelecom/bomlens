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
