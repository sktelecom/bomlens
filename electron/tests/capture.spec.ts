import { test, _electron as electron } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Regenerates the desktop start-screen screenshots used by the docs
// (docs/images/desktop-startup.png ko, desktop-startup-en.png en).
// Opt-in only: run with `SBOM_CAPTURE=1 npx playwright test capture` so the
// regular smoke run (and CI) never overwrites the committed images.
const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const imagesDir = path.resolve(appRoot, "..", "docs", "images");

const SHOTS: Array<{ lang: "en" | "ko"; file: string }> = [
  { lang: "ko", file: "desktop-startup.png" },
  { lang: "en", file: "desktop-startup-en.png" },
];

for (const { lang, file } of SHOTS) {
  test(`capture the start screen (${lang})`, async () => {
    test.skip(process.env.SBOM_CAPTURE !== "1", "opt-in via SBOM_CAPTURE=1");
    const app = await electron.launch({
      args: [appRoot],
      env: { ...process.env, SBOM_SMOKE: "1", SBOM_LANG: lang },
    });
    try {
      const win = await app.firstWindow();
      await win.locator("#subtitle").waitFor();
      await win.locator("#version").waitFor();
      await win.screenshot({ path: path.join(imagesDir, file) });
    } finally {
      await app.close();
    }
  });
}
