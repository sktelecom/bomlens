// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, _electron as electron } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Regenerates the desktop start-screen screenshots used by the docs
// (docs/images/desktop-startup.png ko, desktop-startup-en.png en).
// Opt-in only: run with `SBOM_CAPTURE=1 npx playwright test capture` so the
// regular smoke run (and CI) never overwrites the committed images. Set
// SBOM_CAPTURE_DIR to write somewhere else (for example a scratch directory to
// review the shots before replacing the docs images).
const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const imagesDir = process.env.SBOM_CAPTURE_DIR
  ? path.resolve(process.env.SBOM_CAPTURE_DIR)
  : path.resolve(appRoot, "..", "docs", "images");

const SHOTS: Array<{ lang: "en" | "ko"; file: string }> = [
  { lang: "ko", file: "desktop-startup.png" },
  { lang: "en", file: "desktop-startup-en.png" },
];

fs.mkdirSync(imagesDir, { recursive: true });

for (const { lang, file } of SHOTS) {
  test(`capture the start screen (${lang})`, async () => {
    test.skip(process.env.SBOM_CAPTURE !== "1", "opt-in via SBOM_CAPTURE=1");
    const app = await electron.launch({
      args: [appRoot],
      // SBOM_SMOKE_SCREEN=pulling seeds the step list mid-download with fixed numbers
      // (main.mjs), so the shot is the first-run screen and is the same on every run.
      env: { ...process.env, SBOM_SMOKE: "1", SBOM_SMOKE_SCREEN: "pulling", SBOM_LANG: lang },
    });
    try {
      const win = await app.firstWindow();
      await win.locator("#subtitle").waitFor();
      await win.locator("#version").waitFor();
      // Wait for the seeded progress so the shot never catches the empty first render.
      await win.locator('li[data-step="image"] [role="progressbar"]').waitFor();
      await win.mouse.move(0, 0);
      await win.screenshot({ path: path.join(imagesDir, file) });
    } finally {
      await app.close();
    }
  });
}

// Regenerates the Docker-missing guidance screenshot (docs/images/
// desktop-docker-missing.png), used unchanged by both the en and ko docs.
// SBOM_SMOKE_SCREEN=docker-missing (main.mjs) seeds the screen directly
// instead of waiting on a real Docker check, so this is deterministic like
// the start-screen shots above.
test("capture the Docker-missing screen", async () => {
  test.skip(process.env.SBOM_CAPTURE !== "1", "opt-in via SBOM_CAPTURE=1");
  const app = await electron.launch({
    args: [appRoot],
    env: { ...process.env, SBOM_SMOKE: "1", SBOM_SMOKE_SCREEN: "docker-missing", SBOM_LANG: "ko" },
  });
  try {
    const win = await app.firstWindow();
    await win.locator("#version").waitFor();
    await win.mouse.move(0, 0);
    await win.screenshot({ path: path.join(imagesDir, "desktop-docker-missing.png") });
  } finally {
    await app.close();
  }
});
