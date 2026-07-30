// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test } from "@playwright/test";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Renders docs/images/src/og-card.html into docs/images/og-card.png, the Open
// Graph card the docs site serves (overrides/main.html) and the image uploaded
// as the repository's social preview. Run on demand with `npm run capture:og`;
// the @capture tag keeps it out of the normal `test:ui` run, like the guide
// screenshots in capture.spec.ts.
//
// 1200x630 is the Open Graph size; deviceScaleFactor 2 writes it at 2400x1260
// so the card stays sharp where platforms render it larger.
const IMAGES = "../../../docs/images";

test.use({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 2 });

test("@capture og card", async ({ page }) => {
  const source = path.resolve(process.cwd(), `${IMAGES}/src/og-card.html`);
  await page.goto(pathToFileURL(source).href);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: `${IMAGES}/og-card.png` });
});
