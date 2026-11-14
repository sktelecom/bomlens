// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// The New scan screen: source tiles in a radio group, the input box, three
// settings boxes, and a one-line action bar that stays on screen with every
// group open. Options that send data off the machine carry the same label.

const CAPS = {
  firmware: false,
  scanoss: true,
  deepLicense: true,
  docker: true,
  reachability: true,
  deepCve: true,
};

async function stub(page: Page, caps: object = CAPS) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
}

async function open(page: Page, caps?: object) {
  await stub(page, caps);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
}

/** Open both folded groups and turn the external transfer on, so the page is as
 *  long as it gets. */
async function expandEverything(page: Page) {
  const groups = { "settings-quality": "Result quality", "settings-format": "Output format" };
  for (const [id, name] of Object.entries(groups)) {
    const group = page.getByTestId(id);
    if ((await group.count()) && (await group.getAttribute("open")) === null) {
      await group.getByText(name, { exact: true }).click();
    }
  }
  const upload = page.getByRole("switch", { name: "Upload to a server" });
  if (await upload.count()) {
    if ((await upload.getAttribute("aria-checked")) === "false") await upload.click();
  }
}

async function noHorizontalScroll(page: Page) {
  const over = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(over, "the page does not scroll sideways").toBeLessThanOrEqual(0);
}

for (const [width, height] of [
  [1280, 800],
  [1024, 768],
] as const) {
  test(`the action bar stays in the window with every group open at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await open(page);
    await expandEverything(page);

    const bar = page.getByTestId("action-bar");
    const run = page.getByTestId("run-scan");
    // The page is long now; check the bar from the top and from the bottom.
    for (const y of [0, 100000]) {
      await page.evaluate((top) => window.scrollTo(0, top), y);
      await expect(bar).toBeInViewport({ ratio: 1 });
      await expect(run).toBeInViewport({ ratio: 1 });
    }
    await page.evaluate(() => window.scrollTo(0, 0));
    const scrollable = await page.evaluate(
      () => document.documentElement.scrollHeight - window.innerHeight,
    );
    expect(scrollable, "opening the groups makes the page longer than the window").toBeGreaterThan(200);

    const box = (await bar.boundingBox())!;
    expect(box.height).toBeLessThanOrEqual(72);
    expect(box.y + box.height).toBeLessThanOrEqual(height);

    if (width >= 1280) {
      // One line: the name, version, both switches and the button share a row.
      const parts = [
        page.locator("#project"),
        page.locator("#version"),
        page.getByRole("switch", { name: "Notice" }),
        page.getByRole("switch", { name: "Security report" }),
        run,
      ];
      const mids: number[] = [];
      for (const p of parts) {
        const b = (await p.boundingBox())!;
        mids.push(b.y + b.height / 2);
      }
      expect(Math.max(...mids) - Math.min(...mids)).toBeLessThanOrEqual(16);
    }
    await noHorizontalScroll(page);
  });
}

test("no source type makes the page scroll sideways", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await open(page, { ...CAPS, firmware: true, aibom: true, aiDeclare: true, spdx3: true });
  const sources = [
    "current-dir",
    "rootfs-dir",
    "git-url",
    "zip-upload",
    "docker-image",
    "package-upload",
    "firmware-upload",
    "sbom-upload",
    "ai-model",
    "model-upload",
    "ai-declare",
  ];
  for (const s of sources) {
    await page.getByTestId(`source-${s}`).click();
    await expandEverything(page);
    await noHorizontalScroll(page);
  }
  await page.setViewportSize({ width: 1280, height: 800 });
  await noHorizontalScroll(page);
});

test("the source tiles are a radio group that arrow keys move through", async ({ page }) => {
  await open(page, { ...CAPS, firmware: true, aibom: true, aiDeclare: false });
  const group = page.getByRole("radiogroup", { name: "Source" });
  await expect(group.getByRole("radio")).toHaveCount(11);
  // One tab stop: the selected tile.
  await expect(group.locator('[role="radio"][tabindex="0"]')).toHaveCount(1);
  await expect(page.getByTestId("source-current-dir")).toHaveAttribute("aria-checked", "true");
  await expect(page.getByTestId("source-current-dir")).toHaveAttribute("tabindex", "0");

  await page.getByTestId("source-current-dir").focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByTestId("source-rootfs-dir")).toBeFocused();
  await expect(page.getByTestId("source-rootfs-dir")).toHaveAttribute("aria-checked", "true");
  await expect(page.getByTestId("source-current-dir")).toHaveAttribute("aria-checked", "false");
  await expect(page.getByTestId("source-rootfs-dir")).toHaveAttribute("tabindex", "0");
  await expect(page.getByTestId("source-current-dir")).toHaveAttribute("tabindex", "-1");

  await page.keyboard.press("ArrowDown");
  await expect(page.getByTestId("source-git-url")).toBeFocused();
  await page.keyboard.press("ArrowLeft");
  await expect(page.getByTestId("source-rootfs-dir")).toBeFocused();
  await page.keyboard.press("End");
  // The last tile (the declaration) is locked here: it takes focus, not the selection.
  await expect(page.getByTestId("source-ai-declare")).toBeFocused();
  await expect(page.getByTestId("source-ai-declare")).toHaveAttribute("aria-checked", "false");
  await expect(page.getByTestId("source-rootfs-dir")).toHaveAttribute("aria-checked", "true");
  await page.keyboard.press("Home");
  await expect(page.getByTestId("source-current-dir")).toBeFocused();
  await expect(page.getByTestId("source-current-dir")).toHaveAttribute("aria-checked", "true");
  // Wraps at the first tile.
  await page.keyboard.press("ArrowLeft");
  await expect(page.getByTestId("source-ai-declare")).toBeFocused();
  // Tab leaves the group in one step.
  await page.keyboard.press("Tab");
  const inGroup = await page.evaluate(
    () => document.activeElement?.closest('[role="radiogroup"]') !== null,
  );
  expect(inGroup).toBe(false);
});

test("a locked tile says why, in text, and cannot be chosen", async ({ page }) => {
  await open(page, { ...CAPS, firmware: false, aibom: false, aiDeclare: false });
  for (const id of ["source-firmware-upload", "source-ai-model", "source-ai-declare"]) {
    const tile = page.getByTestId(id);
    await expect(tile).toHaveAttribute("aria-disabled", "true");
    const reason = await tile.getAttribute("aria-describedby");
    expect(reason).toMatch(/^lock-/);
    await expect(page.locator(`#${reason}`)).toBeVisible();
    await tile.click({ force: true });
    await expect(tile).toHaveAttribute("aria-checked", "false");
  }
  await expect(page.getByTestId("source-current-dir")).toHaveAttribute("aria-checked", "true");
});

test("options that send data out carry the same mark", async ({ page }) => {
  await open(page);
  await page.getByText("Result quality").click();
  const marks = page.getByTestId("external-mark");
  await expect(marks).toHaveCount(2);
  const lookup = page.getByTestId("option-identifyVendored");
  await expect(lookup.getByTestId("external-mark")).toBeVisible();
  const upload = page.getByTestId("option-upload");
  await expect(upload.getByTestId("external-mark")).toBeVisible();
});

test("conformance, license, author and version sit under Output format", async ({ page }) => {
  await open(page);
  await page.getByText("Output format").click();
  await expect(page.locator("#outbound-license")).toBeVisible();
  await expect(page.locator("#sbom-author")).toBeVisible();
  await expect(page.locator("#spec-version")).toBeVisible();
  await expect(page.locator("#conformance-profile")).toBeVisible();
});

test("a collapsed group counts the options that differ from the default", async ({ page }) => {
  await open(page);
  const quality = page.getByTestId("settings-quality");
  const format = page.getByTestId("settings-format");
  const toggleQuality = () => quality.getByText("Result quality", { exact: true }).click();
  const toggleFormat = () => format.getByText("Output format", { exact: true }).click();
  // Nothing differs: no count.
  await expect(quality.getByText(/^\d+ on$/)).toHaveCount(0);
  await expect(format.getByText(/^\d+ on$/)).toHaveCount(0);

  await toggleQuality();
  await page.getByRole("switch", { name: "Per-file license scan" }).click();
  await page.getByRole("switch", { name: "Reproducible output" }).click();
  await toggleQuality();
  await expect(quality).not.toHaveAttribute("open", "");
  // Collapsed, the count is still readable, as a number and as text.
  await expect(quality.getByText(/^2$/)).toBeVisible();
  await expect(quality.getByText("2 on")).toHaveCount(1);

  await toggleFormat();
  await page.locator("#outbound-license").fill("Apache-2.0");
  await page.locator("#spec-version").selectOption("1.7");
  await toggleFormat();
  await expect(format.getByText(/^2$/)).toBeVisible();

  // Back to the default: the count goes away; the group the reader is in does
  // not close under them.
  await toggleFormat();
  await page.locator("#outbound-license").fill("");
  await page.locator("#spec-version").selectOption("1.6");
  await expect(format).toHaveAttribute("open", "");
  await expect(format.getByText(/^\d+ on$/)).toHaveCount(0);
});

test("one alert sums up what is missing; field messages stay at the fields", async ({ page }) => {
  await open(page);
  await page.getByTestId("source-git-url").click();
  await page.locator("#project").fill("");
  await page.locator("#version").fill("");
  await page.getByTestId("run-scan").click();

  const alerts = page.locator("main").getByRole("alert");
  await expect(alerts).toHaveCount(1);
  await expect(alerts).toHaveText("Fill in the required fields: Project name, Version, GitHub URL");
  // The target field keeps its own message, and is described by it.
  await expect(page.getByText("Enter the scan target.")).toBeVisible();
  await expect(page.locator("#target")).toHaveAttribute("aria-invalid", "true");
  expect(await page.locator("#target").getAttribute("aria-describedby")).toContain("target-validationMessage");
  // Focus lands on the first invalid field, as before.
  await expect(page.locator("#project")).toBeFocused();
  // The alert sits right above the action bar, not at the fields.
  const alertBox = (await alerts.boundingBox())!;
  const barBox = (await page.getByTestId("action-bar").boundingBox())!;
  expect(alertBox.y + alertBox.height).toBeLessThanOrEqual(barBox.y + 1);

  // Fixing the fields clears it.
  await page.locator("#project").fill("demo");
  await page.locator("#version").fill("1.0");
  await page.locator("#target").fill("https://github.com/acme/demo.git");
  await expect(alerts).toHaveCount(0);
  await expect(page.getByText("Enter the scan target.")).toHaveCount(0);
});

test("a long hint is cut to two lines; More opens it and Less closes it", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await open(page);
  await page.getByText("Result quality").click();
  const toggle = page.getByRole("switch", { name: "Per-file license scan" });
  const textId = (await toggle.getAttribute("aria-describedby"))!;
  const text = page.locator(`[id="${textId}"]`);
  const full = (await text.textContent())!;
  expect(full.length).toBeGreaterThan(80);

  const more = page.getByRole("button", { name: /^More\W*Per-file license scan$/ });
  await expect(more).toBeVisible();
  await expect(more).toHaveAttribute("aria-expanded", "false");
  expect(await more.getAttribute("aria-controls")).toBe(textId);
  // The whole text is in the page; the button is not part of what describes the switch.
  await expect(text).toHaveText(full);
  const inside = await more.evaluate((b, id) => document.getElementById(id)!.contains(b), textId);
  expect(inside).toBe(false);
  const clamped = await text.evaluate((e) => ({ over: e.scrollHeight > e.clientHeight, lines: getComputedStyle(e).webkitLineClamp }));
  expect(clamped).toEqual({ over: true, lines: "2" });

  await more.focus();
  await page.keyboard.press("Enter");
  const less = page.getByRole("button", { name: /^Less\W*Per-file license scan$/ });
  await expect(less).toHaveAttribute("aria-expanded", "true");
  await expect(less).toBeFocused();
  const expanded = await text.evaluate((e) => ({ over: e.scrollHeight > e.clientHeight + 1, lines: getComputedStyle(e).webkitLineClamp }));
  expect(expanded).toEqual({ over: false, lines: "none" });
  await expect(text).toHaveText(full);

  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: /^More\W*Per-file license scan$/ })).toHaveAttribute(
    "aria-expanded",
    "false",
  );
  // A hint that fits in two lines has no button; one that does not, has.
  const mismatched = await page.evaluate(() =>
    [...document.querySelectorAll<HTMLElement>(".bl-hint-text[data-clamped]")].filter((el) => {
      const cut = el.scrollHeight > el.clientHeight + 1;
      const button = el.parentElement?.querySelector(".bl-hint-button") !== null;
      return cut !== button;
    }).length,
  );
  expect(mismatched).toBe(0);
});

test("the external transfer is one row that opens its form when switched on", async ({ page }) => {
  await open(page);
  const row = page.getByTestId("settings-transfer");
  await expect(row).toContainText("External transfer (optional)");
  await expect(page.locator("#uploadUrl")).toHaveCount(0);
  await page.getByRole("switch", { name: "Upload to a server" }).click();
  await expect(page.locator("#uploadUrl")).toBeVisible();
  await expect(page.locator("#uploadToken")).toBeVisible();
  await expect(page.locator("#truscaProjectId")).toHaveCount(0);
  await page.locator("#uploadTarget").selectOption("trusca");
  await expect(page.locator("#truscaProjectId")).toBeVisible();
  // Its fields report their own errors and the one alert counts them.
  await page.getByTestId("run-scan").click();
  await expect(page.locator("main").getByRole("alert")).toHaveCount(1);
  await expect(page.getByText("Enter the upload server URL.")).toBeVisible();
});

async function dropFile(page: Page, name: string) {
  await page.evaluate((fileName) => {
    const dt = new DataTransfer();
    dt.items.add(new File(["x"], fileName));
    const zone = document.querySelector('[data-testid="dropzone"]')!;
    zone.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true }));
  }, name);
}

test("a firmware .zip is accepted by drop, and a file of another type is refused", async ({ page }) => {
  await open(page, { ...CAPS, firmware: true });
  await page.getByTestId("source-firmware-upload").click();
  await expect(page.locator("#file")).toHaveAttribute("accept", /\.zip/);
  await dropFile(page, "router-fw-1.2.zip");
  await expect(page.getByTestId("dropzone-name")).toHaveText("router-fw-1.2.zip");
  await page.getByRole("button", { name: "Remove the chosen file" }).click();
  await dropFile(page, "notes.txt");
  await expect(page.getByTestId("dropzone-name")).toHaveCount(0);
  await expect(page.getByRole("alert").filter({ hasText: "notes.txt" })).toBeVisible();
});

test("every tile's accessible name contains the name it shows", async ({ page }) => {
  await open(page, { ...CAPS, firmware: true, aibom: true, aiDeclare: true });
  const tiles = page.getByRole("radiogroup", { name: "Source" }).getByRole("radio");
  const count = await tiles.count();
  expect(count).toBe(11);
  for (let i = 0; i < count; i++) {
    const tile = tiles.nth(i);
    const shown = ((await tile.locator(".bl-tile-label").textContent()) ?? "").trim();
    expect(shown.length).toBeGreaterThan(0);
    // Playwright's name match is "contains": the tile is found by what it shows.
    await expect(page.getByRole("radio", { name: shown, exact: false })).toContainText(shown);
    const name = await tile.evaluate((el) => (el.getAttribute("aria-label") ?? el.textContent ?? "").trim());
    expect(name.toLowerCase()).toContain(shown.toLowerCase());
  }
});

test("source rows are named groups, and no tile name is cut at 1024px", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await open(page, { ...CAPS, firmware: true, aibom: true, aiDeclare: true });
  for (const name of ["Code", "Build artifact", "SBOM", "AI model"]) {
    await expect(page.getByRole("radiogroup", { name: "Source" }).getByRole("group", { name })).toBeVisible();
  }
  const cut = await page.evaluate(() =>
    [...document.querySelectorAll<HTMLElement>('[role="radio"] > span')]
      .filter((el) => el.scrollWidth > el.clientWidth || getComputedStyle(el).textOverflow === "ellipsis")
      .map((el) => el.textContent),
  );
  expect(cut).toEqual([]);
});

test("pressing a switch's name or description flips it, but the More button does not", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await open(page);
  await page.getByTestId("settings-quality").getByText("Result quality", { exact: true }).click();
  const row = page.getByTestId("option-deepLicense");
  const sw = row.getByRole("switch", { name: "Per-file license scan" });
  await expect(sw).toHaveAttribute("aria-checked", "false");
  await row.getByText("Per-file license scan", { exact: true }).click();
  await expect(sw).toHaveAttribute("aria-checked", "true");
  const description = (await sw.getAttribute("aria-describedby"))!;
  await page.locator(`[id="${description}"]`).click();
  await expect(sw).toHaveAttribute("aria-checked", "false");
  await row.getByRole("button", { name: /^More/ }).click();
  await expect(sw).toHaveAttribute("aria-checked", "false");
});

test("output switch descriptions open from an info button into the line above the bar", async ({ page }) => {
  await open(page);
  const bar = page.getByTestId("action-bar");
  const before = (await bar.boundingBox())!.height;
  const info = page.getByRole("button", { name: "About Notice" });
  await expect(info).toHaveAttribute("aria-expanded", "false");
  const controls = (await info.getAttribute("aria-controls"))!;
  await expect(page.locator(`[id="${controls}"]`)).toBeHidden();
  await info.click();
  await expect(info).toHaveAttribute("aria-expanded", "true");
  const text = page.locator(`[id="${controls}"]`);
  await expect(text).toBeVisible();
  await expect(text).toHaveText("Generate the open-source license NOTICE");
  expect((await bar.boundingBox())!.height).toBeCloseTo(before, 0);
  // The switch is described by the same text whether or not it is open.
  await expect(page.getByRole("switch", { name: "Notice" })).toHaveAccessibleDescription("Generate the open-source license NOTICE");
  await info.click();
  await expect(text).toBeHidden();

});

test("the AI notice hint is part of the notice description for an AI source", async ({ page }) => {
  await open(page, { ...CAPS, aibom: true });
  await page.getByTestId("source-ai-model").click();
  await page.getByRole("button", { name: "About Notice" }).click();
  await expect(page.getByText(/lists the model and dataset licenses/)).toBeVisible();
});

test("a switch the form turned on says why, stays in the Tab order and cannot be changed", async ({ page }) => {
  await open(page);
  await page.getByTestId("source-sbom-upload").click();
  const security = page.getByRole("switch", { name: "Security report" });
  await expect(security).toHaveAttribute("aria-checked", "true");
  await expect(security).toHaveAttribute("aria-disabled", "true");
  await expect(page.getByText("Notice and security report are always on when you analyze an SBOM.")).toBeVisible();
  await security.focus();
  await expect(security).toBeFocused();
  await security.click({ force: true });
  await expect(security).toHaveAttribute("aria-checked", "true");
  await expect(security).toHaveAccessibleDescription(/always on when you analyze an SBOM/);
});

test("the file input's focus is drawn on the dropzone, from Tab and from a failed submit", async ({ page }) => {
  await open(page);
  await page.getByTestId("source-zip-upload").click();
  const zone = page.getByTestId("dropzone");
  const ring = () => zone.evaluate((el) => getComputedStyle(el).outlineStyle + " " + getComputedStyle(el).outlineWidth);
  expect(await ring()).toMatch(/^none/);
  await page.locator("#file").focus();
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Tab");
  await expect(page.locator("#file")).toBeFocused();
  expect(await ring()).toBe("solid 2px");
  await page.locator("#project").fill("demo");
  await page.locator("#version").fill("1.0");
  expect(await ring()).toMatch(/^none/);
  await page.getByTestId("run-scan").click();
  await expect(page.locator("#file")).toBeFocused();
  expect(await ring()).toBe("solid 2px");
});

test("a field focused after a failed submit is not hidden behind the action bar", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await open(page);
  await expandEverything(page);
  await page.locator("#project").fill("demo");
  await page.locator("#version").fill("1.0");
  await page.getByTestId("run-scan").click();
  await expect(page.locator("#uploadUrl")).toBeFocused();
  const alertBox = (await page.locator("main").getByRole("alert").boundingBox())!;
  const fieldBox = (await page.locator("#uploadUrl").boundingBox())!;
  expect(fieldBox.y + fieldBox.height).toBeLessThanOrEqual(alertBox.y);
});

for (const [width, height] of [
  [1280, 800],
  [1440, 900],
] as const) {
  test(`New scan opens at the top with the title and the tiles in view at ${width}x${height}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await open(page);
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
    await expect(page.getByRole("heading", { name: "What do you want to scan?" })).toBeInViewport({ ratio: 1 });
    await expect(page.getByTestId("source-current-dir")).toBeInViewport({ ratio: 1 });
    await expect(page.getByTestId("source-ai-model")).toBeInViewport({ ratio: 1 });
  });
}
