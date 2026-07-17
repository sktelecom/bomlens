import { expect, test, type Page } from "@playwright/test";

/**
 * New-scan identity autofill: project/version are prefilled from the scan
 * source (host folder, git repo name, docker image name/tag) while the user
 * hasn't touched the fields — and never overwrite a user edit. The backend is
 * stubbed (capabilities carries the hostDir the UI was launched from), so the
 * suggestions are exercised without a server.
 */

const CAPS = {
  firmware: false,
  scanoss: false,
  docker: true,
  hostDir: "/Users/dev/projects/acme-app",
};

async function stub(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(CAPS) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
}

async function openNewScan(page: Page) {
  await stub(page);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
}

test("current folder prefills the project from hostDir and a default version", async ({ page }) => {
  await openNewScan(page);
  // Default source is the current folder — its leaf name is the suggestion.
  await expect(page.locator("#project")).toHaveValue("acme-app");
  // A folder states no version, so the placeholder default fills in, letting a
  // first run start without stalling on the required field.
  await expect(page.locator("#version")).toHaveValue("1.0.0");
});

test("git URL prefills the repo name as the project and a default version", async ({ page }) => {
  await openNewScan(page);
  await page.getByRole("button", { name: "GitHub URL" }).click();
  // Switching source drops the folder-based suggestion (empty target = no
  // guess) — and with no target identified, no lone version is shown either.
  await expect(page.locator("#project")).toHaveValue("");
  await expect(page.locator("#version")).toHaveValue("");
  await page.fill("#target", "https://github.com/acme/demo.git");
  await expect(page.locator("#project")).toHaveValue("demo");
  // The repo names no version, so the default fills in once the target is set.
  await expect(page.locator("#version")).toHaveValue("1.0.0");
});

test("docker image prefills name and tag as project and version", async ({ page }) => {
  await openNewScan(page);
  await page.getByRole("button", { name: "Docker image" }).click();
  // Registry path and port are not part of the identity; the tag is the version,
  // which beats the default.
  await page.fill("#target", "registry:5000/nginx:1.25");
  await expect(page.locator("#project")).toHaveValue("nginx");
  await expect(page.locator("#version")).toHaveValue("1.25");
});

test("a user-typed project is never overwritten by the autofill", async ({ page }) => {
  await openNewScan(page);
  await page.fill("#project", "mine");
  await page.getByRole("button", { name: "GitHub URL" }).click();
  await page.fill("#target", "https://github.com/acme/demo.git");
  // Project is user-owned now; the untouched version follows the source (the
  // git repo names none, so the default fills in once the target is identified).
  await expect(page.locator("#project")).toHaveValue("mine");
  await expect(page.locator("#version")).toHaveValue("1.0.0");
});
