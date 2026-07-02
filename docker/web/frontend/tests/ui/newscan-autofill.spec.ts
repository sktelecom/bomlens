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

test("current folder prefills the project from hostDir", async ({ page }) => {
  await openNewScan(page);
  // Default source is the current folder — its leaf name is the suggestion.
  await expect(page.locator("#project")).toHaveValue("acme-app");
  // No version can be derived from a folder — never a made-up default.
  await expect(page.locator("#version")).toHaveValue("");
});

test("git URL prefills the repo name as the project", async ({ page }) => {
  await openNewScan(page);
  await page.getByRole("button", { name: "GitHub URL" }).click();
  // Switching source drops the folder-based suggestion (empty target = no guess).
  await expect(page.locator("#project")).toHaveValue("");
  await page.fill("#target", "https://github.com/acme/demo.git");
  await expect(page.locator("#project")).toHaveValue("demo");
  await expect(page.locator("#version")).toHaveValue("");
});

test("docker image prefills name and tag as project and version", async ({ page }) => {
  await openNewScan(page);
  await page.getByRole("button", { name: "Docker image" }).click();
  // Registry path and port are not part of the identity; the tag is the version.
  await page.fill("#target", "registry:5000/nginx:1.25");
  await expect(page.locator("#project")).toHaveValue("nginx");
  await expect(page.locator("#version")).toHaveValue("1.25");
});

test("a user-typed project is never overwritten by the autofill", async ({ page }) => {
  await openNewScan(page);
  await page.fill("#project", "mine");
  await page.getByRole("button", { name: "GitHub URL" }).click();
  await page.fill("#target", "https://github.com/acme/demo.git");
  // Project is user-owned now; only the untouched version keeps mirroring the
  // source (a git URL suggests none).
  await expect(page.locator("#project")).toHaveValue("mine");
  await expect(page.locator("#version")).toHaveValue("");
});
