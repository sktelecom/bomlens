// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";
import { seedThemeLang } from "./visual";

// A source scan whose code calls an AI service and whose editor setup runs an
// MCP server: the Overview lists both in the "AI used by the code" card.
const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "agentapp_1.0",
  results: [{ name: "agentapp_1.0_bom.json", size: 1234 }],
  security: null,
  conformance: null,
  sbom: {
    components: 1,
    componentList: [
      { name: "openai", version: "1.40.0", group: "", purl: "pkg:pypi/openai@1.40.0", type: "library", licenses: ["Apache-2.0"], scope: "direct" },
    ],
    aiUsage: [
      { kind: "model", name: "gpt-4o", purl: "pkg:generic/openai/gpt-4o", provider: "OpenAI", scope: "runtime", path: "app/chat.py#L12", reviewReasons: [], detectedBy: "bomlens" },
      { kind: "ai-service", name: "OpenAI API", provider: "OpenAI", scope: "runtime", path: "app/chat.py#L10", reviewReasons: [], models: ["gpt-4o"], detectedBy: "bomlens" },
      { kind: "mcp-server", name: "filesystem", scope: "development", path: ".vscode/mcp.json", reviewReasons: ["broad-filesystem-access", "unpinned-package"], detectedBy: "bomlens" },
      { kind: "mcp-config", name: ".vscode/mcp.json", scope: "development", path: ".vscode/mcp.json", reviewReasons: [], detectedBy: "bomlens" },
      { kind: "instruction-file", name: "AGENTS.md", scope: "development", path: "AGENTS.md", reviewReasons: [], detectedBy: "bomlens" },
    ],
  },
};

async function openResult(page: Page, done: unknown) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(done)}\n\n` }),
  );
  await page.goto("/#/new");
  await page.fill("#project", "agentapp");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("the Overview lists the AI the code uses, grouped by kind, with review reasons", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await openResult(page, DONE);
  const card = page.getByTestId("ai-usage");
  await expect(card).toBeVisible();
  await expect(card.getByText("5 items, 1 to review")).toBeVisible();
  await expect(card.getByTestId("ai-usage-group-mcp-server")).toContainText("MCP servers");
  await expect(card.getByText("Called with: gpt-4o")).toBeVisible();
  const label = card.locator("td").getByText("Broad file access", { exact: true });
  await expect(label).toHaveAttribute("title", /filesystem root or the home folder/);
  await expect(card.getByTestId("ai-usage-reasons")).toContainText("no version, so a new release runs without review");
  // Usage items are not components: the rail does not offer Models & datasets.
  await expect(page.getByRole("link", { name: /^Models/ })).toHaveCount(0);

  await waitForSettled(page.locator("main"));
  const axe = await new AxeBuilder({ page })
    .include('[data-testid="ai-usage"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});

test("no card when the scan recorded no AI usage", async ({ page }) => {
  const { aiUsage: _omit, ...sbom } = DONE.sbom;
  await openResult(page, { ...DONE, sbom });
  await expect(page.getByRole("link", { name: /^Components/ }).first()).toBeVisible();
  await expect(page.getByTestId("ai-usage")).toHaveCount(0);
});

test("a model looked up on Hugging Face shows its licence, weights, verdict and the model SBOM command", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  const aiUsage = [
    {
      kind: "model", name: "acme/chat-7b", purl: "pkg:huggingface/acme/chat-7b", provider: "Hugging Face", scope: "runtime",
      path: "app/load.py#L3", reviewReasons: [], detectedBy: "bomlens",
      resolved: "huggingface", license: "apache-2.0", gated: "manual", weightFormats: ["safetensors", "bin"], pickleFiles: 1,
      lineage: "meta-llama/Llama-3.1-8B:llama3.1 > acme/chat-7b:apache-2.0", verdict: "caution", hubUrl: "https://huggingface.co/acme/chat-7b",
    },
    {
      kind: "model", name: "acme/private-1b", purl: "pkg:huggingface/acme/private-1b", provider: "Hugging Face", scope: "runtime",
      path: "app/load.py#L9", reviewReasons: [], detectedBy: "bomlens", resolved: "unreadable", resolvedStatus: 404,
    },
  ];
  await openResult(page, { ...DONE, sbom: { ...DONE.sbom, aiUsage } });
  const card = page.getByTestId("ai-usage");
  await expect(card).toBeVisible();
  await expect(card.getByText("Licence: apache-2.0")).toBeVisible();
  await expect(card.getByText("Gated (manual approval)")).toBeVisible();
  await expect(card.getByText("Weights: safetensors, bin")).toBeVisible();
  await expect(card.getByText("Pickle weights: 1")).toBeVisible();
  await expect(card.getByText(/can run code when they are loaded/)).toBeVisible();
  await expect(card.getByText(/Base models: meta-llama\/Llama-3.1-8B/)).toBeVisible();
  await expect(card.getByText("./scripts/scan-sbom.sh --model acme/chat-7b")).toBeVisible();
  const link = card.getByRole("link", { name: "View on Hugging Face" });
  await expect(link).toHaveAttribute("href", "https://huggingface.co/acme/chat-7b");
  await expect(link).toHaveAttribute("rel", "noopener noreferrer");
  await expect(card.getByText("Hub could not be read (HTTP 404): private, gated or renamed")).toBeVisible();

  await waitForSettled(page.locator("main"));
  const axe = await new AxeBuilder({ page })
    .include('[data-testid="ai-usage"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});
