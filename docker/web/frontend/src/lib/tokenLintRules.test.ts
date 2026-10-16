// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

// @ts-expect-error -- plain .mjs module shared with the CLI, no declarations
import { BRAND_TOKEN, lintLine } from "../../scripts/token-lint-rules.mjs";

const lint = lintLine as (line: string, file?: string) => string[];
const BRAND_RULE = "brand token in the graph or a badge (use a role, a category or a neutral)";
const SHADE_RULE = "role or category shade other than -fg used as text colour";

describe("brand token rule", () => {
  it("recognises brand utilities and the CSS variable", () => {
    for (const s of [
      "bg-brand",
      "bg-brand/10",
      "text-brand-strong",
      "hover:border-brand/40",
      "dark:bg-brand-accent",
      'hsl("--brand")',
      "ring-brand",
    ]) {
      expect(BRAND_TOKEN.test(s), s).toBe(true);
    }
  });

  it("does not match words that merely contain brand", () => {
    for (const s of ["rebrand", "brand-new thing", "const brandName = 1", "text-brandish"]) {
      expect(BRAND_TOKEN.test(s), s).toBe(false);
    }
  });

  it("rejects brand in the dependency graph, the badge, the bars and the marker files", () => {
    const line = '<span className="h-2.5 w-2.5 rounded-full bg-brand" />';
    for (const file of [
      "src/components/DependencyGraph.tsx",
      "src/components/DependencyTree.tsx",
      "src/components/ui/badge.tsx",
      "src/components/ui/marker.tsx",
      "src/components/LicenseRiskBar.tsx",
      "src/components/SeverityBar.tsx",
      "src/components/ui/barlist.tsx",
    ]) {
      expect(lint(line, file), file).toContain(BRAND_RULE);
    }
    expect(lint('direct: hsl("--brand"),', "src/components/DependencyGraph.tsx")).toContain(BRAND_RULE);
  });

  it("rejects brand on any line that draws a Badge, in any file", () => {
    const badge = '<Badge className="border-transparent bg-brand/10 text-brand-strong">'; // token-lint-ignore
    expect(lint(badge, "src/components/RecentScans.tsx")).toContain(BRAND_RULE);
    const variants = 'badgeVariants({ tone }) + " bg-brand"'; // token-lint-ignore
    expect(lint(variants, "src/components/X.tsx")).toContain(BRAND_RULE);
  });

  it("still allows brand on a primary action and elsewhere", () => {
    expect(lint('"bg-brand text-brand-foreground shadow-sm hover:bg-brand/90"', "src/components/ui/button.tsx")).toEqual([]);
    expect(lint('<ScanLine className="text-brand" />', "src/components/TopBar.tsx")).toEqual([]);
  });

  it("honours the ignore marker", () => {
    expect(lint('bg-brand // token-lint-ignore', "src/components/DependencyGraph.tsx")).toEqual([]);
  });
});

describe("role shade rule", () => {
  it("allows only -fg as a text colour", () => {
    expect(lint('className="text-role-danger-fg"')).toEqual([]);
    expect(lint('className="text-cat-weak-fg"')).toEqual([]);
    for (const bad of [
      "text-role-info-emphasis", // token-lint-ignore
      "text-role-success-muted", // token-lint-ignore
      "text-role-neutral-border", // token-lint-ignore
      "text-cat-strong-emphasis", // token-lint-ignore
    ]) {
      expect(lint(`className="${bad}"`), bad).toContain(SHADE_RULE);
    }
  });

  it("lets surfaces, fills and borders use the other shades", () => {
    expect(lint('className="bg-role-danger-muted border-role-danger-border bg-role-severe-emphasis"')).toEqual([]);
  });

  it("exempts an aria-hidden icon", () => {
    expect(lint('<Dot className="text-role-info-emphasis" aria-hidden />')).toEqual([]);
  });
});

describe("the CLI", () => {
  const run = (files: Record<string, string>) => {
    const dir = mkdtempSync(join(tmpdir(), "token-lint-"));
    try {
      for (const [name, body] of Object.entries(files)) {
        const full = join(dir, name);
        mkdirSync(join(full, ".."), { recursive: true });
        writeFileSync(full, body);
      }
      return spawnSync("node", ["scripts/token-lint.mjs"], {
        env: { ...process.env, TOKEN_LINT_SRC: dir },
        encoding: "utf8",
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  it("fails a graph file that uses brand and names the rule", () => {
    const r = run({ "components/DependencyGraph.tsx": 'const a = "bg-brand";\n' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("brand token in the graph or a badge");
  });

  it("passes the same line in a button file", () => {
    const r = run({ "components/ui/button.tsx": 'const a = "bg-brand";\n' });
    expect(r.status).toBe(0);
  });
});
