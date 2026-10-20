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
const BRAND_RULE = "brand token outside the allow list (primary button, logo, focus ring only)";
const SIZE_RULE = "arbitrary font size (use a role size: text-caption, text-label, text-body-sm ...)";
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

  it("rejects brand in any file that is not on the allow list", () => {
    const line = '<span className="h-2.5 w-2.5 rounded-full bg-brand" />';
    for (const file of [
      "src/components/DependencyGraph.tsx",
      "src/components/ui/badge.tsx",
      "src/components/ui/switch.tsx",
      "src/components/FileDropzone.tsx",
      "src/components/DemoBanner.tsx",
      "src/components/TopBar.tsx",
      "src/components/ui/button.tsx.bak",
    ]) {
      expect(lint(line, file), file).toContain(BRAND_RULE);
    }
    expect(lint('direct: hsl("--brand"),', "src/components/DependencyGraph.tsx")).toContain(BRAND_RULE);
    expect(lint('<a className="text-brand-strong underline">', "src/components/Overview.tsx")).toContain(BRAND_RULE);
    expect(lint('<Check className="text-brand" />', "src\\components\\ui\\switch.tsx")).toContain(BRAND_RULE);
  });

  it("rejects brand on a Badge line in any file", () => {
    const badge = '<Badge className="border-transparent bg-brand/10 text-brand-strong">'; // token-lint-ignore
    expect(lint(badge, "src/components/RecentScans.tsx")).toContain(BRAND_RULE);
  });

  it("allows brand in the primary button variants only", () => {
    const line = '"bg-brand text-brand-foreground shadow-sm hover:bg-brand/90"';
    expect(lint(line, "src/components/ui/button.tsx")).toEqual([]);
    expect(lint(line, "src\\components\\ui\\button.tsx")).toEqual([]);
    expect(lint(line, "src/components/ui/badge.tsx")).toContain(BRAND_RULE);
  });

  it("does not flag the focus ring colour", () => {
    expect(lint('"focus-visible:ring-2 focus-visible:ring-ring"', "src/components/X.tsx")).toEqual([]);
  });

  it("honours the ignore marker", () => {
    expect(lint('bg-brand // token-lint-ignore', "src/components/DependencyGraph.tsx")).toEqual([]);
  });
});

describe("arbitrary font size rule", () => {
  it("rejects a size typed at the call site", () => {
    for (const bad of ["text-[10px]", "text-[0.6875rem]", "md:text-[11px]", "text-[ 12px ]", "text-[1.5em]"]) {
      expect(lint(`className="${bad}"`), bad).toContain(SIZE_RULE);
    }
  });

  it("allows the role scale, colours and other bracket values", () => {
    for (const ok of ["text-caption", "text-body-sm", "text-[color:var(--x)]", "w-[10px]", "text-left"]) {
      expect(lint(`className="${ok}"`), ok).toEqual([]);
    }
  });
});

describe("legacy font size rule", () => {
  const LEGACY = "legacy Tailwind font size (renamed: xs=label, sm=body-sm, base=body, lg=heading, xl=title, 3xl=display)";
  it("rejects a removed Tailwind size name, with or without a variant", () => {
    for (const bad of ["text-xs", "text-sm", "text-base", "text-lg", "text-xl", "text-2xl", "md:text-3xl"]) {
      expect(lint(`className="${bad}"`), bad).toContain(LEGACY);
    }
  });

  it("allows the role names that merely start like one", () => {
    for (const ok of ["text-body-sm", "text-label", "text-display", "text-smoke", "text-xs-not-a-size"]) {
      expect(lint(`className="${ok}"`), ok).not.toContain(LEGACY);
    }
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

  it("fails a component that uses brand and names the rule", () => {
    const r = run({ "components/Switch2.tsx": 'const a = "bg-brand";\n' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("brand token outside the allow list");
  });

  it("fails an arbitrary font size and names the rule", () => {
    const r = run({ "components/X.tsx": 'const a = "text-[10px]";\n' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("arbitrary font size");
  });

  it("passes the same line in a button file", () => {
    const r = run({ "components/ui/button.tsx": 'const a = "bg-brand";\n' });
    expect(r.status).toBe(0);
  });
});
