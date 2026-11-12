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
const LEFT_BAR_RULE = "thick left accent border (border-l-2 and up, or a left border of 2px or more)";
const SHADOW_RULE = "arbitrary shadow (use shadow-sm/md/lg or a Primer shadow variable)";
const RADIUS_RULE = "arbitrary corner radius (use rounded-sm/md/lg/full or a Primer radius variable)";

describe("brand token rule", () => {
  it("recognises brand utilities and the CSS variable", () => {
    for (const s of [
      "bg-brand",
      "bg-brand/10",
      "text-brand-strong",
      "hover:border-brand/40",
      "hover:bg-brand-hover",
      "dark:text-brand-strong/80",
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

describe("left accent border rule", () => {
  it("rejects a thick left or inline-start border, as a class or an inline style", () => {
    for (const bad of [
      'className="border-l-2 border-role-danger-border pl-3"',
      'className="border-l-4"',
      'className="md:border-s-2"',
      'className="hover:border-l-8"',
      'className="border-l-[3px]"',
      'style={{ borderLeft: "3px solid var(--borderColor-accent-emphasis)" }}',
      "style={{ borderLeftWidth: 2 }}",
      'style={{ borderInlineStart: "4px solid" }}',
      'style={{ borderLeft: "0.25rem solid var(--x)" }}',
      'className="border-l-[0.25rem]"',
      'const css = "border-left: 4px solid var(--x)";',
    ]) {
      expect(lint(bad), bad).toContain(LEFT_BAR_RULE);
    }
  });

  it("allows a 1px divider, no border, and left-border colours", () => {
    for (const ok of [
      'className="border-l border-border"',
      'className="border-l-0"',
      'className="border-l-[1px]"',
      'className="border-l-[0px]"',
      'style={{ borderLeft: "0.0625rem solid var(--x)" }}',
      "style={{ borderLeft: 0 }}",
      'className="border-l-border"',
      'style={{ borderLeft: "1px solid var(--borderColor-default)" }}',
      'className="border-r-2 border-t-2"',
    ]) {
      expect(lint(ok), ok).not.toContain(LEFT_BAR_RULE);
    }
  });
});

describe("arbitrary shadow rule", () => {
  it("rejects a shadow typed at the call site", () => {
    for (const bad of [
      'className="shadow-[0_1px_2px_var(--x)]"',
      'className="hover:shadow-[inset_0_0_0_1px_var(--x)]"',
      'style={{ boxShadow: "0 1px 2px var(--x)" }}',
      'style={{ boxShadow: "inset 0 0 0 1px var(--x)" }}',
      'const css = "box-shadow: 0 0 0 2px var(--x)";',
      'const css = "box-shadow: inset 0 1px 0 var(--x)";',
    ]) {
      expect(lint(bad), bad).toContain(SHADOW_RULE);
    }
  });

  it("allows the token scale, none, a variable and a computed value", () => {
    for (const ok of [
      'className="shadow-sm hover:shadow-md"',
      'style={{ boxShadow: "none" }}',
      'style={{ boxShadow: "var(--shadow-resting-small)" }}',
      "style={{ boxShadow: shadow }}",
      "style={{ boxShadow: `${ring}` }}",
      "  boxShadow: theShadow",
      'className="shadow-[var(--shadow-resting-small)]"',
    ]) {
      expect(lint(ok), ok).not.toContain(SHADOW_RULE);
    }
  });
});

describe("arbitrary corner radius rule", () => {
  it("rejects a radius typed at the call site", () => {
    for (const bad of [
      'className="rounded-[10px]"',
      'className="rounded-tl-[4px]"',
      'className="md:rounded-[1.5rem]"',
      "style={{ borderRadius: 8 }}",
      'style={{ borderRadius: "6px" }}',
      'style={{ borderTopLeftRadius: "4px" }}',
      'const css = "border-radius: 6px";',
      "style={{ borderRadius: 0.5 }}",
      'style={{ borderRadius: "0.375rem" }}',
      'style={{ borderRadius: "0px 4px" }}',
    ]) {
      expect(lint(bad), bad).toContain(RADIUS_RULE);
    }
  });

  it("allows the token scale, zero and a variable", () => {
    for (const ok of [
      'className="rounded-md rounded-full rounded-t-lg"',
      "style={{ borderRadius: 0 }}",
      'style={{ borderRadius: "var(--borderRadius-medium)" }}',
      "style={{ borderRadius: radius }}",
      'style={{ borderRadius: "0px" }}',
      "  borderRadius: 0",
      'className="rounded-[var(--borderRadius-medium)]"',
    ]) {
      expect(lint(ok), ok).not.toContain(RADIUS_RULE);
    }
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

  it("fails a thick left border and names the rule", () => {
    const r = run({ "components/Card2.tsx": 'const a = "border-l-4 pl-3";\n' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("thick left accent border");
  });

  it("passes the same line in a button file", () => {
    const r = run({ "components/ui/button.tsx": 'const a = "bg-brand";\n' });
    expect(r.status).toBe(0);
  });
});
