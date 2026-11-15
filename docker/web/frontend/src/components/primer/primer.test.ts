// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import i18next from "i18next";
import { createElement, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider, initReactI18next } from "react-i18next";
import { describe, expect, it } from "vitest";

import en from "@/locales/en/common.json";
import ko from "@/locales/ko/common.json";
import { LICENSE_TIER_ORDER } from "@/lib/licenses";

import {
  PACKAGE_SEPARATOR,
  packageCoordinateText,
  severityFill,
  severityLabelKey,
  severityLabelVariant,
  severityShape,
  splitPackage,
  TIER_DISPLAY_COLOR,
  TIER_LABEL_KEY,
  tierFg,
  tierFill,
  tierShape,
  severityFg,
} from "./display";
import { LicenseTierLabel } from "./LicenseTierLabel";
import { PackageCoordinate } from "./PackageCoordinate";
import { SeverityLabel } from "./SeverityLabel";

async function render(el: ReactElement, lng: "en" | "ko" = "en"): Promise<string> {
  const i18n = i18next.createInstance();
  await i18n.use(initReactI18next).init({
    resources: { en: { common: en }, ko: { common: ko } },
    lng,
    defaultNS: "common",
    interpolation: { escapeValue: false },
  });
  return renderToStaticMarkup(createElement(I18nextProvider, { i18n }, el));
}

describe("severity mapping", () => {
  it("maps each grade onto a Primer Label variant", () => {
    expect(severityLabelVariant("CRITICAL")).toBe("danger");
    expect(severityLabelVariant("HIGH")).toBe("severe");
    expect(severityLabelVariant("MEDIUM")).toBe("attention");
  });

  it("keeps Low, unknown and anything unmapped neutral, never the accent", () => {
    for (const s of ["LOW", "UNKNOWN", "NONE", "bogus", null, undefined]) {
      expect(severityLabelVariant(s), String(s)).toBe("secondary");
    }
    expect(severityFill("LOW")).not.toContain("accent");
    expect(severityFill("bogus")).toBe(severityFill("UNKNOWN"));
  });

  it("pairs every grade with the shared marker shape", () => {
    expect(severityShape("CRITICAL")).toBe("diamond");
    expect(severityShape("HIGH")).toBe("triangle");
    expect(severityShape("UNKNOWN")).toBe("dash");
  });

  it("falls back to the Unknown word for an unmapped grade", () => {
    expect(severityLabelKey("HIGH")).toBe("severity.HIGH");
    expect(severityLabelKey("bogus")).toBe("severity.UNKNOWN");
  });

  it("gives every grade a Primer foreground variable", () => {
    for (const s of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "bogus"]) {
      expect(severityFg(s)).toMatch(/^var\(--fgColor-[\w-]+\)$/);
    }
    expect(severityFg("CRITICAL")).toBe("var(--fgColor-danger)");
  });

  it("uses only Primer variables for fills", () => {
    for (const s of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]) {
      expect(severityFill(s)).toMatch(/^var\(--[\w-]+\)$/);
    }
  });
});

describe("licence tier mapping", () => {
  it("covers every tier with a display colour, a label and a shape", () => {
    for (const tier of LICENSE_TIER_ORDER) {
      expect(TIER_DISPLAY_COLOR[tier], tier).toBeTruthy();
      expect(TIER_LABEL_KEY[tier], tier).toMatch(/^licenses\.tier\./);
      expect(tierShape(tier), tier).toBeTruthy();
    }
  });

  it("gives each tier its own bar fill; permissive and uncategorized share the neutral grey", () => {
    const fills = LICENSE_TIER_ORDER.map((t) => tierFill(t));
    expect(new Set(fills).size).toBe(fills.length);
    expect(TIER_DISPLAY_COLOR.permissive).toBe("gray");
    expect(TIER_DISPLAY_COLOR.uncategorized).toBe("gray");
  });

  it("names Primer display variables", () => {
    expect(tierFg("strong-copyleft")).toBe("var(--display-purple-fgColor)");
    expect(tierFill("uncategorized")).toBe("var(--display-gray-bgColor-emphasis)");
    // The report decides the colour: --cat-permissive-emphasis.
    expect(tierFill("permissive")).toBe("rgb(var(--cat-permissive-emphasis))");
  });
});

describe("permissive bar colour", () => {
  // The HTML reports draw the Permissive tier with --cat-permissive-emphasis
  // from docker/shared/bomlens-tokens.css; the web bar must use the same value.
  const value = (css: string, theme: "light" | "dark") => {
    const at = css.search(/^\s*\.dark\s*\{/m);
    const block = theme === "light" ? css.slice(0, at) : css.slice(at);
    return /--cat-permissive-emphasis:\s*([\d ]+)/.exec(block)?.[1]?.trim();
  };
  it("is the report's token, in both themes", () => {
    const shared = readFileSync(join(__dirname, "../../../../../shared/bomlens-tokens.css"), "utf8");
    const web = readFileSync(join(__dirname, "../../index.css"), "utf8");
    expect(value(shared, "light")).toBeTruthy();
    expect(value(web, "light")).toBe(value(shared, "light"));
    expect(value(web, "dark")).toBe(value(shared, "dark"));
    expect(tierFill("permissive")).toContain("--cat-permissive-emphasis");
  });
});

describe("package coordinate", () => {
  it("uses one separator, a spaced slash", () => {
    expect(PACKAGE_SEPARATOR).toBe(" / ");
    expect(packageCoordinateText({ group: "org.springframework", name: "spring-core" })).toBe(
      "org.springframework / spring-core",
    );
    expect(packageCoordinateText({ name: "lodash" })).toBe("lodash");
  });

  it("splits a group:name label at the last colon", () => {
    expect(splitPackage("org.yaml:snakeyaml")).toEqual({ group: "org.yaml", name: "snakeyaml" });
    expect(splitPackage("a:b:c")).toEqual({ group: "a:b", name: "c" });
    expect(splitPackage("lodash")).toEqual({ name: "lodash" });
    expect(splitPackage(":x")).toEqual({ name: ":x" });
    expect(splitPackage("x:")).toEqual({ name: "x:" });
  });
});

describe("components", () => {
  it("SeverityLabel renders the variant, the marker and the translated word", async () => {
    const html = await render(createElement(SeverityLabel, { severity: "CRITICAL", count: 1234 }));
    expect(html).toContain('data-variant="danger"');
    expect(html).toContain('data-marker="diamond"');
    expect(html).toContain("Critical");
    expect(html).toContain("1,234");
  });

  it("SeverityLabel is translated in Korean", async () => {
    const html = await render(createElement(SeverityLabel, { severity: "HIGH" }), "ko");
    expect(html).toContain(ko.severity.HIGH);
    expect(html).toContain('data-variant="severe"');
  });

  it("LicenseTierLabel colours the label with the tier's display variables", async () => {
    const html = await render(createElement(LicenseTierLabel, { tier: "network-copyleft" }));
    expect(html).toContain("var(--display-pink-fgColor)");
    expect(html).toContain("var(--display-pink-borderColor-emphasis)");
    expect(html).toContain('data-marker="bars"');
    expect(html).toContain(en.licenses.tier.networkCopyleft);
  });

  it("PackageCoordinate shows group / name with the full text as the tooltip", async () => {
    const html = await render(createElement(PackageCoordinate, { group: "org.yaml", name: "snakeyaml" }));
    expect(html).toContain('title="org.yaml / snakeyaml"');
    expect(html).toContain("org.yaml / </span>");
    expect(html).toContain(">snakeyaml</span>");
  });
});

describe("src/primer.css", () => {
  const css = readFileSync(join(__dirname, "..", "..", "primer.css"), "utf8");

  it("hides Primer's left bar on the active NavList and ActionList item", () => {
    expect(css).toMatch(/\[class\*="ActionList-ActionListItem"\]\[data-active\]::after/);
    expect(css).toMatch(/\[class\*="ActionList-ActionListItem"\]\[data-is-active-descendant\]::after/);
    expect(css).toMatch(/display:\s*none/);
  });

  it("covers every state the installed Primer draws a left bar for", () => {
    // The bar's signature in Primer's CSS: an absolutely placed ::after pulled
    // 8px left of the item. Each such rule must have a hiding rule here naming
    // the same component and the same state attribute.
    const dist = join(__dirname, "..", "..", "..", "node_modules", "@primer", "react", "dist");
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const e of readdirSync(dir)) {
        const p = join(dir, e);
        if (statSync(p).isDirectory()) walk(p);
        else if (e.endsWith(".css")) files.push(p);
      }
    };
    walk(dist);
    const bars: { component: string; state: string }[] = [];
    for (const f of files) {
      for (const m of readFileSync(f, "utf8").matchAll(/([^{}]+):after\{([^}]*)\}/g)) {
        const [selector, body] = [m[1], m[2]];
        if (!/position:absolute/.test(body) || !/left:calc\(var\(--base-size-8[^)]*\)\*-1\)/.test(body)) continue;
        const kept = selector.replace(/:not\([^)]*\)/g, "");
        // The class that carries the state attribute, e.g. prc-TreeView-TreeViewItem-x[aria-current=true].
        const hit = /prc-([A-Za-z]+-[A-Za-z]+)-[\w-]{5}(?::where\()?\[((?:data|aria)-[\w-]+)/.exec(kept);
        if (hit) bars.push({ component: hit[1], state: hit[2] });
      }
    }
    expect(bars.length, "no left-bar rules found: has Primer's CSS changed shape?").toBeGreaterThanOrEqual(3);
    const hiding = css.split("\n").filter((l) => l.includes("::after"));
    for (const { component, state } of bars) {
      const covered = hiding.some((l) => l.includes(`[class*="${component}`) && l.includes(`[${state}`));
      expect(covered, `${component} [${state}] ::after bar is not hidden`).toBe(true);
    }
  });

  it("overrides the accent and the primary button with the stronger selector", () => {
    expect(css).toContain("[data-color-mode][data-light-theme][data-dark-theme] {");
    for (const v of ["--fgColor-accent", "--button-primary-bgColor-rest", "--focus-outlineColor", "--fontStack-sansSerif"]) {
      expect(css, v).toContain(`${v}:`);
    }
  });

  it("takes every colour from an index.css token, never a literal", () => {
    expect(css).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(\s*[\d.]/);
  });
});
