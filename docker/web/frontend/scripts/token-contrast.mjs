#!/usr/bin/env node
// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Token contrast check: reads the colour tokens in src/index.css and fails when
 * a pair falls under its WCAG 2.x floor, in both themes. Text shades (-fg and
 * muted-foreground) need 4.5:1 on the surfaces they sit on (WCAG 1.4.3). Fill
 * shades (-emphasis, used for bars, dots and progress fills) and the focus ring
 * need 3:1 against the page, the card and the muted surface (WCAG 1.4.11).
 *
 * The browser-based axe matrix measures rendered pages; this check measures the
 * tokens themselves, so a token edit that no screen happens to render today
 * still fails here. Run with `--table` to print every ratio.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE =
  process.env.TOKEN_CONTRAST_SRC ??
  join(fileURLToPath(new URL(".", import.meta.url)), "..", "src", "index.css");

function block(css, selector) {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`token-contrast: no ${selector} block in ${SOURCE}`);
  let depth = 0;
  let i = css.indexOf("{", start);
  const open = i;
  for (; i < css.length; i++) {
    if (css[i] === "{") depth++;
    if (css[i] === "}" && --depth === 0) break;
  }
  return css.slice(open, i);
}

function hslToRgb(h, s, l) {
  s /= 100;
  l /= 100;
  const a = s * Math.min(l, 1 - l);
  const f = (n) => {
    const k = (n + h / 30) % 12;
    return l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1));
  };
  return [f(0), f(8), f(4)].map((x) => Math.round(x * 255));
}

function parseTokens(text) {
  const tokens = {};
  for (const m of text.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
    const value = m[2].replace(/\/\*.*?\*\//g, "").trim();
    const channels = value.match(/^(\d+)\s+(\d+)\s+(\d+)$/);
    const hsl = value.match(/^(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%$/);
    if (channels) tokens[m[1]] = [+channels[1], +channels[2], +channels[3]];
    else if (hsl) tokens[m[1]] = hslToRgb(+hsl[1], +hsl[2], +hsl[3]);
  }
  return tokens;
}

function luminance([r, g, b]) {
  const lin = (c) => {
    c /= 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const css = readFileSync(SOURCE, "utf8");
const table = process.argv.includes("--table");
const failures = [];

for (const [theme, selector] of [["light", ":root"], ["dark", ".dark"]]) {
  const t = parseTokens(block(css, selector));
  const check = (label, fg, bg, floor) => {
    if (!fg || !bg) return;
    const value = ratio(fg, bg);
    if (table) console.log(`${theme.padEnd(5)} ${label.padEnd(44)} ${value.toFixed(2)}  (floor ${floor})`);
    if (value < floor) failures.push(`${theme}: ${label} is ${value.toFixed(2)}:1, needs ${floor}:1`);
  };

  const roles = Object.keys(t)
    .filter((k) => /^(role|cat)-.+-fg$/.test(k))
    .map((k) => k.replace(/-fg$/, ""));
  for (const role of roles) {
    for (const [name, surface] of [["card", t.card], ["page", t.background], ["muted surface", t[`${role}-muted`]]]) {
      check(`${role}-fg on ${name}`, t[`${role}-fg`], surface, 4.5);
    }
    for (const [name, surface] of [["card", t.card], ["page", t.background], ["muted", t.muted]]) {
      check(`${role}-emphasis on ${name}`, t[`${role}-emphasis`], surface, 3);
    }
  }
  for (const [name, surface] of [["card", t.card], ["page", t.background], ["muted", t.muted]]) {
    check(`muted-foreground on ${name}`, t["muted-foreground"], surface, 4.5);
    check(`foreground on ${name}`, t.foreground, surface, 4.5);
  }
  check("ring on page", t.ring, t.background, 3);
  check("ring on card", t.ring, t.card, 3);
  check("selected-foreground on selected", t["selected-foreground"], t.selected, 4.5);
}

if (failures.length) {
  console.error("Token contrast check failed:\n");
  console.error(failures.join("\n"));
  console.error(`\n${failures.length} pair(s) under the WCAG floor. Adjust the token in src/index.css.`);
  process.exit(1);
}
console.log("token-contrast: OK, every text shade is at least 4.5:1 and every fill shade at least 3:1");
