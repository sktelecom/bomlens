#!/usr/bin/env node
// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * i18n coverage — fails when the en and ko message catalogues drift apart.
 * Every key present in one locale must exist in the other (DoD: en ≡ ko,
 * missing keys 0). Run in CI so a new string can't ship in one language only.
 * Also fails on forbidden variants of the glossary terms (see forbidden-terms.mjs
 * and src/locales/GLOSSARY.md).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { findForbidden } from "./forbidden-terms.mjs";

const LOCALES = join(
  fileURLToPath(new URL(".", import.meta.url)),
  "..",
  "src",
  "locales",
);

/** Flatten a nested message object to dotted leaf keys. */
function flatten(obj, prefix = "") {
  const keys = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      keys.push(...flatten(v, key));
    } else {
      keys.push(key);
    }
  }
  return keys;
}

function load(lng) {
  return new Set(
    flatten(JSON.parse(readFileSync(join(LOCALES, lng, "common.json"), "utf8"))),
  );
}

const en = load("en");
const ko = load("ko");

const missingInKo = [...en].filter((k) => !ko.has(k)).sort();
const missingInEn = [...ko].filter((k) => !en.has(k)).sort();

if (missingInKo.length || missingInEn.length) {
  console.error("i18n coverage failed — locales are out of sync:\n");
  if (missingInKo.length)
    console.error(`Missing in ko (${missingInKo.length}):\n  ${missingInKo.join("\n  ")}\n`);
  if (missingInEn.length)
    console.error(`Missing in en (${missingInEn.length}):\n  ${missingInEn.join("\n  ")}\n`);
  process.exit(1);
}
const forbidden = ["en", "ko"].flatMap((lng) =>
  findForbidden(JSON.parse(readFileSync(join(LOCALES, lng, "common.json"), "utf8")), lng).map(
    (h) => ({ lng, ...h }),
  ),
);
if (forbidden.length) {
  console.error("i18n terminology check failed - forbidden terms (see src/locales/GLOSSARY.md):\n");
  for (const h of forbidden)
    console.error(`  ${h.lng}/common.json  ${h.key}: "${h.found}" -> use "${h.prefer}"`);
  process.exit(1);
}
console.log(`i18n coverage passed — en ≡ ko (${en.size} keys).`);
