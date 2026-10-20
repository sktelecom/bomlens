#!/usr/bin/env node
// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Generates docker/shared/bomlens-tokens.css from src/index.css, or with
 * `--check` fails when the committed file differs from what index.css would
 * produce (the CI sync gate). The output lives under docker/ so the Docker
 * build context (docker/) can COPY it for the report pipeline.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderTokensCss } from "./tokens-css.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE = join(HERE, "..", "src", "index.css");
const TARGET = join(HERE, "..", "..", "..", "shared", "bomlens-tokens.css");
const REL = "docker/shared/bomlens-tokens.css";

const expected = renderTokensCss(readFileSync(SOURCE, "utf8"));

if (process.argv.includes("--check")) {
  const actual = existsSync(TARGET) ? readFileSync(TARGET, "utf8") : null;
  if (actual !== expected) {
    console.error(
      `tokens:check: ${REL} is ${actual === null ? "missing" : "out of sync with src/index.css"}.\n` +
        "  Run `npm run tokens:build` in docker/web/frontend and commit the result.",
    );
    process.exit(1);
  }
  console.log(`tokens:check: OK, ${REL} matches src/index.css`);
} else {
  mkdirSync(dirname(TARGET), { recursive: true });
  writeFileSync(TARGET, expected);
  console.log(`tokens:build: wrote ${REL}`);
}
