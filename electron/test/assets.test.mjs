// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// Static checks on the start-screen assets: every file a screen loads exists in the layout a
// development run uses, the package config ships the shared tokens, and the screens carry no
// hard-coded colours outside the one fallback block. This guards the "works in development,
// missing from the package" class of bug at unit-test speed.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const assets = path.join(appRoot, "assets");
const screens = ["status.html", "docker-missing.html"];

function read(file) {
  return fs.readFileSync(file, "utf8");
}

test("every local file a screen references exists in a development layout", () => {
  for (const screen of screens) {
    const html = read(path.join(assets, screen));
    const refs = [...html.matchAll(/(?:href|src)="([^"#]+)"/g)]
      .map((m) => m[1])
      .filter((ref) => !/^(https?:|\/\/)/.test(ref) && !ref.startsWith("docker-missing.html"));
    assert.ok(refs.length > 0, `${screen} references nothing`);
    for (const ref of refs) {
      // The packaged copy of the tokens sits next to the screen only after packaging; a
      // development run uses the second link, which points into docker/shared.
      if (ref === "bomlens-tokens.css") continue;
      assert.ok(fs.existsSync(path.resolve(assets, ref)), `${screen} -> ${ref} does not exist`);
    }
  }
});

test("both screens link the token CSS from the packaged and the development location", () => {
  for (const screen of screens) {
    const html = read(path.join(assets, screen));
    assert.match(html, /href="bomlens-tokens\.css"/, screen);
    assert.match(html, /href="\.\.\/\.\.\/docker\/shared\/bomlens-tokens\.css"/, screen);
  }
});

test("electron-builder copies the shared tokens next to the screens", () => {
  const config = read(path.join(appRoot, "electron-builder.yml"));
  assert.match(config, /from:\s*\.\.\/docker\/shared\s*\n\s*to:\s*assets\s*\n\s*filter:\s*\n\s*-\s*bomlens-tokens\.css/);
  // assets/** must stay in the file list: it ships the screens and steps.cjs.
  assert.match(config, /-\s*assets\/\*\*\/\*/);
});

test("the shared tokens file defines what the screens read", () => {
  const css = read(path.resolve(appRoot, "..", "docker", "shared", "bomlens-tokens.css"));
  const html = screens.map((screen) => read(path.join(assets, screen))).join("\n");
  const used = new Set([...html.matchAll(/var\((--[a-z0-9-]+)\)/g)].map((m) => m[1]));
  for (const name of used) {
    if (name.startsWith("--s-")) continue; // the screens' own aliases
    assert.ok(css.includes(`${name}:`), `token ${name} is used but not defined`);
  }
});

test("hex colours appear only in the fallback palette, never in rules", () => {
  for (const screen of screens) {
    const html = read(path.join(assets, screen));
    const style = html.slice(html.indexOf("<style>"), html.indexOf("</style>"));
    // Drop the two fallback blocks (:root and :root.dark custom property lists).
    const rules = style.replace(/:root(?:\.dark)?\s*\{[^}]*\}/g, "");
    assert.doesNotMatch(rules, /#[0-9a-fA-F]{3,8}\b/, `${screen} has a hex colour outside the fallback`);
  }
});
