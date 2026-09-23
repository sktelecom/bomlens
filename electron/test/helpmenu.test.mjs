// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// helpmenu.mjs 단위 테스트(electron 비의존). 실제 메뉴 표시는 데스크톱 앱에서 확인한다.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { buildMenuTemplate, ISSUE_FORM_URL } from "../lib/helpmenu.mjs";
import { mainMessages } from "../lib/i18n.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const opts = { reportLabel: "Report a problem", helpLabel: "Help", onReport: () => {} };

test("the menu keeps the standard menus and adds the report item under Help", () => {
  const tpl = buildMenuTemplate({ ...opts, platform: "win32" });
  assert.deepEqual(tpl.map((m) => m.role), ["fileMenu", "editMenu", "viewMenu", "windowMenu", "help"]);
  const help = tpl.at(-1);
  assert.equal(help.label, "Help");
  assert.equal(help.submenu.length, 1);
  assert.equal(help.submenu[0].label, "Report a problem");
  assert.equal(help.submenu[0].click, opts.onReport);
});

test("macOS gets the application menu first", () => {
  const tpl = buildMenuTemplate({ ...opts, platform: "darwin" });
  assert.equal(tpl[0].role, "appMenu");
  assert.equal(tpl.at(-1).role, "help");
});

test("the menu wording matches the web UI and has no ellipsis", () => {
  const en = mainMessages("en");
  const ko = mainMessages("ko");
  assert.equal(en.reportProblem, "Report a problem");
  assert.equal(ko.reportProblem, "문제 신고");
  const web = JSON.parse(fs.readFileSync(path.join(root, "docker/web/frontend/src/locales/en/common.json"), "utf8"));
  const webKo = JSON.parse(fs.readFileSync(path.join(root, "docker/web/frontend/src/locales/ko/common.json"), "utf8"));
  assert.equal(en.reportProblem, web.nav.helpReport);
  assert.equal(ko.reportProblem, webKo.nav.helpReport);
});

// The issue form file is the source of truth. Every copy of its URL (this
// module, the web UI, the start screen) must name a form that exists and agree.
test("every copy of the issue form URL names an existing form and they agree", () => {
  const template = ISSUE_FORM_URL.split("template=")[1];
  assert.ok(fs.existsSync(path.join(root, ".github/ISSUE_TEMPLATE", template)), template);
  const web = fs.readFileSync(path.join(root, "docker/web/frontend/src/lib/diagnostics.ts"), "utf8");
  assert.ok(web.includes(ISSUE_FORM_URL), "the web UI's ISSUE_FORM_URL differs");
  const status = fs.readFileSync(path.join(here, "../assets/status.html"), "utf8");
  assert.ok(status.includes(ISSUE_FORM_URL), "the start screen's link differs");
  const missing = fs.readFileSync(path.join(here, "../assets/docker-missing.html"), "utf8");
  assert.ok(missing.includes(ISSUE_FORM_URL), "the Docker guidance screen's link differs");
});
