// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the pure helpers of the start screen (assets/steps.cjs) and for the pull
// payload main.mjs sends it. The DOM rendering is covered by the Playwright smoke spec.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";
import { BOOT } from "../lib/boot.mjs";
import { pullPayload } from "../lib/pullprogress.mjs";

const require = createRequire(import.meta.url);
const Steps = require("../assets/steps.cjs");

test("the step table covers every boot state", () => {
  for (const state of Object.values(BOOT)) {
    const states = Steps.stepStates(state);
    assert.deepEqual(Object.keys(states), Steps.STEP_IDS, state);
  }
});

test("steps advance with the boot", () => {
  assert.deepEqual(Steps.stepStates("checking"), { docker: "current", image: "pending", ui: "pending" });
  assert.deepEqual(Steps.stepStates("pulling"), { docker: "done", image: "current", ui: "pending" });
  assert.deepEqual(Steps.stepStates("starting"), { docker: "done", image: "done", ui: "current" });
  assert.deepEqual(Steps.stepStates("ready"), { docker: "done", image: "done", ui: "done" });
});

test("a failure marks exactly one step and keeps earlier steps done", () => {
  assert.deepEqual(Steps.stepStates("failed-pull"), { docker: "done", image: "failed", ui: "pending" });
  assert.equal(Steps.failedStep("failed-docker"), "docker");
  assert.equal(Steps.failedStep("failed-pull"), "image");
  assert.equal(Steps.failedStep("failed-start"), "ui");
  assert.equal(Steps.failedStep("failed-died"), "ui");
  assert.equal(Steps.failedStep("pulling"), null);
});

test("an unknown state falls back to the first step instead of throwing", () => {
  assert.deepEqual(Steps.stepStates("nonsense"), Steps.stepStates("idle"));
  assert.deepEqual(Steps.stepStates(undefined), Steps.stepStates("idle"));
});

test("failureKey picks the text by state and reason", () => {
  assert.deepEqual(Steps.failureKey("failed-pull", "proxy"), { step: "image", key: "proxy" });
  assert.deepEqual(Steps.failureKey("failed-pull", null), { step: "image", key: "unknown" });
  assert.deepEqual(Steps.failureKey("failed-start", "not-ready"), { step: "ui", key: "not-ready" });
  // A raw message that is not a known ContainerError code gets the generic start text.
  assert.deepEqual(Steps.failureKey("failed-start", "spawn ENOENT"), { step: "ui", key: "start" });
  assert.deepEqual(Steps.failureKey("failed-died", null), { step: "ui", key: "died" });
  assert.deepEqual(Steps.failureKey("failed-docker", "not-running"), { step: "docker", key: "docker" });
  assert.equal(Steps.failureKey("pulling", null), null);
});

test("formatElapsed renders m:ss and h:mm:ss", () => {
  assert.equal(Steps.formatElapsed(0), "0:00");
  assert.equal(Steps.formatElapsed(9), "0:09");
  assert.equal(Steps.formatElapsed(94), "1:34");
  assert.equal(Steps.formatElapsed(3600), "1:00:00");
  assert.equal(Steps.formatElapsed(3725), "1:02:05");
  assert.equal(Steps.formatElapsed(-5), "0:00");
  assert.equal(Steps.formatElapsed("x"), "0:00");
});

test("pullView reports a layer ratio, and no ratio before any layer is known", () => {
  assert.deepEqual(Steps.pullView({ complete: 3, total: 7, secs: 94 }), {
    complete: 3,
    total: 7,
    fraction: 3 / 7,
    secs: 94,
    update: false,
  });
  assert.equal(Steps.pullView({ complete: 0, total: 0, secs: 4 }).fraction, null);
  assert.equal(Steps.pullView(null).fraction, null);
  // complete can never exceed total, whatever the payload says.
  assert.equal(Steps.pullView({ complete: 9, total: 7 }).complete, 7);
  assert.equal(Steps.pullView({ complete: 1, total: 2, update: true }).update, true);
});

test("pullPayload carries the tally, whole elapsed seconds and the update flag", () => {
  assert.deepEqual(pullPayload({ complete: 3, total: 7 }, 1_000, 95_400), {
    complete: 3,
    total: 7,
    secs: 94,
    update: false,
  });
  assert.equal(pullPayload({ complete: 0, total: 0 }, 5_000, 4_000).secs, 0);
  assert.equal(pullPayload({ complete: 1, total: 2 }, 0, 1_000, true).update, true);
});
