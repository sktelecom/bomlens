// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// Pure helpers for the start screen (status.html). No DOM and no Electron, so the same file
// runs as a classic <script> in the window (it publishes BomLensSteps on globalThis) and under
// `node --test` (module.exports). It is a .cjs file because the package is ESM ("type":
// "module") while the window needs a classic script it can load without a module loader.
(function (root) {
  "use strict";

  var STEP_IDS = ["docker", "image", "ui"];

  // Boot state (lib/boot.mjs BOOT values) -> state of each of the three steps.
  // Unknown or missing states fall back to "idle" so a bad value can never blank the screen.
  var TABLE = {
    idle: ["current", "pending", "pending"],
    checking: ["current", "pending", "pending"],
    pulling: ["done", "current", "pending"],
    starting: ["done", "done", "current"],
    ready: ["done", "done", "done"],
    "failed-docker": ["failed", "pending", "pending"],
    "failed-pull": ["done", "failed", "pending"],
    "failed-start": ["done", "done", "failed"],
    "failed-died": ["done", "done", "failed"],
  };

  function stepStates(state) {
    var row = TABLE[state] || TABLE.idle;
    var out = {};
    for (var i = 0; i < STEP_IDS.length; i++) out[STEP_IDS[i]] = row[i];
    return out;
  }

  // The step that failed, or null when the boot has not failed.
  function failedStep(state) {
    var states = stepStates(state);
    for (var i = 0; i < STEP_IDS.length; i++) {
      if (states[STEP_IDS[i]] === "failed") return STEP_IDS[i];
    }
    return null;
  }

  // Which failure text to show. Pull failures carry a classified reason (proxy, dns, ...);
  // start failures carry a ContainerError code or a raw message; the others have one text.
  var START_REASONS = { "run-failed": 1, "exited-early": 1, "not-ready": 1 };
  function failureKey(state, reason) {
    if (state === "failed-pull") return { step: "image", key: reason || "unknown" };
    if (state === "failed-docker") return { step: "docker", key: "docker" };
    if (state === "failed-died") return { step: "ui", key: "died" };
    if (state === "failed-start") {
      return { step: "ui", key: START_REASONS[reason] ? reason : "start" };
    }
    return null;
  }

  // Seconds -> "m:ss" (or "h:mm:ss" past an hour). Bad input renders as "0:00".
  function formatElapsed(secs) {
    var n = Math.floor(Number(secs));
    if (!isFinite(n) || n < 0) n = 0;
    var h = Math.floor(n / 3600);
    var m = Math.floor((n % 3600) / 60);
    var s = n % 60;
    var ss = (s < 10 ? "0" : "") + s;
    if (h > 0) return h + ":" + (m < 10 ? "0" : "") + m + ":" + ss;
    return m + ":" + ss;
  }

  // Progress payload from main -> what the bar should show. `total` grows while docker is still
  // announcing layers, so the ratio is a layer count, never a byte percentage (a non-TTY
  // `docker pull` prints no byte counts). Returns null fraction while no layer is known yet.
  function pullView(payload) {
    var p = payload || {};
    var total = Math.max(0, Math.floor(Number(p.total)) || 0);
    var complete = Math.min(total, Math.max(0, Math.floor(Number(p.complete)) || 0));
    return {
      complete: complete,
      total: total,
      fraction: total > 0 ? complete / total : null,
      secs: Math.max(0, Math.floor(Number(p.secs)) || 0),
      update: p.update === true,
    };
  }

  var api = {
    STEP_IDS: STEP_IDS,
    stepStates: stepStates,
    failedStep: failedStep,
    failureKey: failureKey,
    formatElapsed: formatElapsed,
    pullView: pullView,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.BomLensSteps = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
