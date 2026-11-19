// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// scanmounts.mjs의 저장 목록 정규화 로직 단위 테스트(fs 비의존).
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addScanMounts,
  MAX_SCAN_MOUNTS,
  parseScanMounts,
  planScanMounts,
  removeScanMount,
} from "../lib/scanmounts.mjs";

test("parseScanMounts accepts a plain string array", () => {
  assert.deepEqual(parseScanMounts('["/data/rootfs", "C:\\\\extract"]'), [
    "/data/rootfs",
    "C:\\extract",
  ]);
});

test("parseScanMounts returns [] for corrupt or non-array JSON", () => {
  assert.deepEqual(parseScanMounts("not json"), []);
  assert.deepEqual(parseScanMounts('{"a":1}'), []);
  assert.deepEqual(parseScanMounts('"just a string"'), []);
});

test("parseScanMounts drops non-strings, blanks, control chars and duplicates", () => {
  const text = JSON.stringify(["/a", 42, "  ", "/a", "/b\nc", "/ok"]);
  assert.deepEqual(parseScanMounts(text), ["/a", "/ok"]);
});

test("parseScanMounts caps the list at MAX_SCAN_MOUNTS", () => {
  const many = Array.from({ length: MAX_SCAN_MOUNTS + 3 }, (_, i) => `/d${i}`);
  assert.equal(parseScanMounts(JSON.stringify(many)).length, MAX_SCAN_MOUNTS);
});

test("addScanMounts merges, dedupes and keeps the cap", () => {
  assert.deepEqual(addScanMounts(["/a"], ["/b", "/a"]), ["/a", "/b"]);
  assert.deepEqual(addScanMounts(null, ["/x"]), ["/x"]);
  const full = Array.from({ length: MAX_SCAN_MOUNTS }, (_, i) => `/d${i}`);
  assert.equal(addScanMounts(full, ["/overflow"]).length, MAX_SCAN_MOUNTS);
});

test("removeScanMount removes exactly the given path", () => {
  assert.deepEqual(removeScanMount(["/a", "/b"], "/a"), ["/b"]);
  assert.deepEqual(removeScanMount(["/a"], "/nope"), ["/a"]);
  assert.deepEqual(removeScanMount(null, "/a"), []);
});

test("planScanMounts reports what the cap kept out instead of dropping it silently", () => {
  const full = Array.from({ length: MAX_SCAN_MOUNTS - 1 }, (_, i) => `/d${i}`);
  const plan = planScanMounts(full, ["/new1", "/new2", "/new3"]);
  assert.equal(plan.next.length, MAX_SCAN_MOUNTS);
  assert.deepEqual(plan.added, ["/new1"]);
  assert.deepEqual(plan.dropped, ["/new2", "/new3"]);
  // The result list is what addScanMounts gives.
  assert.deepEqual(plan.next, addScanMounts(full, ["/new1", "/new2", "/new3"]));
});

test("planScanMounts on a full list adds nothing and drops every new folder", () => {
  const full = Array.from({ length: MAX_SCAN_MOUNTS }, (_, i) => `/d${i}`);
  const plan = planScanMounts(full, ["/x"]);
  assert.deepEqual(plan.added, []);
  assert.deepEqual(plan.dropped, ["/x"]);
  assert.deepEqual(plan.next, full);
});

test("planScanMounts ignores folders already listed, blanks, duplicates and unusable names", () => {
  const plan = planScanMounts(["/a"], ["/a", "  ", "/b", "/b", "/bad\nname", 5]);
  assert.deepEqual(plan.added, ["/b"]);
  assert.deepEqual(plan.dropped, []);
  assert.deepEqual(plan.next, ["/a", "/b"]);
  assert.deepEqual(planScanMounts(null, null), { next: [], added: [], dropped: [] });
});
