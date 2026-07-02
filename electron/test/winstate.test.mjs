// winstate.mjs 단위 테스트(electron 비의존). 저장 파일 파싱의 방어와
// 모니터 구성 변화 대응(sanitizeBounds)을 검증한다.
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWindowState, sanitizeBounds } from "../lib/winstate.mjs";

const GOOD = { x: 40, y: 60, width: 1200, height: 860, maximized: false };
// 1920×1080 단일 모니터의 workArea(작업표시줄 40px 가정).
const WORK = [{ x: 0, y: 0, width: 1920, height: 1040 }];
const DEFAULTS = { width: 1200, height: 860 };

test("parseWindowState accepts a valid state", () => {
  assert.deepEqual(parseWindowState(JSON.stringify(GOOD)), GOOD);
});

test("parseWindowState returns null for corrupt JSON", () => {
  assert.equal(parseWindowState("{not json"), null);
  assert.equal(parseWindowState(""), null);
  assert.equal(parseWindowState(undefined), null);
});

test("parseWindowState returns null for schema violations", () => {
  // JSON으로는 유효하지만 객체 스키마가 아닌 값들.
  assert.equal(parseWindowState("null"), null);
  assert.equal(parseWindowState("[1,2]"), null);
  assert.equal(parseWindowState('"x"'), null);
  // 필드 누락과 타입 오염.
  assert.equal(parseWindowState(JSON.stringify({ ...GOOD, width: undefined })), null);
  assert.equal(parseWindowState(JSON.stringify({ ...GOOD, width: "1200" })), null);
  assert.equal(parseWindowState(JSON.stringify({ ...GOOD, y: null })), null);
  assert.equal(parseWindowState(JSON.stringify({ ...GOOD, maximized: "true" })), null);
});

test("parseWindowState keeps only the known fields", () => {
  const dirty = { ...GOOD, extra: "junk" };
  assert.deepEqual(parseWindowState(JSON.stringify(dirty)), GOOD);
});

test("maximized state survives a save/load round trip", () => {
  const state = { ...GOOD, maximized: true };
  const loaded = parseWindowState(JSON.stringify(state));
  assert.equal(loaded.maximized, true);
  assert.deepEqual(sanitizeBounds(loaded, WORK, DEFAULTS), {
    x: GOOD.x,
    y: GOOD.y,
    width: GOOD.width,
    height: GOOD.height,
  });
});

test("sanitizeBounds keeps a fully visible window", () => {
  assert.deepEqual(sanitizeBounds(GOOD, WORK, DEFAULTS), {
    x: 40,
    y: 60,
    width: 1200,
    height: 860,
  });
});

test("sanitizeBounds falls back to defaults when the monitor is gone", () => {
  // 외장 모니터(음수 좌표)에 있던 창인데 이제 주 모니터만 남은 경우.
  const onRemoved = { x: -1900, y: 100, width: 1200, height: 860, maximized: false };
  assert.equal(sanitizeBounds(onRemoved, WORK, DEFAULTS), DEFAULTS);
});

test("sanitizeBounds falls back to defaults for null state or bad work areas", () => {
  assert.equal(sanitizeBounds(null, WORK, DEFAULTS), DEFAULTS);
  assert.equal(sanitizeBounds(GOOD, [], DEFAULTS), DEFAULTS);
  assert.equal(sanitizeBounds(GOOD, undefined, DEFAULTS), DEFAULTS);
});

test("sanitizeBounds boundary: exactly 100x80 overlap is enough, one pixel less is not", () => {
  // 창 오른쪽 아래 귀퉁이만 workArea 왼쪽 위에 걸친 경우: 교집합이 정확히 100×80.
  const barely = { x: -1100, y: -780, width: 1200, height: 860, maximized: false };
  assert.deepEqual(sanitizeBounds(barely, WORK, DEFAULTS), {
    x: -1100,
    y: -780,
    width: 1200,
    height: 860,
  });
  // 가로 교집합 99px: 부족.
  assert.equal(
    sanitizeBounds({ ...barely, x: -1101 }, WORK, DEFAULTS),
    DEFAULTS,
  );
  // 세로 교집합 79px: 부족.
  assert.equal(
    sanitizeBounds({ ...barely, y: -781 }, WORK, DEFAULTS),
    DEFAULTS,
  );
});

test("sanitizeBounds checks every monitor, not just the first", () => {
  // 주 모니터 오른쪽에 두 번째 모니터가 있는 구성. 창은 두 번째 모니터 위에 있다.
  const dual = [
    { x: 0, y: 0, width: 1920, height: 1040 },
    { x: 1920, y: 0, width: 2560, height: 1400 },
  ];
  const onSecond = { x: 2200, y: 200, width: 1200, height: 860, maximized: false };
  assert.deepEqual(sanitizeBounds(onSecond, dual, DEFAULTS), {
    x: 2200,
    y: 200,
    width: 1200,
    height: 860,
  });
});
