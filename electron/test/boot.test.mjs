// boot.mjs의 상태표 단위 테스트(electron 비의존). 실제 전이는 main.mjs가 수행하므로
// 여기서는 상태 집합과 canRetry/isBusy 판정이 표와 정확히 일치하는지만 검증한다.
import assert from "node:assert/strict";
import { test } from "node:test";
import { BOOT, canRetry, isBusy } from "../lib/boot.mjs";

// 상태별 기대값 표: retry(다시 시도 가능)와 busy(부팅 진행 중).
const TABLE = {
  idle: { retry: false, busy: false },
  checking: { retry: false, busy: true },
  pulling: { retry: false, busy: true },
  starting: { retry: false, busy: true },
  ready: { retry: false, busy: false },
  "failed-docker": { retry: true, busy: false },
  "failed-pull": { retry: true, busy: false },
  "failed-start": { retry: true, busy: false },
  "failed-died": { retry: true, busy: false },
};

test("BOOT covers exactly the states in the table", () => {
  assert.deepEqual(Object.values(BOOT).sort(), Object.keys(TABLE).sort());
});

test("canRetry is true only for failed-* states", () => {
  for (const [state, { retry }] of Object.entries(TABLE)) {
    assert.equal(canRetry(state), retry, `canRetry(${state})`);
  }
});

test("isBusy is true only while startup is in progress", () => {
  for (const [state, { busy }] of Object.entries(TABLE)) {
    assert.equal(isBusy(state), busy, `isBusy(${state})`);
  }
});

test("canRetry and isBusy reject non-states safely", () => {
  assert.equal(canRetry(undefined), false);
  assert.equal(canRetry(null), false);
  assert.equal(isBusy(undefined), false);
  assert.equal(isBusy("no-such-state"), false);
});
