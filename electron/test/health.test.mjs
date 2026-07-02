// health.mjs의 단위 테스트(electron 비의존). 짧은 intervalMs를 주입해 실제 시간으로
// 몇 틱만 돌리고 onDown 호출 규칙을 검증한다.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHealthMonitor } from "../lib/health.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("consecutive ping failures with a dead container fire onDown exactly once", async () => {
  let downs = 0;
  const monitor = createHealthMonitor({
    pingFn: async () => false,
    aliveFn: async () => false,
    intervalMs: 5,
    timeoutMs: 50,
    onDown: () => {
      downs += 1;
    },
  });
  monitor.start();
  await sleep(80);
  monitor.stop();
  assert.equal(downs, 1);
});

test("a busy-but-alive container never fires onDown, even past the threshold", async () => {
  let downs = 0;
  let aliveChecks = 0;
  const monitor = createHealthMonitor({
    pingFn: async () => false,
    aliveFn: async () => {
      aliveChecks += 1;
      return true;
    },
    intervalMs: 5,
    timeoutMs: 50,
    failThreshold: 2,
    onDown: () => {
      downs += 1;
    },
  });
  monitor.start();
  await sleep(80);
  monitor.stop();
  // failThreshold(2)를 훨씬 넘겨 실패했어도 컨테이너가 살아 있으면 오탐하지 않는다.
  assert.ok(aliveChecks > 2, `aliveFn should have been consulted repeatedly (${aliveChecks})`);
  assert.equal(downs, 0);
});

test("a successful ping resets the counter and monitoring continues to a real death", async () => {
  let downs = 0;
  // 시나리오: 실패(바쁨) → 성공(리셋) → 실패 + 사망 → onDown 1회.
  const pings = [false, true, false];
  const alives = [true, false];
  const monitor = createHealthMonitor({
    pingFn: async () => (pings.length ? pings.shift() : false),
    aliveFn: async () => (alives.length ? alives.shift() : false),
    intervalMs: 5,
    timeoutMs: 50,
    onDown: () => {
      downs += 1;
    },
  });
  monitor.start();
  await sleep(80);
  monitor.stop();
  assert.equal(downs, 1);
});

test("after stop() no callbacks fire", async () => {
  let downs = 0;
  const monitor = createHealthMonitor({
    pingFn: async () => false,
    aliveFn: async () => false,
    intervalMs: 5,
    timeoutMs: 50,
    onDown: () => {
      downs += 1;
    },
  });
  monitor.start();
  monitor.stop();
  await sleep(40);
  assert.equal(downs, 0);
});

test("a hanging ping counts as a failure via timeoutMs", async () => {
  let downs = 0;
  const monitor = createHealthMonitor({
    // 영원히 응답하지 않는 ping — timeoutMs가 실패로 잘라야 한다.
    pingFn: () => new Promise(() => {}),
    aliveFn: async () => false,
    intervalMs: 5,
    timeoutMs: 10,
    onDown: () => {
      downs += 1;
    },
  });
  monitor.start();
  await sleep(80);
  monitor.stop();
  assert.equal(downs, 1);
});
