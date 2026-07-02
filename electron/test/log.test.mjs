// log.mjs 단위 테스트(electron 비의존). 줄 형식, 실행마다 파일을 새로 쓰는지,
// 순서 보존, 그리고 파일 오류를 조용히 넘기는지 검증한다.
import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createStartupLogger, formatLogLine } from "../lib/log.mjs";

test("formatLogLine prefixes an ISO timestamp and ends with a newline", () => {
  const date = new Date("2026-07-02T04:05:06.789Z");
  assert.equal(formatLogLine(date, "Checking Docker..."), "2026-07-02T04:05:06.789Z Checking Docker...\n");
});

test("createStartupLogger truncates the previous run and appends lines in order", async () => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "bomlens-log-"));
  const file = path.join(dir, "startup.log");
  // 이전 실행의 내용이 남아 있다고 가정한다. 새 로거가 이를 지워야 한다.
  await fs.promises.writeFile(file, "stale line from a previous run\n");

  const logger = createStartupLogger(file);
  logger.line("first");
  logger.line("second");
  await logger.close();

  const text = await fs.promises.readFile(file, "utf8");
  assert.ok(!text.includes("stale line"), "previous contents should be truncated");
  const lines = text.trimEnd().split("\n");
  assert.equal(lines.length, 2);
  assert.match(lines[0], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z first$/);
  assert.match(lines[1], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z second$/);
});

test("logger swallows file errors instead of throwing", async () => {
  // 존재하지 않는 디렉터리: 스트림 생성/쓰기가 실패해도 line/close는 예외가 없어야 한다.
  const logger = createStartupLogger(path.join(os.tmpdir(), "no-such-dir-bomlens", "x", "startup.log"));
  logger.line("goes nowhere");
  await logger.close();
  // close 이후의 line도 조용히 무시된다.
  logger.line("after close");
});
