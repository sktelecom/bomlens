// container.mjs의 순수 로직 단위 테스트(electron 비의존). 실제 Docker 기동/E2E는
// Windows에서 tests/windows-e2e-checklist.md와 desktop 워크플로우로 검증한다.
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  AIBOM_IMAGE,
  cleanupOrphans,
  DEFAULT_IMAGE,
  DESKTOP_LABEL,
  FIRMWARE_IMAGE,
  defaultOutputDir,
  findFreePort,
} from "../lib/container.mjs";

// cleanupOrphans용 가짜 run: docker 호출을 기록하고 ps 응답만 주입한다.
function fakeRun(psResult) {
  const calls = [];
  const runImpl = async (cmd, args) => {
    calls.push([cmd, ...args]);
    if (args[0] === "ps") return psResult;
    return { code: 0, out: "", err: "" };
  };
  return { calls, runImpl };
}

test("findFreePort returns a usable TCP port", async () => {
  const port = await findFreePort();
  assert.equal(typeof port, "number");
  assert.ok(port > 0 && port < 65536);
});

test("defaultOutputDir sits under the home directory", () => {
  // 환경변수 오버라이드가 없을 때의 기본값(홈/sbom-output)을 검증.
  if (!process.env.SBOM_OUTPUT_DIR) {
    assert.equal(defaultOutputDir(), path.join(os.homedir(), "sbom-output"));
  }
});

test("defaultOutputDir honours SBOM_OUTPUT_DIR when set", () => {
  // server.py와 같은 베이스를 공유하도록, 설정된 출력 디렉터리를 그대로 쓴다
  // (실행별 하위 폴더는 server.py가 이 베이스 아래에 만든다). 공백만 있는 값은
  // 미설정으로 보고 홈/sbom-output 기본값으로 되돌아간다.
  const prev = process.env.SBOM_OUTPUT_DIR;
  try {
    const custom = path.join(os.tmpdir(), "custom-sbom-out");
    process.env.SBOM_OUTPUT_DIR = custom;
    assert.equal(defaultOutputDir(), custom);
    process.env.SBOM_OUTPUT_DIR = "   ";
    assert.equal(defaultOutputDir(), path.join(os.homedir(), "sbom-output"));
  } finally {
    if (prev === undefined) delete process.env.SBOM_OUTPUT_DIR;
    else process.env.SBOM_OUTPUT_DIR = prev;
  }
});

test("DEFAULT_IMAGE points at the bomlens image by default", () => {
  // 환경변수 오버라이드가 없을 때의 기본값을 검증.
  if (!process.env.SBOM_SCANNER_IMAGE) {
    assert.equal(DEFAULT_IMAGE, "ghcr.io/sktelecom/bomlens:latest");
  }
});

test("cleanupOrphans lists by label and stops each orphan", async () => {
  const { calls, runImpl } = fakeRun({ code: 0, out: "abc123\ndef456\n", err: "" });
  const cleaned = await cleanupOrphans({ runImpl });
  assert.equal(cleaned, 2);
  // ps는 데스크톱 라벨 필터로 조회하고, 각 ID를 stop -t 3으로 정리해야 한다.
  assert.deepEqual(calls, [
    ["docker", "ps", "-q", "--filter", `label=${DESKTOP_LABEL}`],
    ["docker", "stop", "-t", "3", "abc123"],
    ["docker", "stop", "-t", "3", "def456"],
  ]);
});

test("cleanupOrphans keeps the current container via excludeId", async () => {
  // docker ps -q는 짧은 ID, run -d가 돌려준 excludeId는 전체 ID — 접두 일치로 제외한다.
  const { calls, runImpl } = fakeRun({ code: 0, out: "abc123\ndef456\n", err: "" });
  const cleaned = await cleanupOrphans({ runImpl, excludeId: `abc123${"0".repeat(58)}` });
  assert.equal(cleaned, 1);
  assert.deepEqual(calls.slice(1), [["docker", "stop", "-t", "3", "def456"]]);
});

test("cleanupOrphans returns 0 for an empty list without stopping anything", async () => {
  const { calls, runImpl } = fakeRun({ code: 0, out: "\n", err: "" });
  assert.equal(await cleanupOrphans({ runImpl }), 0);
  assert.equal(calls.length, 1);
});

test("cleanupOrphans returns 0 quietly when docker ps fails", async () => {
  const { calls, runImpl } = fakeRun({ code: 1, out: "", err: "docker daemon down" });
  assert.equal(await cleanupOrphans({ runImpl }), 0);
  assert.equal(calls.length, 1);
});

test("sibling image refs default to the firmware/aibom images", () => {
  // server.py의 SBOM_FIRMWARE_IMAGE/SBOM_AIBOM_IMAGE 기본값과 일치해야 한다.
  if (!process.env.SBOM_FIRMWARE_IMAGE) {
    assert.equal(FIRMWARE_IMAGE, "ghcr.io/sktelecom/bomlens-firmware:latest");
  }
  if (!process.env.SBOM_AIBOM_IMAGE) {
    assert.equal(AIBOM_IMAGE, "ghcr.io/sktelecom/bomlens-aibom:latest");
  }
});
