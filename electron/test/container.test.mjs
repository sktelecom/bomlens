// container.mjs의 순수 로직 단위 테스트(electron 비의존). 실제 Docker 기동/E2E는
// Windows에서 tests/windows-e2e-checklist.md와 desktop 워크플로우로 검증한다.
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  DEFAULT_IMAGE,
  defaultOutputDir,
  findFreePort,
} from "../lib/container.mjs";

test("findFreePort returns a usable TCP port", async () => {
  const port = await findFreePort();
  assert.equal(typeof port, "number");
  assert.ok(port > 0 && port < 65536);
});

test("defaultOutputDir sits under the home directory", () => {
  assert.equal(defaultOutputDir(), path.join(os.homedir(), "sbom-output"));
});

test("DEFAULT_IMAGE points at the generator image by default", () => {
  // 환경변수 오버라이드가 없을 때의 기본값을 검증.
  if (!process.env.SBOM_SCANNER_IMAGE) {
    assert.equal(DEFAULT_IMAGE, "ghcr.io/sktelecom/sbom-generator:latest");
  }
});
