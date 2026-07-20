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
  ContainerError,
  CONTAINER_ERR,
  currentDockerBin,
  defaultOutputDir,
  findFreePort,
  resolveDockerBin,
  scanMountArgs,
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

test("ContainerError carries a translatable code and never a message for the user", () => {
  const err = new ContainerError(CONTAINER_ERR.RUN_FAILED, "port is already allocated");
  assert.equal(err.code, "run-failed");
  assert.equal(err.detail, "port is already allocated");
  // 코드 자체가 message가 되어야 로그에 안정적인 검색 키가 남는다.
  assert.equal(err.message, "run-failed");
  assert.ok(err instanceof Error);
  // 사전이 아니라 여기에 한국어가 들어가면 영어 UI로 그대로 샌다.
  for (const code of Object.values(CONTAINER_ERR)) assert.doesNotMatch(code, /[가-힣]/);
});

test("docker binary defaults to PATH so it is never probed eagerly", () => {
  // 기본값이 리터럴이어야 fake-docker(PATH 주입)와 cleanupOrphans 호출 단언이 성립한다.
  assert.equal(currentDockerBin(), "docker");
});

test("resolveDockerBin probes the known Windows install paths in order", () => {
  const env = {
    ProgramFiles: "C:\\Program Files",
    LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local",
    USERPROFILE: "C:\\Users\\u",
    ProgramData: "C:\\ProgramData",
  };
  // Docker Desktop이 있으면 그것을 먼저 고른다.
  assert.equal(
    resolveDockerBin({ platform: "win32", env, exists: () => true }),
    "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
  );
  // Rancher Desktop만 설치된 경우(가장 흔한 오진 상황)를 집어낸다.
  const rancher = "C:\\Users\\u\\.rd\\bin\\docker.exe";
  assert.equal(
    resolveDockerBin({ platform: "win32", env, exists: (p) => p === rancher }),
    rancher,
  );
  // 실제 이 개발 PC의 설치 형태: Program Files 아래 시스템 전역 Rancher Desktop.
  // 관리형 사내 노트북에서 흔한 경로라 반드시 잡아야 한다.
  const rdSystem = "C:\\Program Files\\Rancher Desktop\\resources\\resources\\win32\\bin\\docker.exe";
  assert.equal(
    resolveDockerBin({ platform: "win32", env, exists: (p) => p === rdSystem }),
    rdSystem,
  );
  // 아무것도 없으면 null — 호출부는 "docker"를 그대로 쓰고 미설치로 안내한다.
  assert.equal(resolveDockerBin({ platform: "win32", env, exists: () => false }), null);
});

test("resolveDockerBin skips candidates whose env var is missing", () => {
  // USERPROFILE이 비어 있을 때 "\\.rd\\bin\\docker.exe" 같은 엉뚱한 경로를 만들면 안 된다.
  const seen = [];
  resolveDockerBin({
    platform: "win32",
    env: { ProgramFiles: "C:\\PF", ProgramData: "C:\\PD" },
    exists: (p) => {
      seen.push(p);
      return false;
    },
  });
  assert.deepEqual(seen, [
    "C:\\PF\\Docker\\Docker\\resources\\bin\\docker.exe",
    "C:\\PF\\Rancher Desktop\\resources\\resources\\win32\\bin\\docker.exe",
    "C:\\PD\\chocolatey\\bin\\docker.exe",
  ]);
});

test("resolveDockerBin probes Homebrew and Rancher paths on macOS", () => {
  const brew = "/opt/homebrew/bin/docker";
  assert.equal(
    resolveDockerBin({ platform: "darwin", env: { HOME: "/Users/u" }, exists: (p) => p === brew }),
    brew,
  );
  const rd = "/Users/u/.rd/bin/docker";
  assert.equal(
    resolveDockerBin({ platform: "darwin", env: { HOME: "/Users/u" }, exists: (p) => p === rd }),
    rd,
  );
});

test("scanMountArgs mounts each folder read-only and passes the roots env", () => {
  // scan-sbom.sh --ui --mount와 같은 계약: /scan-targets/<이름>:ro 마운트 +
  // SBOM_UI_SCAN_ROOTS("<컨테이너 경로>|<호스트 경로>" 줄 단위).
  const args = scanMountArgs(["/data/server-rootfs"]);
  assert.deepEqual(args, [
    "-v",
    "/data/server-rootfs:/scan-targets/server-rootfs:ro",
    "-e",
    "SBOM_UI_SCAN_ROOTS=/scan-targets/server-rootfs|/data/server-rootfs\n",
  ]);
});

test("scanMountArgs dedupes clashing folder names with a numeric suffix", () => {
  const args = scanMountArgs(["/a/rootfs", "/b/rootfs"]);
  assert.equal(args[1], "/a/rootfs:/scan-targets/rootfs:ro");
  assert.equal(args[3], "/b/rootfs:/scan-targets/rootfs-2:ro");
});

test("scanMountArgs names filesystem roots 'root' and sanitizes odd characters", () => {
  // 리눅스 루트("/")와 윈도우 드라이브 루트("C:\")는 마지막 경로 조각이 없다.
  assert.equal(scanMountArgs(["/"])[1], "/:/scan-targets/root:ro");
  assert.equal(scanMountArgs(["C:\\"])[1], "C:\\:/scan-targets/root:ro");
  // 한글·공백 등 허용 밖 문자는 '-'로 치환된다(컨테이너 경로만; 호스트 경로는 그대로).
  assert.equal(scanMountArgs(["/mnt/서버 백업"])[1], "/mnt/서버 백업:/scan-targets/-----:ro");
});

test("scanMountArgs skips blank entries and returns [] for an empty list", () => {
  assert.deepEqual(scanMountArgs([]), []);
  assert.deepEqual(scanMountArgs(["", "   ", null]), []);
});

test("scanMountArgs keeps a Windows folder path intact in mount and env", () => {
  const args = scanMountArgs(["C:\\Users\\me\\extracted-rootfs"]);
  assert.equal(args[1], "C:\\Users\\me\\extracted-rootfs:/scan-targets/extracted-rootfs:ro");
  assert.equal(
    args[3],
    "SBOM_UI_SCAN_ROOTS=/scan-targets/extracted-rootfs|C:\\Users\\me\\extracted-rootfs\n",
  );
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
