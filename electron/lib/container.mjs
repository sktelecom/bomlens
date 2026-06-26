// SBOM Generator UI 컨테이너 수명주기 관리(순수 Node — electron 비의존, 단위 테스트 가능).
//
// onot의 lib/sidecar.mjs가 PyInstaller 바이너리를 spawn하는 자리에서, 우리는 Docker로
// `MODE=UI` 컨테이너를 띄운다. 우리 웹 UI 백엔드(docker/web/server.py)와 React SPA는 이미
// 스캐너 이미지 안에 들어 있으므로, BrowserWindow는 이 컨테이너가 서빙하는 localhost를
// 그대로 로드하면 된다. 마운트 구성은 scripts/sbom-ui.bat과 동일하다.
import { spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const DEFAULT_IMAGE =
  process.env.SBOM_SCANNER_IMAGE ?? "ghcr.io/sktelecom/sbom-generator:latest";

// Opt-in scan images the base UI container launches as SIBLING containers (via
// the mounted host Docker socket) for firmware and AI-model inputs — the GPL
// firmware tools and the heavy aibom deps can't live in the permissive-only
// base image. Kept in sync with server.py's SBOM_FIRMWARE_IMAGE / SBOM_AIBOM_IMAGE
// defaults; passed into the container as env so both sides agree on the refs.
export const FIRMWARE_IMAGE =
  process.env.SBOM_FIRMWARE_IMAGE ?? "ghcr.io/sktelecom/bomlens-firmware:latest";
export const AIBOM_IMAGE =
  process.env.SBOM_AIBOM_IMAGE ?? "ghcr.io/sktelecom/bomlens-aibom:latest";

// 결과 저장 폴더. 두 엔진(Rancher/Docker Desktop) 모두 기본 공유하는 홈 디렉터리 아래.
// SBOM_OUTPUT_DIR로 베이스를 바꿀 수 있다(실행별 하위 폴더는 server.py가 그 아래에 만든다).
export function defaultOutputDir() {
  const override = process.env.SBOM_OUTPUT_DIR;
  return override && override.trim() ? override : path.join(os.homedir(), "sbom-output");
}

// 호스트의 Docker 엔진을 컨테이너에 연결하는 마운트. UI 컨테이너가 언어별 cdxgen 이미지를
// 띄우려면 호스트 엔진에 접근해야 한다. Windows 명명 파이프(\\.\pipe\docker_engine)는 Docker
// Desktop만 특수처리하고 Rancher Desktop은 거부하므로(invalid volume name), 양쪽 모두 지원하고
// 컨테이너 엔트리포인트가 실제로 요구하는 유닉스 소켓을 쓴다. (sbom-ui.bat과 동일하게 정렬)
function engineMount() {
  return "/var/run/docker.sock:/var/run/docker.sock";
}

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
    let out = "";
    let err = "";
    child.stdout?.on("data", (d) => (out += d.toString()));
    child.stderr?.on("data", (d) => (err += d.toString()));
    child.on("error", () => resolve({ code: -1, out, err }));
    child.on("close", (code) => resolve({ code: code ?? -1, out, err }));
  });
}

export function findFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// /capabilities는 200 + JSON을 반환하는 가벼운 엔드포인트라 readiness 신호로 적합하다.
function ping(port) {
  return new Promise((resolve) => {
    const req = http.get(
      { host: "127.0.0.1", port, path: "/capabilities", timeout: 1500 },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });
}

// Docker 설치/실행 상태를 점검한다. check-setup 도우미와 같은 항목.
export async function dockerStatus() {
  const version = await run("docker", ["version"]);
  if (version.code !== 0) return { installed: false, running: false };
  const info = await run("docker", ["info"]);
  return { installed: true, running: info.code === 0 };
}

export async function imagePresent(image = DEFAULT_IMAGE) {
  const r = await run("docker", ["image", "inspect", image]);
  return r.code === 0;
}

// 첫 실행이면 이미지를 받는다. 진행 줄을 onProgress로 흘려보내 창에 표시할 수 있게 한다.
export function pullImage(image = DEFAULT_IMAGE, onProgress = () => {}) {
  return new Promise((resolve) => {
    const child = spawn("docker", ["pull", image], { stdio: ["ignore", "pipe", "pipe"] });
    const emit = (buf) =>
      buf
        .toString()
        .split(/\r?\n/)
        .filter(Boolean)
        .forEach((line) => onProgress(line));
    child.stdout.on("data", emit);
    child.stderr.on("data", emit);
    child.on("error", () => resolve(false));
    child.on("close", (code) => resolve(code === 0));
  });
}

export class UiContainer {
  constructor({
    image = DEFAULT_IMAGE,
    hostPort,
    outputDir = defaultOutputDir(),
    firmwareImage = FIRMWARE_IMAGE,
    aibomImage = AIBOM_IMAGE,
  } = {}) {
    this.image = image;
    this.hostPort = hostPort;
    this.outputDir = outputDir;
    this.firmwareImage = firmwareImage;
    this.aibomImage = aibomImage;
    this.id = null;
  }

  // 컨테이너를 detached로 띄우고 /capabilities가 200이 될 때까지 기다린다.
  async start({ timeoutMs = 60000 } = {}) {
    const name = `sbom-ui-${this.hostPort}`;
    const args = [
      "run",
      "-d",
      "--rm",
      "--name",
      name,
      "-p",
      `${this.hostPort}:8080`,
      "-v",
      `${this.outputDir}:/src`,
      "-v",
      `${this.outputDir}:/host-output`,
      "-v",
      engineMount(),
      "-e",
      "MODE=UI",
      "-e",
      "UI_PORT=8080",
      "-e",
      `SBOM_UI_HOST_DIR=${this.outputDir}`,
      // Sibling-image refs for firmware / AI-model scans (server.py launches
      // these via the host socket when the input type needs them).
      "-e",
      `SBOM_FIRMWARE_IMAGE=${this.firmwareImage}`,
      "-e",
      `SBOM_AIBOM_IMAGE=${this.aibomImage}`,
      this.image,
    ];
    const r = await run("docker", args);
    if (r.code !== 0) {
      throw new Error(`docker run 실패: ${r.err.trim() || r.out.trim()}`);
    }
    this.id = r.out.trim().split(/\r?\n/).pop();

    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await ping(this.hostPort)) return this.hostPort;
      if (!(await this.alive())) throw new Error("UI 컨테이너가 기동 중 종료되었습니다.");
      await sleep(300);
    }
    await this.stop();
    throw new Error(`UI가 ${timeoutMs}ms 안에 준비되지 않았습니다.`);
  }

  async alive() {
    if (!this.id) return false;
    const r = await run("docker", ["inspect", "-f", "{{.State.Running}}", this.id]);
    return r.code === 0 && r.out.trim() === "true";
  }

  // 컨테이너 정리. --rm이므로 stop이면 제거까지 된다. 고아 방지로 멱등하게.
  async stop() {
    const id = this.id;
    this.id = null;
    if (!id) return;
    await run("docker", ["stop", "-t", "3", id]);
  }
}
