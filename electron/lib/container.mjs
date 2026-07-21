// BomLens UI 컨테이너 수명주기 관리(순수 Node — electron 비의존, 단위 테스트 가능).
//
// onot의 lib/sidecar.mjs가 PyInstaller 바이너리를 spawn하는 자리에서, 우리는 Docker로
// `MODE=UI` 컨테이너를 띄운다. 우리 웹 UI 백엔드(docker/web/server.py)와 React SPA는 이미
// 스캐너 이미지 안에 들어 있으므로, BrowserWindow는 이 컨테이너가 서빙하는 localhost를
// 그대로 로드하면 된다. 마운트 구성은 scripts/sbom-ui.bat과 동일하다.
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const DEFAULT_IMAGE =
  process.env.SBOM_SCANNER_IMAGE ?? "ghcr.io/sktelecom/bomlens:latest";

// 데스크톱 앱이 띄운 UI 컨테이너 식별 라벨. 앱이 강제 종료되면 --rm 컨테이너도 살아남는데,
// 다음 기동 때 이 라벨로 고아를 찾아 정리한다(cleanupOrphans).
export const DESKTOP_LABEL = "bomlens.desktop=1";

// 컨테이너 기동 실패 사유. 문구가 아니라 코드로 던져야 i18n.mjs가 사용자 언어로 옮길 수 있다
// (여기서 한국어 문자열을 던지면 영어 UI에 한국어가 그대로 샌다). detail은 docker가 준
// 원문 등 번역하지 않는 부가 정보.
export const CONTAINER_ERR = {
  RUN_FAILED: "run-failed",
  EXITED_EARLY: "exited-early",
  NOT_READY: "not-ready",
};

export class ContainerError extends Error {
  constructor(code, detail = "") {
    super(code);
    this.name = "ContainerError";
    this.code = code;
    this.detail = detail;
  }
}

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

// 추가 스캔 대상 폴더(--ui --mount의 데스크톱판)를 docker run 인자로 변환한다(순수 —
// 단위 테스트 가능). scan-sbom.sh와 같은 규칙: 폴더 이름을 안전한 문자로 정리해
// /scan-targets/<이름>에 읽기 전용으로 붙이고, 겹치면 -2, -3을 덧붙인다. 서버에는
// SBOM_UI_SCAN_ROOTS("<컨테이너 경로>|<호스트 경로>" 줄 단위)로 전달한다.
export function scanMountArgs(dirs = []) {
  const args = [];
  const seen = new Set();
  let scanRoots = "";
  for (const dir of dirs) {
    const trimmed = String(dir ?? "").trim();
    if (!trimmed) continue;
    // 끝의 구분자를 떼고 마지막 경로 조각을 이름으로 쓴다(윈도우 드라이브 루트
    // "C:\" 는 조각이 없어 아래 루트 폴백을 탄다).
    const segments = trimmed.split(/[/\\]+/).filter((s) => s && !/^[A-Za-z]:$/.test(s));
    let name = (segments[segments.length - 1] ?? "").replace(/[^A-Za-z0-9._-]/g, "-");
    if (!name || name === "-" || name === "." || name === "..") name = "root";
    let unique = name;
    for (let n = 2; seen.has(unique); n += 1) unique = `${name}-${n}`;
    seen.add(unique);
    args.push("-v", `${trimmed}:/scan-targets/${unique}:ro`);
    scanRoots += `/scan-targets/${unique}|${trimmed}\n`;
  }
  if (scanRoots) args.push("-e", `SBOM_UI_SCAN_ROOTS=${scanRoots}`);
  return args;
}

// 호스트의 Docker 엔진을 컨테이너에 연결하는 마운트. UI 컨테이너가 언어별 cdxgen 이미지를
// 띄우려면 호스트 엔진에 접근해야 한다. Windows 명명 파이프(\\.\pipe\docker_engine)는 Docker
// Desktop만 특수처리하고 Rancher Desktop은 거부하므로(invalid volume name), 양쪽 모두 지원하고
// 컨테이너 엔트리포인트가 실제로 요구하는 유닉스 소켓을 쓴다. (sbom-ui.bat과 동일하게 정렬)
function engineMount() {
  return "/var/run/docker.sock:/var/run/docker.sock";
}

// docker 호출. timeoutMs를 주면 그 안에 끝나지 않을 때 프로세스를 죽이고 code:-2로 돌려준다.
// 코드 규약: -1 = spawn 실패(바이너리 없음), -2 = 타임아웃. 둘을 구분해야 "Docker 미설치"와
// "데몬이 응답하지 않음"을 갈라 안내할 수 있다. 타임아웃이 없으면 방화벽에 걸린 데몬 호출이
// 살아있어 보이는 창에서 영원히 멈춘다.
function run(cmd, args, { timeoutMs, ...opts } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
    let out = "";
    let err = "";
    let timer = null;
    // kill 이후에도 close가 뒤따라 오므로 resolve는 한 번만 유효하다(두 번째는 무시됨).
    const done = (result) => {
      if (timer) clearTimeout(timer);
      timer = null;
      resolve(result);
    };
    child.stdout?.on("data", (d) => (out += d.toString()));
    child.stderr?.on("data", (d) => (err += d.toString()));
    child.on("error", () => done({ code: -1, out, err }));
    child.on("close", (code) => done({ code: code ?? -1, out, err }));
    if (timeoutMs) {
      timer = setTimeout(() => {
        child.kill();
        done({ code: -2, out, err, timedOut: true });
      }, timeoutMs);
    }
  });
}

// PATH에 docker가 없을 때만 뒤져보는 알려진 설치 경로.
//
// 왜 필요한가: Rancher Desktop을 설치하면 PATH에 ~/.rd/bin이 추가되지만, 이미 떠 있던
// Explorer(그리고 거기서 실행된 앱)는 갱신된 PATH를 물려받지 못한다. 그러면 트레이에서
// 엔진이 멀쩡히 도는데도 앱은 "Docker가 설치되어 있지 않습니다"를 띄운다. macOS도 같은
// 문제가 있다 — GUI로 띄운 앱은 셸 PATH를 상속하지 않아 Homebrew/Colima의 docker를 못 본다.
//
// 순수 함수로 두어(exists/platform/env 주입) 단위 테스트가 실제 파일시스템에 의존하지 않게 한다.
export function resolveDockerBin({
  exists = fs.existsSync,
  platform = process.platform,
  env = process.env,
} = {}) {
  const join = (base, tail) => (base ? `${base}${tail}` : null);
  const candidates =
    platform === "win32"
      ? [
          join(env.ProgramFiles ?? "C:\\Program Files", "\\Docker\\Docker\\resources\\bin\\docker.exe"),
          // Rancher Desktop ships both a system-wide installer (Program Files) and
          // a per-user one (LOCALAPPDATA). Probe both — a machine-wide install is
          // the common case on managed corporate laptops.
          join(env.ProgramFiles ?? "C:\\Program Files", "\\Rancher Desktop\\resources\\resources\\win32\\bin\\docker.exe"),
          join(env.LOCALAPPDATA, "\\Programs\\Rancher Desktop\\resources\\resources\\win32\\bin\\docker.exe"),
          join(env.USERPROFILE, "\\.rd\\bin\\docker.exe"),
          join(env.ProgramData ?? "C:\\ProgramData", "\\chocolatey\\bin\\docker.exe"),
        ]
      : [
          "/usr/local/bin/docker",
          "/opt/homebrew/bin/docker",
          join(env.HOME, "/.rd/bin/docker"),
          join(env.HOME, "/.docker/bin/docker"),
        ];
  for (const candidate of candidates) {
    if (candidate && exists(candidate)) return candidate;
  }
  return null;
}

// 실제로 실행할 docker 명령. 기본값은 PATH의 "docker"이고, spawn이 ENOENT로 실패했을 때만
// (dockerStatus 안에서) 탐색 결과로 교체된다 — 미리 뒤지면 사용자의 진짜 PATH 항목을 가릴 수 있다.
let dockerBin = "docker";
export function currentDockerBin() {
  return dockerBin;
}
// Docker 재확인(FAILED_DOCKER 재시도) 시 캐시를 버린다. 앱을 켜 둔 채 Docker를 설치한
// 경우에도 복구되어야 한다.
export function resetDockerBin() {
  dockerBin = "docker";
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
// 기동 대기(UiContainer.start)와 로드 이후의 헬스 모니터(main.mjs)가 함께 쓴다.
export function ping(port) {
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
// info는 콜드 스타트한 Docker Desktop이 정상적으로 ~15초까지 걸린다. 너무 조이면 건강한
// 노트북이 "엔진 미실행"으로 오분류되므로 넉넉히 잡는다.
const VERSION_TIMEOUT_MS = 10_000;
const INFO_TIMEOUT_MS = 20_000;
const QUICK_TIMEOUT_MS = 15_000;

export async function dockerStatus() {
  let version = await run(dockerBin, ["version"], { timeoutMs: VERSION_TIMEOUT_MS });
  // code -1은 spawn 실패(PATH에 없음)다. 이때만 알려진 설치 경로를 뒤져 한 번 더 시도한다.
  if (version.code === -1 && dockerBin === "docker") {
    const probed = resolveDockerBin();
    if (probed) {
      dockerBin = probed;
      version = await run(dockerBin, ["version"], { timeoutMs: VERSION_TIMEOUT_MS });
    }
  }
  // 타임아웃은 "바이너리는 있는데 데몬이 응답하지 않는" 상태다. 미설치로 오분류하면
  // 사용자에게 엉뚱한 설치 안내를 띄우게 된다.
  if (version.timedOut) return { installed: true, running: false };
  if (version.code !== 0) return { installed: false, running: false };
  const info = await run(dockerBin, ["info"], { timeoutMs: INFO_TIMEOUT_MS });
  return { installed: true, running: info.code === 0 };
}

export async function imagePresent(image = DEFAULT_IMAGE) {
  const r = await run(dockerBin, ["image", "inspect", image], { timeoutMs: QUICK_TIMEOUT_MS });
  return r.code === 0;
}

// 실패 원인 분류를 위해 보관하는 출력 꼬리 길이. 전체 pull 로그는 수 MB가 될 수 있다.
const PULL_LOG_TAIL = 4096;

// 첫 실행이면 이미지를 받는다. 진행 줄을 onProgress로 흘려보내 창에 표시할 수 있게 한다.
//
// 타임아웃은 절대시간이 아니라 "정체(stall)" 기준이다 — 행사장 Wi-Fi에서는 큰 pull이
// 정당하게 20분을 넘길 수 있어(AI 모델 이미지 3.5GB, cdxgen 올인원 4.35GB) 절대 상한은
// 멀쩡한 다운로드를 죽인다. 대신 출력이 완전히
// 멎으면(방화벽에 걸린 half-open 연결) 그때 끊는다. maxMs는 폭주 방지용 최후 상한.
//
// 반환: { ok, reason, log } — reason은 실패했을 때만 의미가 있다("timeout" | "exit").
// (예전에는 boolean을 돌려줬다. 호출부에서 truthy 검사로 착각하지 않도록 주의.)
export function pullImage(
  image = DEFAULT_IMAGE,
  onProgress = () => {},
  { stallMs = 150_000, maxMs = 45 * 60_000 } = {},
) {
  return new Promise((resolve) => {
    const child = spawn(dockerBin, ["pull", image], { stdio: ["ignore", "pipe", "pipe"] });
    let log = "";
    let stallTimer = null;
    let maxTimer = null;
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(stallTimer);
      clearTimeout(maxTimer);
      resolve(result);
    };
    const kick = () => {
      clearTimeout(stallTimer);
      stallTimer = setTimeout(() => {
        child.kill();
        finish({ ok: false, reason: "timeout", log });
      }, stallMs);
    };

    const emit = (buf) => {
      const text = buf.toString();
      // 원인 분류용으로 꼬리만 남긴다(classifyPullFailure가 읽는다).
      log = (log + text).slice(-PULL_LOG_TAIL);
      kick();
      text
        .split(/\r?\n/)
        .filter(Boolean)
        .forEach((line) => onProgress(line));
    };

    child.stdout.on("data", emit);
    child.stderr.on("data", emit);
    child.on("error", () => finish({ ok: false, reason: "exit", log }));
    child.on("close", (code) => finish({ ok: code === 0, reason: "exit", log }));

    kick();
    maxTimer = setTimeout(() => {
      child.kill();
      finish({ ok: false, reason: "timeout", log });
    }, maxMs);
  });
}

// 이전 실행이 남긴 고아 UI 컨테이너를 정리한다(DESKTOP_LABEL 기준). excludeId가 주어지면
// 그 컨테이너(현재 실행분)는 남긴다. docker ps는 짧은 ID를, run -d는 전체 ID를 돌려주므로
// 접두 일치로 비교한다. Docker 오류는 조용히 0을 반환한다(정리는 최선 노력이면 충분).
export async function cleanupOrphans({ runImpl = run, excludeId = null } = {}) {
  const r = await runImpl(dockerBin, ["ps", "-q", "--filter", `label=${DESKTOP_LABEL}`], {
    timeoutMs: QUICK_TIMEOUT_MS,
  });
  if (r.code !== 0) return 0;
  const ids = r.out
    .split(/\r?\n/)
    .map((id) => id.trim())
    .filter(Boolean)
    .filter((id) => !(excludeId && (excludeId.startsWith(id) || id.startsWith(excludeId))));
  for (const id of ids) {
    await runImpl(dockerBin, ["stop", "-t", "3", id], { timeoutMs: QUICK_TIMEOUT_MS });
  }
  return ids.length;
}

export class UiContainer {
  constructor({
    image = DEFAULT_IMAGE,
    hostPort,
    outputDir = defaultOutputDir(),
    firmwareImage = FIRMWARE_IMAGE,
    aibomImage = AIBOM_IMAGE,
    scanMounts = [],
  } = {}) {
    this.image = image;
    this.hostPort = hostPort;
    this.outputDir = outputDir;
    this.firmwareImage = firmwareImage;
    this.aibomImage = aibomImage;
    this.scanMounts = scanMounts;
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
      "--label",
      DESKTOP_LABEL,
      "-p",
      `${this.hostPort}:8080`,
      "-v",
      `${this.outputDir}:/src`,
      "-v",
      `${this.outputDir}:/host-output`,
      // 추가 스캔 대상 폴더(읽기 전용) — 웹 UI의 "디렉터리 경로" 입력 선택지가 된다.
      ...scanMountArgs(this.scanMounts),
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
    const r = await run(dockerBin, args);
    if (r.code !== 0) {
      throw new ContainerError(CONTAINER_ERR.RUN_FAILED, r.err.trim() || r.out.trim());
    }
    this.id = r.out.trim().split(/\r?\n/).pop();

    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await ping(this.hostPort)) return this.hostPort;
      if (!(await this.alive())) throw new ContainerError(CONTAINER_ERR.EXITED_EARLY);
      await sleep(300);
    }
    await this.stop();
    throw new ContainerError(CONTAINER_ERR.NOT_READY, String(timeoutMs));
  }

  async alive() {
    if (!this.id) return false;
    const r = await run(dockerBin, ["inspect", "-f", "{{.State.Running}}", this.id], {
      timeoutMs: QUICK_TIMEOUT_MS,
    });
    return r.code === 0 && r.out.trim() === "true";
  }

  // 컨테이너 정리. --rm이므로 stop이면 제거까지 된다. 고아 방지로 멱등하게.
  async stop() {
    const id = this.id;
    this.id = null;
    if (!id) return;
    await run(dockerBin, ["stop", "-t", "3", id]);
  }
}
