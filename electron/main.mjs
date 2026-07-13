// Electron 메인 프로세스: Docker 점검 → 이미지 프리풀 → MODE=UI 컨테이너 기동 →
// 헬스 폴링 → 컨테이너가 서빙하는 UI 로드 → 종료 시 컨테이너 정리.
//
// onot의 main.mjs를 본떴으나, 파이썬 사이드카 대신 Docker 컨테이너를 띄운다(lib/container.mjs).
// 백엔드와 React SPA가 이미 스캐너 이미지 안에 있으므로 BrowserWindow는 localhost를 로드한다.
import { app, BrowserWindow, dialog, ipcMain, nativeTheme, screen, session, shell } from "electron";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  cleanupOrphans,
  DEFAULT_IMAGE,
  dockerStatus,
  findFreePort,
  imagePresent,
  ping,
  pullImage,
  UiContainer,
} from "./lib/container.mjs";
import { BOOT, canRetry, isBusy } from "./lib/boot.mjs";
import { addScanMounts, parseScanMounts, removeScanMount } from "./lib/scanmounts.mjs";
import { createHealthMonitor } from "./lib/health.mjs";
import { createStartupLogger } from "./lib/log.mjs";
import { parseWindowState, sanitizeBounds } from "./lib/winstate.mjs";
import { mainMessages, resolveLang } from "./lib/i18n.mjs";
import { checkForUpdate, RELEASES_PAGE } from "./lib/update.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

let container = null;
let healthMonitor = null;
let mainWindow = null;
// 부팅 로그: 상태 화면과 같은 내용을 userData/startup.log에 남긴다(whenReady에서 생성).
let startupLogger = null;
let appOrigin = "file://";
// 시작 화면 언어: app.getLocale()로 결정(앱 준비 이후에 확정). 그 전 안전한 기본은 영어.
let lang = "en";
let t = mainMessages("en");

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

// 진행 메시지: 상태 화면(렌더러)과 시작 로그 파일에 이중으로 기록한다.
function status(line) {
  send("status", line);
  startupLogger?.line(line);
}

// 부팅 상태 전이: 전역 상태를 갱신하고 렌더러(상태 화면)에 브로드캐스트한다.
// reason은 실패 상태의 부가 정보(예: docker-missing의 not-installed/not-running).
let bootState = BOOT.IDLE;
function setBootState(state, reason = null) {
  bootState = state;
  // 상태 전이도 시작 로그에 남긴다. 진행 메시지 사이의 전이 시점이 문제 진단에 유용하다.
  startupLogger?.line(reason ? `boot state: ${state} (${reason})` : `boot state: ${state}`);
  send("startup-state", { state, reason });
}

// 보안: 신규 창 차단, 외부 출처 네비게이션은 시스템 브라우저로.
function hardenWebContents(contents) {
  contents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http:") || url.startsWith("https:")) shell.openExternal(url);
    return { action: "deny" };
  });
  contents.on("will-navigate", (event, url) => {
    if (!url.startsWith(appOrigin) && !url.startsWith("file://")) {
      event.preventDefault();
      if (url.startsWith("http:") || url.startsWith("https:")) shell.openExternal(url);
    }
  });
}

// 추가 스캔 폴더(웹 UI "디렉터리 경로" 입력의 선택지가 되는 읽기 전용 마운트):
// userData/scan-mounts.json에 저장하고 컨테이너 기동 인자에 반영한다(lib/scanmounts.mjs).
// 마운트는 기동 시점에만 붙일 수 있으므로, 목록이 바뀌면 컨테이너를 재시작한다.
function scanMountsPath() {
  return path.join(app.getPath("userData"), "scan-mounts.json");
}

// 저장된 목록 그대로(존재하지 않는 폴더 포함) — IPC 추가/제거의 기준이 된다.
function savedScanMounts() {
  try {
    return parseScanMounts(fs.readFileSync(scanMountsPath(), "utf8"));
  } catch {
    // 파일 없음/읽기 실패: 첫 실행처럼 빈 목록.
    return [];
  }
}

// 실제로 마운트할 목록: 사라진 폴더(이동/삭제/USB 분리)는 이번 기동에서만 빼고
// 목록에는 남긴다 — 폴더가 돌아오면 다음 실행에서 다시 붙는다. docker run이
// 없는 경로로 실패하는 것보다 낫다.
function mountableScanMounts() {
  return savedScanMounts().filter((dir) => {
    try {
      return fs.statSync(dir).isDirectory();
    } catch {
      startupLogger?.line(`scan mount skipped (not a directory): ${dir}`);
      return false;
    }
  });
}

function saveScanMounts(list) {
  try {
    fs.writeFileSync(scanMountsPath(), JSON.stringify(list));
  } catch {
    // 저장 실패는 무시한다(이번 실행의 마운트는 유지되고, 다음 실행에서 빠질 뿐이다).
  }
}

// 마운트 목록 변경 후 컨테이너 재시작: 상태 화면으로 돌아가 부팅을 재개한다.
// 진행 중인 스캔도 함께 끊기므로, 호출부(렌더러)가 사용자 동작에만 묶는다.
async function restartForScanMounts() {
  healthMonitor?.stop();
  healthMonitor = null;
  const current = container;
  container = null;
  appOrigin = "file://";
  await current?.stop();
  if (!mainWindow || mainWindow.isDestroyed() || shutdownPromise) return;
  await mainWindow.loadFile(path.join(here, "assets", "status.html"), {
    query: { lang, v: app.getVersion() },
  });
  setBootState(BOOT.IDLE);
  startup().catch((err) => status(t.startFailed(err.message)));
}

// 창 위치/크기 기억: userData/window-state.json에 저장하고 다음 실행에서 복원한다.
// 파일 손상이나 모니터 구성 변화로 화면 밖이면 기본 크기로 뜬다(lib/winstate.mjs).
const WINDOW_DEFAULTS = { width: 1200, height: 860 };

function windowStatePath() {
  return path.join(app.getPath("userData"), "window-state.json");
}

function restoreWindowState() {
  let saved = null;
  try {
    saved = parseWindowState(fs.readFileSync(windowStatePath(), "utf8"));
  } catch {
    // 파일 없음/읽기 실패: 첫 실행처럼 기본값으로 뜬다.
  }
  const workAreas = screen.getAllDisplays().map((display) => display.workArea);
  return {
    bounds: sanitizeBounds(saved, workAreas, WINDOW_DEFAULTS),
    maximized: saved?.maximized === true,
  };
}

function saveWindowState() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  // getNormalBounds(): 최대화 상태여도 복원 시 쓸 일반 상태의 영역을 준다.
  const state = { ...mainWindow.getNormalBounds(), maximized: mainWindow.isMaximized() };
  try {
    fs.writeFileSync(windowStatePath(), JSON.stringify(state));
  } catch {
    // 저장 실패는 무시한다(다음 실행이 기본값으로 뜰 뿐이다).
  }
}

async function createWindow() {
  const { bounds, maximized } = restoreWindowState();
  mainWindow = new BrowserWindow({
    ...bounds,
    // 첫 페인트 배경을 OS 테마에 맞춰 흰/검 플래시를 막는다. 시작 화면의 CSS
    // (prefers-color-scheme)와 같은 색이어야 한다.
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#0a0a0c" : "#f5f5f7",
    title: "BomLens",
    // Windows/Linux에서 메뉴바를 숨긴다(Alt로 꺼낼 수 있고 Edit 단축키는 유지된다).
    // Menu.setApplicationMenu(null)은 단축키까지 없애므로 쓰지 않는다.
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(here, "preload.mjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false, // ESM preload 사용
    },
  });
  if (maximized) mainWindow.maximize();
  mainWindow.on("close", saveWindowState);
  await mainWindow.loadFile(path.join(here, "assets", "status.html"), {
    query: { lang, v: app.getVersion() },
  });
}

async function startup() {
  // 중복 진입 가드: 이미 부팅이 진행 중이면 아무것도 하지 않는다(재시도 경합 대비).
  if (isBusy(bootState)) return;
  setBootState(BOOT.CHECKING);
  status(t.dockerChecking);
  const docker = await dockerStatus();
  if (!docker.installed || !docker.running) {
    appOrigin = "file://";
    const reason = !docker.installed ? "not-installed" : "not-running";
    setBootState(BOOT.FAILED_DOCKER, reason);
    // platform은 OS별 설치 안내(옵션 목록) 분기용. 렌더러는 process에 접근할 수 없다.
    await mainWindow.loadFile(path.join(here, "assets", "docker-missing.html"), {
      query: { reason, lang, platform: process.platform, v: app.getVersion() },
    });
    return;
  }

  // 이전 실행(강제 종료 등)이 남긴 고아 UI 컨테이너를 라벨 기준으로 정리한다.
  const cleaned = await cleanupOrphans({ excludeId: container?.id ?? null });
  if (cleaned > 0) status(t.cleanedOrphans(cleaned));

  if (!(await imagePresent(DEFAULT_IMAGE))) {
    setBootState(BOOT.PULLING);
    status(t.firstPull);
    status(t.image(DEFAULT_IMAGE));
    status(t.network);
    const ok = await pullImage(DEFAULT_IMAGE, (line) => status(line));
    if (!ok) {
      status(t.pullFailed);
      setBootState(BOOT.FAILED_PULL);
      return;
    }
  }

  setBootState(BOOT.STARTING);
  status(t.startingUi);
  try {
    const port = await findFreePort();
    container = new UiContainer({
      image: DEFAULT_IMAGE,
      hostPort: port,
      scanMounts: mountableScanMounts(),
    });
    await container.start({ timeoutMs: 90000 });

    appOrigin = `http://127.0.0.1:${port}`;
    status(t.ready);
    await mainWindow.loadURL(appOrigin);
    setBootState(BOOT.READY);
    // UI 로드 이후의 컨테이너 사망 감지: ping 실패 + 컨테이너 종료가 확인되면
    // 상태 화면으로 되돌린다(handleContainerDown). 바쁜 서버(ping만 실패)는 오탐하지 않는다.
    healthMonitor?.stop();
    healthMonitor = createHealthMonitor({
      pingFn: () => ping(port),
      aliveFn: () => (container ? container.alive() : Promise.resolve(false)),
      onDown: () => {
        handleContainerDown().catch(() => {});
      },
    });
    healthMonitor.start();
  } catch (err) {
    // 기동 실패는 상태만 전이하고 기존처럼 호출자(startFailed 로그)로 던진다.
    setBootState(BOOT.FAILED_START, err.message);
    throw err;
  }
}

// UI 로드 후 컨테이너가 죽었을 때: 모니터를 멈추고 잔여물을 방어적으로 정리한 뒤
// 상태 화면으로 돌아가 failed-died로 전이한다(재시도 버튼이 뜬다).
async function handleContainerDown() {
  healthMonitor?.stop();
  healthMonitor = null;
  const current = container;
  container = null;
  appOrigin = "file://";
  await current?.stop();
  if (!mainWindow || mainWindow.isDestroyed() || shutdownPromise) return;
  await mainWindow.loadFile(path.join(here, "assets", "status.html"), {
    query: { lang, v: app.getVersion() },
  });
  setBootState(BOOT.FAILED_DIED);
  status(t.containerDied);
}

// 새 릴리스 알림: 부팅이 어느 종착지(UI 로드, Docker 안내, 실패)에 도달한 뒤에 띄워
// 이미지 풀 진행 중에 대화상자가 끼어들지 않게 한다. 실패는 전부 조용히 무시된다.
async function showUpdateDialog(info) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const { response } = await dialog.showMessageBox(mainWindow, {
    type: "info",
    title: t.updateTitle,
    message: t.updateMessage(info.current, info.latest),
    buttons: [t.updateDownload, t.updateLater],
    defaultId: 0,
    cancelId: 1,
  });
  if (response === 0) shell.openExternal(RELEASES_PAGE);
}

// 컨테이너 정리: 멱등 promise로 단일화해 종료 경합에도 정확히 1회 수행.
let shutdownPromise = null;
function shutdown() {
  if (!shutdownPromise) {
    healthMonitor?.stop();
    healthMonitor = null;
    const current = container;
    container = null;
    shutdownPromise = Promise.resolve(current?.stop());
  }
  return shutdownPromise;
}

// 단일 인스턴스 강제: 두 번째 실행은 즉시 종료한다. 두 인스턴스가 각자 컨테이너를
// 띄우면 출력 폴더를 놓고 경합하므로, 락을 못 잡으면 아무 로직도 등록하지 않는다.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  // 사용자가 앱을 또 실행하면 기존 창을 앞으로 가져온다.
  app.on("second-instance", () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });
  registerApp();
}

// 앱 수명주기 등록. 단일 인스턴스 락을 잡은 경우에만 호출된다.
function registerApp() {
  // 시작 화면의 "다시 시도" 요청. 3중 가드를 통과해야 실제로 재시도한다.
  // 1) file:// 시작 화면에서 온 요청만 — loadURL 이후에는 컨테이너 SPA에도 같은
  //    preload가 주입되므로, 원격 콘텐츠가 이 채널을 부르는 경로를 막는다.
  // 2) 실패 종착 상태에서만 — 진행 중이거나 정상이면 무시.
  // 3) 종료 절차가 시작됐으면 무시.
  ipcMain.handle("startup:retry", async (event) => {
    if (!event.senderFrame?.url?.startsWith("file://")) return { ok: false };
    if (!canRetry(bootState)) return { ok: false };
    if (shutdownPromise) return { ok: false };

    if (bootState === BOOT.FAILED_DOCKER) {
      // Docker 안내 화면에서의 재확인: 여전히 불가면 화면 전환 없이 사유만 돌려준다.
      const docker = await dockerStatus();
      if (!docker.installed || !docker.running) {
        return { ok: false, reason: !docker.installed ? "not-installed" : "not-running" };
      }
      // Docker가 살아났다: 상태 화면으로 돌아가 부팅을 재개한다(응답은 즉시 반환).
      await mainWindow.loadFile(path.join(here, "assets", "status.html"), {
        query: { lang, v: app.getVersion() },
      });
      startup().catch((err) => status(t.startFailed(err.message)));
      return { ok: true };
    }

    // failed-pull / failed-start / failed-died: 모니터를 멈추고 남은 컨테이너를
    // 방어적으로 정리한 뒤 재시도.
    healthMonitor?.stop();
    healthMonitor = null;
    await container?.stop();
    container = null;
    startup().catch((err) => status(t.startFailed(err.message)));
    return { ok: true };
  });

  // 스캔 폴더 추가/제거(웹 UI의 "디렉터리 경로" 입력에서 호출). 가드:
  // 1) 우리 출처에서 온 요청만 — 컨테이너 SPA(appOrigin) 또는 시작 화면(file://).
  // 2) 부팅 진행 중이나 종료 절차 중에는 거부(재시작 경합 방지).
  // 추가/제거 후에는 컨테이너를 재시작해야 마운트가 반영된다(진행 중 스캔도 끊긴다).
  function scanMountsAllowed(event) {
    const url = event.senderFrame?.url ?? "";
    if (!url.startsWith("file://") && !(appOrigin !== "file://" && url.startsWith(appOrigin))) {
      return false;
    }
    return !isBusy(bootState) && !shutdownPromise;
  }

  ipcMain.handle("scan-mounts:choose", async (event) => {
    if (!scanMountsAllowed(event)) return { ok: false, reason: "busy" };
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      title: t.scanMountChooseTitle,
      properties: ["openDirectory", "multiSelections"],
    });
    if (canceled || filePaths.length === 0) return { ok: false, reason: "canceled" };
    const next = addScanMounts(savedScanMounts(), filePaths);
    saveScanMounts(next);
    await restartForScanMounts();
    return { ok: true, mounts: next };
  });

  ipcMain.handle("scan-mounts:remove", async (event, hostPath) => {
    if (!scanMountsAllowed(event)) return { ok: false, reason: "busy" };
    if (typeof hostPath !== "string" || !hostPath) return { ok: false, reason: "bad-path" };
    const current = savedScanMounts();
    const next = removeScanMount(current, hostPath);
    if (next.length === current.length) return { ok: false, reason: "not-found" };
    saveScanMounts(next);
    await restartForScanMounts();
    return { ok: true, mounts: next };
  });

  app.whenReady().then(async () => {
    // 시작 화면 언어 확정: SBOM_LANG 환경변수 우선, 없으면 시스템 로캘(한국어면 ko, 아니면 en).
    lang = resolveLang(process.env.SBOM_LANG, app.getLocale());
    t = mainMessages(lang);
    // 시작 로그 파일: 실행마다 새로 쓴다. UI 전환 후 사라진 진행 내역을 문제 보고에 쓴다.
    startupLogger = createStartupLogger(path.join(app.getPath("userData"), "startup.log"));
    // macOS About 패널에 앱 이름과 버전을 표기한다(다른 OS에서는 효과가 없고 무해).
    app.setAboutPanelOptions({ applicationName: "BomLens", applicationVersion: app.getVersion() });
    app.on("web-contents-created", (_e, contents) => hardenWebContents(contents));
    // 보안: 로컬 컨테이너 출처로만 연결을 한정하는 CSP.
    session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          "Content-Security-Policy": [
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:* http://localhost:*; frame-src 'self'",
          ],
        },
      });
    });

    await createWindow();
    // 테스트 시드: 부팅 스모크는 첫 화면 렌더와 i18n만 확인하고 Docker/컨테이너 기동
    // (수 GB 이미지 풀)은 건너뛴다. SBOM_SMOKE=1이면 상태 화면에 머물러 결정론적으로 끝난다.
    if (process.env.SBOM_SMOKE === "1") {
      // 화면 시드: SBOM_SMOKE_SCREEN=docker-missing이면 Docker 안내 화면을 직접 띄워
      // 재확인 버튼과 OS별 안내 렌더를 스모크로 검증할 수 있게 한다.
      if (process.env.SBOM_SMOKE_SCREEN === "docker-missing") {
        await mainWindow.loadFile(path.join(here, "assets", "docker-missing.html"), {
          query: { reason: "not-installed", lang, platform: process.platform, v: app.getVersion() },
        });
        return;
      }
      status(t.ready);
      return;
    }
    // 업데이트 확인은 부팅과 병렬로 시작하되(비차단), 표시는 부팅 종착 이후에 한다.
    // 개발 실행에서는 꺼져 있고 SBOM_FORCE_UPDATE_CHECK=1로만 켠다(수동 검증용).
    const updatePromise =
      app.isPackaged || process.env.SBOM_FORCE_UPDATE_CHECK === "1"
        ? checkForUpdate({ currentVersion: app.getVersion() }).catch(() => null)
        : Promise.resolve(null);
    startup()
      .catch((err) => {
        status(t.startFailed(err.message));
      })
      .finally(async () => {
        const info = await updatePromise;
        if (info) await showUpdateDialog(info);
      });
  });

  app.on("window-all-closed", () => {
    shutdown().finally(() => app.quit());
  });

  // 종료 직전 로그 스트림을 닫아 버퍼를 파일로 밀어낸다. 실패는 무시된다.
  app.on("quit", () => {
    startupLogger?.close();
    startupLogger = null;
  });

  let quitting = false;
  app.on("before-quit", (event) => {
    if (quitting) return;
    event.preventDefault();
    quitting = true;
    shutdown().finally(() => app.quit());
  });
}
