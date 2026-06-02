// Electron 메인 프로세스: Docker 점검 → 이미지 프리풀 → MODE=UI 컨테이너 기동 →
// 헬스 폴링 → 컨테이너가 서빙하는 UI 로드 → 종료 시 컨테이너 정리.
//
// onot의 main.mjs를 본떴으나, 파이썬 사이드카 대신 Docker 컨테이너를 띄운다(lib/container.mjs).
// 백엔드와 React SPA가 이미 스캐너 이미지 안에 있으므로 BrowserWindow는 localhost를 로드한다.
import { app, BrowserWindow, session, shell } from "electron";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_IMAGE,
  dockerStatus,
  findFreePort,
  imagePresent,
  pullImage,
  UiContainer,
} from "./lib/container.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

let container = null;
let mainWindow = null;
let appOrigin = "file://";

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

function status(line) {
  send("status", line);
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

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 860,
    backgroundColor: "#0a0a0b",
    title: "SBOM Generator",
    webPreferences: {
      preload: path.join(here, "preload.mjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false, // ESM preload 사용
    },
  });
  await mainWindow.loadFile(path.join(here, "assets", "status.html"));
}

async function startup() {
  status("Docker 상태를 확인하는 중...");
  const docker = await dockerStatus();
  if (!docker.installed || !docker.running) {
    appOrigin = "file://";
    const reason = !docker.installed ? "not-installed" : "not-running";
    await mainWindow.loadFile(path.join(here, "assets", "docker-missing.html"), {
      query: { reason },
    });
    return;
  }

  if (!(await imagePresent(DEFAULT_IMAGE))) {
    status(`처음 실행이라 스캐너 이미지를 내려받습니다 (약 3~4GB).`);
    status(`이미지: ${DEFAULT_IMAGE}`);
    status(`네트워크 상황에 따라 수 분 걸릴 수 있어요...`);
    const ok = await pullImage(DEFAULT_IMAGE, (line) => status(line));
    if (!ok) {
      status("이미지 다운로드에 실패했습니다. 인터넷 연결을 확인하고 앱을 다시 실행하세요.");
      return;
    }
  }

  status("UI 컨테이너를 시작하는 중...");
  const port = await findFreePort();
  container = new UiContainer({ image: DEFAULT_IMAGE, hostPort: port });
  await container.start({ timeoutMs: 90000 });

  appOrigin = `http://127.0.0.1:${port}`;
  status("준비 완료. UI를 엽니다.");
  await mainWindow.loadURL(appOrigin);
}

// 컨테이너 정리: 멱등 promise로 단일화해 종료 경합에도 정확히 1회 수행.
let shutdownPromise = null;
function shutdown() {
  if (!shutdownPromise) {
    const current = container;
    container = null;
    shutdownPromise = Promise.resolve(current?.stop());
  }
  return shutdownPromise;
}

app.whenReady().then(async () => {
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
  startup().catch((err) => {
    status(`시작에 실패했습니다: ${err.message}`);
  });
});

app.on("window-all-closed", () => {
  shutdown().finally(() => app.quit());
});

let quitting = false;
app.on("before-quit", (event) => {
  if (quitting) return;
  event.preventDefault();
  quitting = true;
  shutdown().finally(() => app.quit());
});
