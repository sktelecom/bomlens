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
import { mainMessages, resolveLang } from "./lib/i18n.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

let container = null;
let mainWindow = null;
let appOrigin = "file://";
// 시작 화면 언어: app.getLocale()로 결정(앱 준비 이후에 확정). 그 전 안전한 기본은 영어.
let lang = "en";
let t = mainMessages("en");

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
    backgroundColor: "#0a0a0c",
    title: "SBOM Generator",
    webPreferences: {
      preload: path.join(here, "preload.mjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false, // ESM preload 사용
    },
  });
  await mainWindow.loadFile(path.join(here, "assets", "status.html"), {
    query: { lang },
  });
}

async function startup() {
  status(t.dockerChecking);
  const docker = await dockerStatus();
  if (!docker.installed || !docker.running) {
    appOrigin = "file://";
    const reason = !docker.installed ? "not-installed" : "not-running";
    await mainWindow.loadFile(path.join(here, "assets", "docker-missing.html"), {
      query: { reason, lang },
    });
    return;
  }

  if (!(await imagePresent(DEFAULT_IMAGE))) {
    status(t.firstPull);
    status(t.image(DEFAULT_IMAGE));
    status(t.network);
    const ok = await pullImage(DEFAULT_IMAGE, (line) => status(line));
    if (!ok) {
      status(t.pullFailed);
      return;
    }
  }

  status(t.startingUi);
  const port = await findFreePort();
  container = new UiContainer({ image: DEFAULT_IMAGE, hostPort: port });
  await container.start({ timeoutMs: 90000 });

  appOrigin = `http://127.0.0.1:${port}`;
  status(t.ready);
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
  // 시작 화면 언어 확정: SBOM_LANG 환경변수 우선, 없으면 시스템 로캘(한국어면 ko, 아니면 en).
  lang = resolveLang(process.env.SBOM_LANG, app.getLocale());
  t = mainMessages(lang);
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
    status(t.ready);
    return;
  }
  startup().catch((err) => {
    status(t.startFailed(err.message));
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
