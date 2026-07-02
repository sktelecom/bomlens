// 렌더러에 안전한 브리지만 노출(contextIsolation). 시작 단계의 상태 로그와 부팅 상태를
// 받고, 실패 상태에서만 재시도를 요청할 수 있다. loadURL 이후에는 컨테이너 SPA에도 같은
// preload가 주입되므로, 여기에는 시작 화면에 필요한 최소 채널만 둔다(재시도는 main이 검증).
import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("sbomDesktop", {
  onStatus: (cb) => {
    if (typeof cb !== "function") return;
    ipcRenderer.on("status", (_event, line) => cb(line));
  },
  onStartupState: (cb) => {
    if (typeof cb !== "function") return;
    ipcRenderer.on("startup-state", (_event, payload) => cb(payload));
  },
  retryStartup: () => ipcRenderer.invoke("startup:retry"),
});
