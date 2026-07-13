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
  // 스캔 폴더 추가/제거(SPA의 "디렉터리 경로" 입력에서 사용). 폴더 선택과 목록
  // 저장, 컨테이너 재시작은 main이 수행하고 검증한다. 성공하면 앱이 상태 화면을
  // 거쳐 UI를 다시 로드하므로, 렌더러는 응답 후 상태를 정리할 필요가 없다.
  chooseScanFolder: () => ipcRenderer.invoke("scan-mounts:choose"),
  removeScanFolder: (hostPath) => ipcRenderer.invoke("scan-mounts:remove", hostPath),
});
