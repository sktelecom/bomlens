// 렌더러에 안전한 브리지만 노출(contextIsolation). 시작 단계의 상태 로그를 받는다.
import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("sbomDesktop", {
  onStatus: (cb) => {
    if (typeof cb !== "function") return;
    ipcRenderer.on("status", (_event, line) => cb(line));
  },
});
