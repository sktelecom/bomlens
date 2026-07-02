// 시작 로그(순수 — electron 비의존, 단위 테스트 가능).
//
// 상태 화면의 진행 로그는 UI로 전환되면 사라진다. 부팅이 이상하게 끝났을 때 사용자에게
// 받을 수 있는 흔적으로, 같은 내용을 userData/startup.log 파일에도 남긴다.
// 로깅이 부팅을 방해하면 안 되므로 모든 파일 오류는 조용히 무시한다.
import fs from "node:fs";

// 로그 한 줄 형식: ISO 타임스탬프 프리픽스와 본문.
// 예) 2026-07-02T04:00:00.000Z Checking Docker...
export function formatLogLine(date, text) {
  return `${date.toISOString()} ${text}\n`;
}

// 실행마다 파일을 새로 쓰는('w' 플래그) 로거를 만든다. line(text)은 타임스탬프를 붙여
// 한 줄을 덧붙이고, close()는 스트림을 닫는다(쓰기 완료를 기다리는 promise 반환).
// 파일을 못 만들거나 쓰기가 실패해도 예외를 내지 않는다.
export function createStartupLogger(filePath) {
  let stream = null;
  try {
    stream = fs.createWriteStream(filePath, { flags: "w" });
    // 쓰기 오류(디스크 가득 참, 권한 등)가 나면 그 뒤로는 조용히 로깅을 포기한다.
    stream.on("error", () => {
      stream = null;
    });
  } catch {
    stream = null;
  }
  return {
    line(text) {
      try {
        stream?.write(formatLogLine(new Date(), text));
      } catch {
        // 로깅 실패는 무시한다.
      }
    },
    close() {
      const current = stream;
      stream = null;
      if (!current) return Promise.resolve();
      return new Promise((resolve) => {
        try {
          current.end(() => resolve());
        } catch {
          resolve();
        }
      });
    },
  };
}
