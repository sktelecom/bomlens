// 데스크톱 시작 화면 문자열의 한국어/영어 사전과 로캘 선택(순수 — electron 비의존, 단위 테스트 가능).
// 웹 UI(docker/web/frontend, i18next)와 동일한 원칙: 로캘이 ko로 시작하면 한국어, 아니면 영어 폴백.
// 전역 확장에 맞춰 비한국어 환경에서는 영어로 뜨고, 한국 사용자는 기존 경험을 그대로 유지한다.

export const SUPPORTED = ["en", "ko"];

// app.getLocale()이나 navigator.language 같은 BCP 47 문자열을 받아 지원 언어로 환원한다.
export function pickLang(locale = "en") {
  return String(locale).toLowerCase().startsWith("ko") ? "ko" : "en";
}

// 언어 결정: SBOM_LANG 환경변수가 있으면 우선(사용자가 언어를 강제하거나 스크린샷을 찍을 때),
// 없으면 시스템 로캘. 둘 다 지원 언어로 환원한다.
export function resolveLang(envLang, sysLocale) {
  return pickLang(envLang || sysLocale || "en");
}

// 메인 프로세스(main.mjs)가 status()로 흘리는 문구. 일부는 값이 끼어들어 함수로 둔다.
const MAIN = {
  ko: {
    dockerChecking: "Docker 상태를 확인하는 중...",
    firstPull: "처음 실행이라 스캐너 이미지를 내려받습니다 (약 3~4GB).",
    image: (img) => `이미지: ${img}`,
    network: "네트워크 상황에 따라 수 분 걸릴 수 있어요...",
    pullFailed: "이미지 다운로드에 실패했습니다. 인터넷 연결을 확인하고 앱을 다시 실행하세요.",
    cleanedOrphans: (n) => `이전 실행에서 남은 컨테이너 ${n}개를 정리했습니다.`,
    startingUi: "UI 컨테이너를 시작하는 중...",
    ready: "준비 완료. UI를 엽니다.",
    startFailed: (msg) => `시작에 실패했습니다: ${msg}`,
    containerDied: "UI 컨테이너가 종료되었습니다. 다시 시도를 눌러 재시작하세요.",
    updateTitle: "업데이트 알림",
    updateMessage: (current, latest) =>
      `새 버전(v${latest})이 나왔습니다. 현재 버전은 v${current}입니다.`,
    updateDownload: "다운로드 페이지 열기",
    updateLater: "나중에",
    scanMountChooseTitle: "스캔할 폴더 선택",
  },
  en: {
    dockerChecking: "Checking Docker status...",
    firstPull: "First run: downloading the scanner image (about 3-4 GB).",
    image: (img) => `Image: ${img}`,
    network: "This can take a few minutes depending on your network...",
    pullFailed: "Image download failed. Check your internet connection and restart the app.",
    cleanedOrphans: (n) =>
      n === 1
        ? "Cleaned up 1 leftover container from a previous run."
        : `Cleaned up ${n} leftover containers from a previous run.`,
    startingUi: "Starting the UI container...",
    ready: "Ready. Opening the UI.",
    startFailed: (msg) => `Startup failed: ${msg}`,
    containerDied: "The UI container stopped. Press Try again to restart it.",
    updateTitle: "Update available",
    updateMessage: (current, latest) =>
      `A new version (v${latest}) is available. You are on v${current}.`,
    updateDownload: "Open download page",
    updateLater: "Later",
    scanMountChooseTitle: "Choose folders to scan",
  },
};

// 메인 프로세스 문구 묶음을 로캘에 맞춰 돌려준다.
export function mainMessages(locale) {
  return MAIN[pickLang(locale)];
}
