// 부팅 상태 기계(순수 — electron 비의존, 단위 테스트 가능).
//
// main.mjs의 startup()은 원래 1회용이었다. 재시도(다시 시도 버튼)와 컨테이너 사망 감지를
// 얹으려면 "지금 부팅이 어디까지 갔는가"를 한 곳에서 추적해야 해서, 상태 상수와 판정
// 함수를 여기로 분리한다. 상태 전이 자체는 main.mjs가 수행한다.

export const BOOT = {
  IDLE: "idle", // 아직 startup()이 시작되지 않음
  CHECKING: "checking", // Docker 설치/실행 점검 중
  PULLING: "pulling", // 스캐너 이미지 다운로드 중
  STARTING: "starting", // UI 컨테이너 기동/헬스 대기 중
  READY: "ready", // 컨테이너 UI 로드 완료
  FAILED_DOCKER: "failed-docker", // Docker 미설치 또는 엔진 미실행
  FAILED_PULL: "failed-pull", // 이미지 다운로드 실패
  FAILED_START: "failed-start", // 컨테이너 기동 실패
  FAILED_DIED: "failed-died", // UI 로드 후 컨테이너가 죽음
};

// 재시도 가능 여부: 실패 종착 상태에서만 true. 진행 중이거나 정상이면 재시도가 의미 없다.
export function canRetry(state) {
  return typeof state === "string" && state.startsWith("failed-");
}

// 부팅 진행 중 여부: startup() 중복 진입을 막는 가드에 쓴다.
export function isBusy(state) {
  return state === BOOT.CHECKING || state === BOOT.PULLING || state === BOOT.STARTING;
}
