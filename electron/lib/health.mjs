// UI 컨테이너 사망 감지 헬스 모니터(순수 — electron/docker 비의존, 단위 테스트 가능).
//
// UI 로드 이후에도 컨테이너는 밖에서 죽을 수 있다(docker stop, 엔진 재시작, OOM 등).
// 주기적으로 ping(HTTP /capabilities)을 보내고, 실패하면 컨테이너 생존 여부(aliveFn)로
// 확정한다. 규칙:
// - ping 성공 → 실패 카운터 리셋.
// - ping 실패 → aliveFn 확인. 컨테이너가 죽었으면(false) 즉시 onDown.
//   살아 있으면(true) 카운터만 올린다 — failThreshold에 도달해도 onDown을 부르지 않는다.
//   무거운 스캔으로 응답이 늦는 서버를 죽음으로 오탐하지 않기 위해서다.
// - onDown은 정확히 1회만 호출되고, 호출 전에 모니터가 스스로 멈춘다.
export function createHealthMonitor({
  pingFn,
  aliveFn,
  intervalMs = 15000,
  timeoutMs = 10000,
  failThreshold = 4,
  onDown,
}) {
  let timer = null;
  let stopped = true;
  let downFired = false;
  let failures = 0;
  let checking = false;

  // ping이 매달리는 경우(응답도 오류도 없음)를 timeoutMs로 잘라 실패로 본다.
  function pingWithTimeout() {
    return new Promise((resolve) => {
      const cutoff = setTimeout(() => resolve(false), timeoutMs);
      cutoff.unref?.();
      Promise.resolve()
        .then(pingFn)
        .then(
          (ok) => {
            clearTimeout(cutoff);
            resolve(Boolean(ok));
          },
          () => {
            clearTimeout(cutoff);
            resolve(false);
          },
        );
    });
  }

  async function check() {
    // 이전 점검이 아직 진행 중이면(느린 ping) 이번 틱은 건너뛴다.
    if (stopped || checking) return;
    checking = true;
    try {
      const up = await pingWithTimeout();
      if (stopped) return;
      if (up) {
        failures = 0;
        return;
      }
      // 카운터는 failThreshold에서 상한을 둔다(진단용 — onDown 판정에는 쓰지 않는다).
      failures = Math.min(failures + 1, failThreshold);
      const alive = await Promise.resolve()
        .then(aliveFn)
        .catch(() => false);
      if (stopped) return;
      if (!alive && !downFired) {
        downFired = true;
        stop();
        onDown();
      }
    } finally {
      checking = false;
    }
  }

  function start() {
    if (timer || downFired) return;
    stopped = false;
    failures = 0;
    timer = setInterval(check, intervalMs);
    timer.unref?.();
  }

  function stop() {
    stopped = true;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return { start, stop };
}
