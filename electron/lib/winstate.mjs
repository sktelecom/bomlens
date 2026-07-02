// 창 위치/크기 기억(순수 — electron 비의존, 단위 테스트 가능).
//
// userData/window-state.json에 저장된 창 상태를 다음 실행에서 복원할 때 쓴다.
// 파일 손상(손으로 고치다 깨짐, 디스크 오류)과 모니터 구성 변화(외장 모니터 제거 등)로
// 창이 화면 밖에 뜨는 사고를 여기서 막는다. 파일 입출력은 main.mjs가 수행한다.

// 저장 파일 파싱: JSON 파싱 + 스키마({x,y,width,height:number, maximized:boolean}) 검증.
// 하나라도 어긋나면 null을 반환한다(호출자는 기본값으로 뜬다).
export function parseWindowState(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) return null;
  for (const key of ["x", "y", "width", "height"]) {
    if (typeof data[key] !== "number" || !Number.isFinite(data[key])) return null;
  }
  if (typeof data.maximized !== "boolean") return null;
  const { x, y, width, height, maximized } = data;
  return { x, y, width, height, maximized };
}

// 복원한 창을 사용자가 잡을 수 있는 최소 노출 크기. 어느 모니터와도 이만큼 겹치지
// 않으면 저장된 위치를 버린다.
const MIN_VISIBLE_WIDTH = 100;
const MIN_VISIBLE_HEIGHT = 80;

// 저장된 창 영역이 지금 모니터 구성에서 보이는지 검사한다. workAreas는
// {x,y,width,height} 배열(screen.getAllDisplays()의 workArea). 어느 workArea와의
// 교집합이 최소 100×80 이상이면 저장된 영역을 그대로 쓰고, 아니면 defaults를 반환한다.
export function sanitizeBounds(state, workAreas, defaults) {
  if (!state || !Array.isArray(workAreas)) return defaults;
  for (const area of workAreas) {
    const overlapWidth =
      Math.min(state.x + state.width, area.x + area.width) - Math.max(state.x, area.x);
    const overlapHeight =
      Math.min(state.y + state.height, area.y + area.height) - Math.max(state.y, area.y);
    if (overlapWidth >= MIN_VISIBLE_WIDTH && overlapHeight >= MIN_VISIBLE_HEIGHT) {
      return { x: state.x, y: state.y, width: state.width, height: state.height };
    }
  }
  return defaults;
}
