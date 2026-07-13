// 추가 스캔 폴더 목록의 저장/복원(순수 — electron/fs 비의존, 단위 테스트 가능).
// userData/scan-mounts.json에 문자열 배열로 저장한다. 파일 손상이나 형식 이탈은
// 빈 목록으로 되돌린다(다음 실행이 마운트 없이 뜰 뿐이다). fs 입출력은 main.mjs가 한다.

// 마운트 수 상한: docker run 인자 폭주와 UI 선택지 과밀을 막는다. 초과분은 앞에서부터 자른다.
export const MAX_SCAN_MOUNTS = 8;

// 문자열 배열을 검증된 폴더 목록으로 정규화한다: 문자열만, 공백 제거, 중복 제거, 상한 적용.
// 개행이나 NUL이 든 경로는 SBOM_UI_SCAN_ROOTS의 줄 단위 형식을 깨뜨리므로 버린다.
function normalize(list) {
  const out = [];
  for (const entry of list ?? []) {
    if (typeof entry !== "string") continue;
    const dir = entry.trim();
    if (!dir || /[\n\r\0]/.test(dir)) continue;
    if (!out.includes(dir)) out.push(dir);
    if (out.length >= MAX_SCAN_MOUNTS) break;
  }
  return out;
}

// 파일 내용(JSON 문자열)을 검증된 폴더 경로 배열로 환원한다.
export function parseScanMounts(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  return Array.isArray(parsed) ? normalize(parsed) : [];
}

// 기존 목록에 새 폴더들을 합친다(중복 제거, 상한 유지). 반환은 새 배열.
export function addScanMounts(current, added) {
  return normalize([...(current ?? []), ...(added ?? [])]);
}

// 목록에서 폴더 하나를 뺀다. 반환은 새 배열.
export function removeScanMount(current, dir) {
  return (current ?? []).filter((d) => d !== dir);
}
