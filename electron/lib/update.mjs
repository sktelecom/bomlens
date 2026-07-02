// 시작 시 새 릴리스 확인(순수 Node — electron 비의존, 단위 테스트 가능).
// 업데이트 알림은 부가 기능이므로 네트워크 오류, rate limit, 응답 이상은 전부
// 조용히 무시하고 null을 돌려준다. 부팅을 막거나 오류 화면을 띄우지 않는다.

export const RELEASES_API =
  "https://api.github.com/repos/sktelecom/sbom-tools/releases/latest";
export const RELEASES_PAGE =
  "https://github.com/sktelecom/sbom-tools/releases/latest";

// "v1.5.5"나 "1.5.5-rc.1" 같은 문자열에서 숫자 세 자리만 뽑는다.
// 프리릴리스 접미사는 비교에서 무시한다(/releases/latest는 어차피 정식 릴리스만 준다).
export function parseVersion(str) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(str ?? "").trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

// 어느 쪽이든 파싱에 실패하면 false — 확신이 없으면 알리지 않는다.
export function isNewerVersion(latest, current) {
  const a = parseVersion(latest);
  const b = parseVersion(current);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return false;
}

// /releases/latest 응답에서 알림에 필요한 정보만 추린다. draft/prerelease는
// API가 원래 제외하지만 방어적으로 한 번 더 거른다.
export function releaseUpdateInfo(release, currentVersion) {
  if (!release || release.draft || release.prerelease) return null;
  if (!parseVersion(release.tag_name)) return null;
  const latest = String(release.tag_name).trim().replace(/^v/, "");
  if (!isNewerVersion(latest, currentVersion)) return null;
  return { latest, current: String(currentVersion) };
}

// GitHub API로 최신 릴리스를 확인한다. User-Agent는 필수 — 없으면 GitHub이 403을 준다.
// fetchImpl 주입으로 네트워크 없이 테스트한다.
export async function checkForUpdate({
  currentVersion,
  fetchImpl = fetch,
  timeoutMs = 5000,
} = {}) {
  try {
    const res = await fetchImpl(RELEASES_API, {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "BomLens-desktop",
      },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res || res.status !== 200) return null;
    return releaseUpdateInfo(await res.json(), currentVersion);
  } catch {
    return null;
  }
}
