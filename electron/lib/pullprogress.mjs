// docker pull 출력 해석(순수 — electron 비의존, 단위 테스트 가능).
//
// 왜 필요한가: 이미지를 받는 동안 상태 화면에는 raw 출력만 흐른다. non-TTY docker pull은
// 레이어 하나당 상태 줄 하나만 뱉으므로 몇 분씩 화면이 멎어 보이고, 참가자는 앱이 죽은 줄 안다.
//
// 중요한 제약: non-TTY에서는 **바이트 수와 진행바가 아예 나오지 않는다**(진행바는 TTY 전용).
// 실제 출력은 아래 형태뿐이라, 퍼센트/ETA는 만들어낼 수 없고 레이어 개수가 유일하게 정직한 단위다.
//
//   3.19: Pulling from library/alpine
//   17a39c0ba978: Pulling fs layer
//   17a39c0ba978: Download complete
//   ef1614f30685: Download complete        <- "Pulling fs layer" 없이 등장하기도 한다
//   17a39c0ba978: Pull complete
//   Digest: sha256:...
//   Status: Downloaded newer image for alpine:3.19
//
// 그래서 총 레이어 수는 "Pulling fs layer" 줄이 아니라 **등장한 모든 레이어 ID**로 센다.
// docker가 일부 레이어의 "Pull complete"를 생략하기도 하므로 완료 수는 끝까지 총계에 못 미칠 수
// 있다 — 진행 표시로는 충분하고(멈춘 게 아님을 보이는 것이 목적), 완료 판정은 pull의 종료코드가 한다.

const LAYER_LINE = /^([0-9a-f]{6,}):\s+(.+?)\s*$/;
const DONE_STATUSES = new Set(["Pull complete", "Already exists"]);

function snapshot(layers) {
  let complete = 0;
  for (const status of layers.values()) if (DONE_STATUSES.has(status)) complete += 1;
  return { total: layers.size, complete };
}

// 레이어 상태를 누적하는 집계기. feed()는 집계가 실제로 바뀌었을 때만 값을 돌려주므로
// (아니면 null) 호출부가 매 줄마다 렌더하지 않아도 된다.
export function createPullProgress() {
  const layers = new Map();
  let last = "";
  return {
    feed(line) {
      const m = LAYER_LINE.exec(String(line));
      if (!m) return null;
      const [, id, rawStatus] = m;
      // TTY 진행바가 섞여 들어오는 환경(사용자가 콘솔에서 돌린 로그를 붙여넣는 등)에 대비해
      // "Downloading [===>   ] 12MB/120MB"의 꼬리를 떼어 상태 이름만 남긴다.
      const status = rawStatus.replace(/\s*\[.*$/, "").trim();
      layers.set(id, status);
      const snap = snapshot(layers);
      const key = `${snap.complete}/${snap.total}`;
      if (key === last) return null;
      last = key;
      return snap;
    },
    snapshot: () => snapshot(layers),
  };
}

// pull 실패 원인 분류. 문구가 아니라 키를 돌려주고 번역은 i18n이 맡는다.
// reason === "timeout"이면 출력 내용과 무관하게 정체로 끊긴 것이다.
// 순서가 중요하다: 디스크·DNS처럼 특정적인 신호를 프록시/인증보다 먼저 본다
// (프록시 MITM은 x509, 사내 프록시 거부는 403/proxyconnect로 나타난다).
export function classifyPullFailure(logTail = "", reason = "exit") {
  if (reason === "timeout") return "timeout";
  const s = String(logTail);
  if (/no space left on device|disk quota exceeded/i.test(s)) return "disk";
  if (/no such host|dial tcp: lookup|name resolution|Temporary failure in name resolution/i.test(s))
    return "dns";
  if (
    /proxyconnect|x509|certificate signed by unknown authority|certificate is not trusted|\b403\b|Forbidden|tls: (?:bad|failed)/i.test(
      s,
    )
  )
    return "proxy";
  if (/unauthorized|authentication required|pull access denied|denied:/i.test(s)) return "auth";
  return "unknown";
}
