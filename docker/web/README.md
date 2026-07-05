# 웹 UI (서버 계층)

BomLens 웹 UI의 백엔드와 프런트엔드를 다루는 기여자 문서입니다. 웹 UI를 사용만
한다면 사이트의 [웹 UI로 스캔하기](https://sktelecom.github.io/sbom-tools/) 가이드를
보세요.

웹 UI는 스캐너 이미지 안에서 `MODE=UI`로 실행됩니다. 데스크톱 앱(`electron/`)은 이
서버를 컨테이너로 띄우고 `localhost`를 BrowserWindow로 감싼 얇은 셸입니다. 즉
브라우저 UI와 데스크톱 앱은 같은 서버·같은 화면을 공유합니다.

## 구성

- `server.py` — 파이썬 표준 라이브러리만 쓰는 HTTP 서버. 빌드된 React SPA(`frontend/dist`)를
  서빙하고, `/usr/local/bin/run-scan`을 실행해 스캔을 구동합니다. 외부 의존성 없음.
- `frontend/` — React 18 + Vite + Tailwind SPA. UI 개발·테스트·디자인 토큰은
  [`frontend/README.md`](frontend/README.md)를 보세요.

## server.py 요약

주요 엔드포인트(자세한 목록은 `server.py` 상단 주석 참고):

- `GET /` — index.html (React SPA)
- `GET /capabilities` — 이 이미지에서 쓸 수 있는 입력 유형(firmware, docker) 안내
- `GET /scan-stream?...` — Server-Sent Events로 실시간 스캔 로그 + 최종 요약 전송
- `POST /upload?kind=...` — 업로드 파일 저장 후 토큰 반환
- `GET /results`, `GET /file?name=...`, `GET /download-all` — 생성된 산출물 조회·다운로드

입력 유형(`/scan-stream`의 `source` 파라미터)은 각각 스캔 MODE로 매핑됩니다.
`current-dir`, `git-url`, `zip-upload`은 SOURCE, `rootfs-dir`은 ROOTFS,
`sbom-upload`은 ANALYZE, `docker-image`은 IMAGE로 이어집니다. `firmware-upload`은
FIRMWARE(unblob 포함 이미지 한정), `ai-model`은 AIBOM(bomlens-aibom 이미지 한정)입니다.

설계 원칙: 스캔 실행 경로(`SBOM_RUN_SCAN`)와 이미지 이름 같은 값은 서버 환경변수로만
정해지고 요청 입력에서 파생되지 않습니다. 파일 서빙은 경로 탐색(path traversal)을
막습니다.

## 로컬 실행과 테스트

- 소스 트리로 웹 UI 띄우기: 저장소 루트에서 `./scripts/scan-sbom.sh --ui` 실행.
  최신 `server.py`와 새로 빌드한 프런트가 이미지 위에 마운트됩니다.
- 계약 테스트(Docker 없이): `tests/test-web-ui.sh`가 `SBOM_RUN_SCAN`에 스텁 스캐너를
  꽂아 `/scan-stream` SSE 프로토콜과 JSON 계약을 검증합니다. 엔드포인트나 응답
  형태를 바꾸면 이 테스트도 함께 갱신합니다.
- 프런트가 소비하는 JSON 계약은 `frontend/src/lib/api.ts`가 `server.py`를 미러링합니다.
  서버 응답을 바꾸면 양쪽을 함께 맞춥니다.

이미지 빌드·배포 전반은 상위 [`docker/README.md`](../README.md)를 보세요.
