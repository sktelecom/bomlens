# BomLens 데스크톱 앱 (Electron)

콘솔 없이 더블클릭으로 BomLens 웹 UI를 여는 데스크톱 앱이다. 스캐너 자체는 여전히
Docker 컨테이너로 실행되며, 이 앱은 Docker 점검과 이미지 다운로드, 컨테이너 기동과 정리를
대신 처리한다.

> 일반 사용자는 빌드할 필요 없이 [최신 릴리스](https://github.com/sktelecom/sbom-tools/releases/latest)에서
> `SBOM-Generator-*.exe`(또는 `.dmg`)를 받아 설치하면 된다. 아직 미서명이라 Windows에서
> SmartScreen 경고가 뜨면 "추가 정보"를 누르고 "실행"을 고른다. 아래 내용은 개발자용 빌드 안내다.

## 동작 방식

1. Docker 설치와 실행 여부를 점검한다. 없으면 한국어 안내 화면을 띄운다.
2. 첫 실행이면 스캐너 이미지(`ghcr.io/sktelecom/bomlens:latest`)를 받고 진행을 표시한다.
3. `MODE=UI` 컨테이너를 띄운다. 마운트 구성은 `scripts/sbom-ui.bat`과 같다(명명 파이프와
   홈 디렉터리 아래 `sbom-output` 출력 폴더).
4. 컨테이너의 `/capabilities`가 200을 반환하면 그 localhost 주소를 창에 로드한다.
5. 앱을 닫으면 컨테이너를 정리한다.

핵심 로직은 `lib/container.mjs`(순수 Node)에 있어 electron 없이도 검증할 수 있다.

시작할 때 보이는 화면이다. 진행 상황을 로그로 보여주고, 준비가 끝나면 UI로 전환한다.

![데스크톱 앱 시작 화면](../docs/images/desktop-startup.png)

Docker가 없거나 꺼져 있으면 스캔 대신 안내 화면을 띄운다.

![Docker가 없을 때의 안내 화면](../docs/images/desktop-docker-missing.png)

## 개발

```bash
cd electron
npm install
npm start
```

Docker 엔진이 실행 중이어야 한다. 이미지를 미리 받아 두면 첫 기동이 빠르다.

```bash
docker pull ghcr.io/sktelecom/bomlens:latest
```

시작 화면 언어는 시스템 로캘을 따른다(한국어면 한국어, 아니면 영어). `SBOM_LANG=en` 또는
`SBOM_LANG=ko`로 강제할 수 있다. 웹 UI 자체 언어는 화면 우측 상단 KO/EN 토글로 바꾼다.

```bash
SBOM_LANG=en npm start
```

## 빌드 (인스톨러)

```bash
npm install
npm run dist          # 현재 OS 기본 타깃
npm run dist:win      # Windows NSIS
```

산출물은 `dist-electron/`에 생성된다. 멀티플랫폼 빌드는 CI(`.github/workflows/desktop.yml`)가
`windows-latest`와 `macos-latest`에서 수행한다. 1차 빌드는 미서명이다.

## 코드 서명

미서명 인스톨러는 Windows SmartScreen과 macOS Gatekeeper 경고를 띄운다. 서명하려면 코드
서명 인증서가 필요하다. 인증서는 유료이고 조직 신원 확인이 필요해 별도로 발급받아야 한다.

CI 워크플로우는 아래 저장소 시크릿이 설정되면 자동으로 서명하도록 배선돼 있다(시크릿이
없으면 지금처럼 미서명으로 빌드된다).

| 시크릿 | 용도 |
|--------|------|
| `CSC_LINK` | 코드 서명 인증서(base64 인코딩한 `.pfx`/`.p12`, 또는 경로) |
| `CSC_KEY_PASSWORD` | 인증서 비밀번호 |
| `APPLE_ID` | (macOS 공증) Apple ID |
| `APPLE_APP_SPECIFIC_PASSWORD` | (macOS 공증) 앱 암호 |
| `APPLE_TEAM_ID` | (macOS 공증) 팀 ID |

설정 방법:

1. Windows: Authenticode 인증서(`.pfx`)를 base64로 인코딩해 `CSC_LINK`에, 비밀번호를
   `CSC_KEY_PASSWORD`에 넣는다. 이것만으로 NSIS 인스톨러가 서명된다.
2. macOS: Developer ID 인증서를 같은 방식으로 `CSC_LINK`/`CSC_KEY_PASSWORD`에 넣고,
   `electron-builder.yml`의 `mac.identity: null`을 제거한 뒤 `APPLE_*` 시크릿으로 공증을
   설정한다.

시크릿은 저장소 Settings의 Secrets and variables에서 추가한다.
