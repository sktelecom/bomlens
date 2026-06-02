# SBOM Generator 데스크톱 앱 (Electron)

콘솔 없이 더블클릭으로 SBOM Generator 웹 UI를 여는 데스크톱 앱이다. 스캐너 자체는 여전히
Docker 컨테이너로 실행되며, 이 앱은 Docker 점검과 이미지 다운로드, 컨테이너 기동과 정리를
대신 처리한다. 설계 배경은 [데스크톱 앱 검토 보고서](../docs/desktop-app-study.md)를 참고한다.

> 일반 사용자는 빌드할 필요 없이 [최신 릴리스](https://github.com/sktelecom/sbom-tools/releases/latest)에서
> `SBOM-Generator-*.exe`(또는 `.dmg`)를 받아 설치하면 된다. 아직 미서명이라 Windows에서
> SmartScreen 경고가 뜨면 "추가 정보"를 누르고 "실행"을 고른다. 아래 내용은 개발자용 빌드 안내다.

## 동작 방식

1. Docker 설치와 실행 여부를 점검한다. 없으면 한국어 안내 화면을 띄운다.
2. 첫 실행이면 스캐너 이미지(`ghcr.io/sktelecom/sbom-generator:latest`)를 받고 진행을 표시한다.
3. `MODE=UI` 컨테이너를 띄운다. 마운트 구성은 `scripts/sbom-ui.bat`과 같다(명명 파이프와
   홈 디렉터리 아래 `sbom-output` 출력 폴더).
4. 컨테이너의 `/capabilities`가 200을 반환하면 그 localhost 주소를 창에 로드한다.
5. 앱을 닫으면 컨테이너를 정리한다.

핵심 로직은 `lib/container.mjs`(순수 Node)에 있어 electron 없이도 검증할 수 있다.

## 개발

```bash
cd electron
npm install
npm start
```

Docker 엔진이 실행 중이어야 한다. 이미지를 미리 받아 두면 첫 기동이 빠르다.

```bash
docker pull ghcr.io/sktelecom/sbom-generator:latest
```

## 빌드 (인스톨러)

```bash
npm install
npm run dist          # 현재 OS 기본 타깃
npm run dist:win      # Windows NSIS
```

산출물은 `dist-electron/`에 생성된다. 멀티플랫폼 빌드는 CI(`.github/workflows/desktop.yml`)가
`windows-latest`와 `macos-latest`에서 수행한다. 1차 빌드는 미서명이다.
