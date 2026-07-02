# BomLens 데스크톱 앱 (Electron)

콘솔 없이 더블클릭으로 BomLens 웹 UI를 여는 데스크톱 앱이다. 스캐너 자체는 여전히
Docker 컨테이너로 실행되며, 이 앱은 Docker 점검과 이미지 다운로드, 컨테이너 기동과 정리를
대신 처리한다.

> 일반 사용자는 빌드할 필요 없이 [최신 릴리스](https://github.com/sktelecom/sbom-tools/releases/latest)에서
> `BomLens-Setup.exe`(또는 `.dmg`)를 받아 설치하면 된다. 아직 미서명이라 Windows에서
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
앱은 단일 인스턴스만 허용하므로, 앱을 켜 둔 채 스모크 테스트(`npm run test:smoke`)를
돌리면 락 때문에 실패한다. 먼저 앱을 닫고 실행한다.

```bash
docker pull ghcr.io/sktelecom/bomlens:latest
```

시작 화면 언어는 시스템 로캘을 따른다(한국어면 한국어, 아니면 영어). `SBOM_LANG=en` 또는
`SBOM_LANG=ko`로 강제할 수 있다. 웹 UI 자체 언어는 화면 우측 상단 KO/EN 토글로 바꾼다.

```bash
SBOM_LANG=en npm start
```

앱은 시작할 때 GitHub 최신 릴리스를 확인해 새 버전이 있으면 다운로드 안내 대화상자를
띄운다(`lib/update.mjs`). 실패는 조용히 무시되어 부팅에 영향을 주지 않는다. 개발
실행(`npm start`)에서는 꺼져 있고, `SBOM_FORCE_UPDATE_CHECK=1`로 켜서 확인할 수 있다.

## 빌드 (인스톨러)

```bash
npm install
npm run dist          # 현재 OS 기본 타깃
npm run dist:win      # Windows NSIS
```

산출물은 `dist-electron/`에 생성된다. 멀티플랫폼 빌드는 CI(`.github/workflows/desktop.yml`)가
`windows-latest`와 `macos-latest`에서 수행한다. 1차 빌드는 미서명이다.

## 코드 서명

미서명 인스톨러는 Windows SmartScreen과 macOS Gatekeeper 경고를 띄운다. CI 워크플로우는
아래 저장소 시크릿이 설정되면 자동으로 서명하고 공증하도록 배선돼 있다. 시크릿이 없으면
지금처럼 미서명으로 빌드된다. 별도의 설정 파일 수정은 필요 없다.

Windows와 macOS 인증서는 반드시 서로 다른 시크릿에 넣는다. 범용 `CSC_LINK`는 macOS
빌드도 읽기 때문에, Windows용 `.pfx`를 거기 넣으면 macos 러너가 Apple 인증서로 임포트를
시도해 빌드가 실패한다.

| 시크릿 | 용도 |
|--------|------|
| `WIN_CSC_LINK` | Windows Authenticode 인증서(base64 인코딩한 `.pfx`) |
| `WIN_CSC_KEY_PASSWORD` | Windows 인증서 비밀번호 |
| `CSC_LINK` | macOS Developer ID Application 인증서(base64 인코딩한 `.p12`) |
| `CSC_KEY_PASSWORD` | macOS 인증서 비밀번호 |
| `APPLE_ID` | macOS 공증에 쓸 Apple ID |
| `APPLE_APP_SPECIFIC_PASSWORD` | 위 Apple ID의 앱 암호(appleid.apple.com에서 발급) |
| `APPLE_TEAM_ID` | Apple Developer 팀 ID(멤버십 페이지) |

`APPLE_*` 3종은 전부 넣거나 전부 뺀다. 일부만 설정하면 electron-builder가 설정 오류로
빌드를 실패시킨다. 3종이 모두 없으면 공증만 건너뛰고 서명은 진행된다(공증 자체는 서명이
성공한 빌드에서만 시도된다). 시크릿은 저장소 Settings의 Secrets and variables에서 추가한다.

### 인증서 발급 절차 (사람이 진행)

macOS부터. Apple Developer Program 가입이 필요하다(연 99달러).

1. 가입 주체를 정한다. 조직 가입(SK Telecom)은 D-U-N-S 번호와 법인 검증이 필요해 수일에서
   수주가 걸리지만 Gatekeeper에 회사 이름이 표기된다. 개인 가입은 빠르지만 개인 이름이
   표기되어 조직 배포에 어울리지 않는다. 조직 가입을 권장한다.
2. Account Holder 권한으로 Developer ID Application 인증서를 발급하고 키체인에서 `.p12`로
   내보낸 뒤 base64로 인코딩해 `CSC_LINK`에, 비밀번호를 `CSC_KEY_PASSWORD`에 넣는다.
3. appleid.apple.com에서 앱 암호를 발급해(2단계 인증 필요) `APPLE_ID`,
   `APPLE_APP_SPECIFIC_PASSWORD`에 넣고, 멤버십 페이지의 팀 ID를 `APPLE_TEAM_ID`에 넣는다.

Windows는 두 경로 중에서 고른다.

- Azure Trusted Signing(권장): 월 10달러 수준으로 저렴하고 파일 인증서가 필요 없다. Azure
  구독과 3년 이상 조직 이력 검증이 필요하다. electron-builder 26이 기본 지원하지만
  `azureSignOptions`를 설정 파일에 상주시킬 수 없어(있으면 무조건 Azure 경로로 감), 채택이
  결정되면 워크플로우에서 조건 주입하는 후속 변경이 필요하다.
- OV Authenticode: 연 200~500달러. 2023년 6월부터 개인키의 HSM 보관이 강제되어 파일
  `.pfx` 발급이 사실상 막혔으므로, CI에서 쓰려면 DigiCert KeyLocker 같은 클라우드 HSM
  상품이 필요하다. 발급받으면 `WIN_CSC_LINK`/`WIN_CSC_KEY_PASSWORD`에 넣는다.

어느 경로든 SmartScreen 평판은 서명 후에도 다운로드가 쌓여야 해소된다(EV 인증서만 즉시
확보).

### 서명 확인 (첫 서명 릴리스 후)

```bash
# macOS
codesign -dv --verbose BomLens.app
spctl -a -t open --context context:primary-signature BomLens-Setup.dmg
xcrun stapler validate BomLens-Setup.dmg
```

```powershell
# Windows
Get-AuthenticodeSignature BomLens-Setup.exe
```

서명이 자리 잡으면 후속으로 검토할 것: 사용자 문서의 Gatekeeper 우회 안내
(`docs/start/no-cli.md`) 축소, 그리고 electron-updater 기반 완전 자동 업데이트 도입
(macOS 자동 업데이트는 서명된 앱에서만 동작하므로 서명이 선결 조건이다).
