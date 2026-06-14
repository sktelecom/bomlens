# 영어 스크린샷 캡처 지시문 (Windows)

이 파일은 실제 Windows PC에서 터미널 코딩 에이전트를 열고 그대로 시키는 지시문이다. 저장소를 클론하면
이 파일이 함께 오므로, 에이전트에게 "tests/en-screenshots-prompt.md 대로 진행해"라고 하면 된다.

## 미션

메인 `README.md`는 본문이 영어다. 거기에 박힌 화면 캡처 3장을 영어 UI로 찍어 `docs/images`에
넣고, README가 그 영어 파일을 가리키도록 한 PR을 마무리한다. README 본문 영문화와 이미지 참조
교체는 이미 `docs/readme-english` 브랜치에 들어가 있으므로, 이 브랜치에 캡처만 추가하면 된다.

GUI 조작(앱 실행·토글·화면 띄우기)은 사람이, 캡처와 파일 배치와 커밋과 PR은 에이전트가 맡는다.

## 캡처할 3장

기존 한글 캡처와 같은 화면·테마·창 너비로 찍어 README 안에서 톤이 튀지 않게 한다.

| 저장 경로 | 대응 한글 원본 | 화면 |
|-----------|----------------|------|
| `docs/images/web-ui-en.png` | `web-ui.png` | 웹 UI 초기 설정 화면(프로젝트 이름·스캔 대상·생성 옵션, 우측 빈 로그 패널) |
| `docs/images/web-ui-scan-en.png` | `web-ui-scan.png` | 스캔 진행 중, 우측에 실시간 로그가 흐르는 상태 |
| `docs/images/desktop-startup-en.png` | `desktop-startup.png` | 데스크톱 앱 시작 화면(Docker 점검·이미지 다운로드·컨테이너 시작 로그) |

한글 원본 3장(`web-ui.png` 등)은 한국어 문서들이 참조하므로 **덮어쓰지 않는다.** 새 `-en.png`만
추가한다.

## 사전 준비

- 터미널 코딩 에이전트, `git`, GitHub CLI(`gh auth login` 완료)
- Docker 엔진([Rancher Desktop](https://rancherdesktop.io/) 권장) 실행
- 저장소 클론 후 작업 브랜치로 이동:

```powershell
git fetch origin
git checkout docs/readme-english
git pull
```

## 절차

### 1. 웹 UI 2장 (EN 토글)

웹 UI는 우측 상단 KO/EN 토글로 언어를 바꾼다. 영어로 전환한 뒤 캡처한다. 데스크톱 앱이나
`sbom-ui.bat` 어느 쪽으로 띄워도 된다.

- 사람: 앱을 띄우고 우측 상단 **EN**을 누른다.
- 사람: `web-ui-en` 화면(초기 설정)을 맨 앞에 둔다. 에이전트가 캡처한다.
- 사람: ZIP 등으로 스캔을 시작해 로그가 흐르는 상태를 맨 앞에 둔다. 에이전트가 `web-ui-scan-en`을 캡처한다.

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Capture web-ui-en -Window
powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Capture web-ui-scan-en -Window
```

### 2. 데스크톱 시작 화면 1장 (영어 강제)

시작 화면 언어는 시스템 로캘을 따른다. 한국어 Windows에서는 그냥 두면 한국어로 뜨므로,
`SBOM_LANG=en`으로 영어를 강제해 소스에서 실행한 뒤 시작 화면을 캡처한다. 첫 실행이면 이미지
다운로드 진행이 보이고, 이미 받은 상태면 점검·컨테이너 시작 로그가 영어로 보인다.

```powershell
cd electron
npm install
$env:SBOM_LANG="en"; npm start
```

- 사람: Docker 점검·다운로드·컨테이너 시작 로그가 보이는 시작 화면을 맨 앞에 둔다.
- 에이전트가 캡처한다:

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Capture desktop-startup-en -Window
```

각 캡처는 `docs/images/<이름>.png`로 저장된다. 이미 받은 이미지라 다운로드 진행을 못 보면,
로컬 이미지를 한 번 지우고(`docker rmi ghcr.io/sktelecom/bomlens:latest`) 다시 실행해
첫 실행 화면을 재현한다.

### 3. 확인과 PR

`docs/readme-english`의 README는 이미 `-en.png`를 가리킨다. 세 파일이 그 경로에 있으면 링크가
바로 맞는다.

```powershell
git status --short                 # docs/images/*-en.png 3개가 새로 보여야 한다
git add docs/images/web-ui-en.png docs/images/web-ui-scan-en.png docs/images/desktop-startup-en.png
git commit -m "docs(readme): add English UI screenshots"
git push
```

이 브랜치로 이미 PR이 열려 있으면 push만으로 갱신된다. 없으면 `gh pr create --base main --fill`로
연다. `main` 직접 push는 금지다.

## 보고

마지막에 다음을 요약한다.

- 찍은 캡처 3장과 저장 경로
- 시작 화면이 영어로 떴는지(`SBOM_LANG=en` 적용 여부)
- 갱신/생성한 PR 링크
- 못 찍은 화면이 있으면 사유

찍지 못한 화면은 해당 `-en.png`를 비워 두고 README가 깨진 링크가 되지 않도록 보고에 남긴다.
