# Windows 검증 지시문 (Claude on Windows)

이 파일은 실제 Windows PC에서 Claude Code를 열고 그대로 시키는 지시문이다. 저장소를 클론하면
이 파일이 함께 오므로, Claude에게 "tests/windows-verify-prompt.md 대로 진행해"라고 하면 된다.

## 미션

SBOM Generator 데스크톱 앱의 실제 동작을 Windows에서 검증하고, `docs/notice-quickstart.md`의
`TODO(windows-capture)` 자리표시를 실제 스크린샷으로 교체해 PR을 올린다. GUI 클릭은 사람이,
스크립트 실행과 캡처와 문서 반영과 PR은 Claude가 맡는다.

## 사전 준비 (한 번)

사람이 미리 갖춰 둔다.

- Claude Code for Windows, 그리고 `git`과 GitHub CLI(`gh auth login` 완료)
- Docker 엔진: [Rancher Desktop](https://rancherdesktop.io/) 설치 후 실행(권장)
- 이 저장소 클론: `git clone https://github.com/sktelecom/sbom-tools.git`
- 데스크톱 앱: [최신 릴리스](https://github.com/sktelecom/sbom-tools/releases/latest)에서
  `SBOM-Generator-*.exe` 다운로드

## 역할 분담

| 일 | 담당 |
|----|------|
| `windows-verify.ps1 -Smoke` 실행, 로그 해석 | Claude |
| 화면 캡처(`-Capture`), 크롭, `docs/images` 반영, PR | Claude |
| exe 더블클릭, SmartScreen "추가 정보 → 실행", Rancher 설치, 브라우저 ZIP 업로드 | 사람 |
| 캡처할 GUI 화면을 맨 앞으로 띄워 두기 | 사람(그 뒤 캡처는 Claude) |

세부 점검표는 `tests/windows-e2e-checklist.md`를 따른다. 이 지시문은 그 체크리스트를 실행하는
순서를 정리한 것이다.

## 절차

### 1. 자동 스모크

Claude가 실행한다. 명명 파이프 마운트, 파일 공유 경로, NOTICE 생성, UI 컨테이너 응답을
비대화형으로 확인한다.

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Smoke
```

FAIL이 없으면 다음으로 넘어간다. SKIP(예: Git Bash 없음)은 아래 수동 단계에서 다시 본다.

### 2. 데스크톱 앱 흐름 점검 + 캡처

`tests/windows-e2e-checklist.md`의 "데스크톱 앱 흐름" 표를 따라 사람이 GUI를 진행하고, 각 화면을
맨 앞으로 띄운 상태에서 Claude가 캡처한다. 캡처 명령은 카운트다운 뒤 맨 앞 창을 저장한다.

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Capture <이름> -Window
```

캡처할 화면과 이름:

| 사람이 띄울 화면 | 캡처 이름 |
|------------------|-----------|
| exe 더블클릭 시 "Windows가 PC를 보호했습니다" 경고 | `smartscreen` |
| `sbom-ui.bat` 첫 실행 시 다운로드 안내가 뜬 검은 창 | `bat-console` |
| 스캔 완료 후 결과 목록에서 NOTICE 파일이 보이는 화면 | `app-results` |
| (선택) Rancher Desktop 설치 화면 | `rancher-install` |
| (선택) 앱 창에 웹 UI가 로드된 화면 | `app-running` |

각 캡처는 `docs/images/<이름>.png`로 저장된다.

### 3. 캡처를 문서 자리표시와 교체

Claude가 `docs/notice-quickstart.md`에서 아래 주석을 찾아 해당 이미지 태그로 바꾼다. 주석 문구로
찾으면 줄 번호가 바뀌어도 안전하다.

| 바꿀 주석(검색어) | 교체 결과 |
|-------------------|-----------|
| `TODO(windows-capture): SmartScreen` | `![SmartScreen 경고에서 "추가 정보"를 눌러 "실행"으로 진행](images/smartscreen.png)` |
| `TODO(windows-capture): sbom-ui.bat 첫 실행` | `![sbom-ui.bat 첫 실행 시 이미지 다운로드 안내가 뜬 콘솔 창](images/bat-console.png)` |
| `TODO(windows-capture): 결과 다운로드 목록` | `![결과 목록에서 NOTICE 파일을 내려받는 화면](images/app-results.png)` |

`.md` 저장 시 `scripts/check-doc-style.sh` 훅 경고가 없는지 확인한다(산문 화살표·과한 볼드 금지).

### 4. 인코딩과 막힘 진단 점검 (체크리스트)

`tests/windows-e2e-checklist.md`의 인코딩 표와 막힘 진단 표를 수행한다. 한글 콘솔에서
`sbom-ui.bat`과 `check-setup.bat` 메시지가 깨지지 않는지, 엔진을 끈 상태와 포트 8080 점유
상태에서 `check-setup.bat`이 올바른 한국어 안내를 내는지 확인한다.

### 5. 결과를 PR로 반영

Claude가 진행한다. `main` 직접 push 금지, feature 브랜치와 `gh pr create`로 올린다.

```powershell
git checkout -b docs/windows-screenshots
git add docs/images/*.png docs/notice-quickstart.md
git commit -m "docs(quickstart): add real Windows screenshots from e2e verification"
gh pr create --base main --fill
```

## 보고

마지막에 다음을 요약한다.

- 자동 스모크 결과(PASS/SKIP/FAIL)
- 데스크톱 앱 흐름 점검표에서 통과/실패한 항목과 진단
- 채운 스크린샷 목록과 남은 자리표시
- 올린 PR 링크

캡처할 수 없는 화면(예: 사람이 그 상태를 못 띄운 경우)은 자리표시를 그대로 두고 보고에 남긴다.
