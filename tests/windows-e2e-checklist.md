# Windows e2e 수동 체크리스트

이 문서는 실제 Windows PC에서 라이선스 담당자(이하 A)의 사용 흐름을 그대로 재현해, 가이드만
보고 오픈소스 고지문을 만들 수 있는지 점검하는 체크리스트입니다. 자동화할 수 있는 부분은
`tests/windows-smoke.ps1`이 처리하므로, 여기서는 더블클릭, 브라우저 업로드, 한글 인코딩처럼
사람이 봐야 하는 부분을 다룹니다.

검증 캡처는 `docs/notice-quickstart.md`의 스크린샷 자리표시(`TODO(windows-capture)`)를 실제
화면으로 교체하는 데 씁니다.

## 역할 분담 (Claude와 사람)

이 PC에서 Claude Code를 켜서 검증을 맡길 수 있습니다. 다만 Claude는 터미널 에이전트라
스크립트 실행과 화면 캡처, 문서 반영, 커밋은 하지만 버튼 클릭이나 드래그 같은 GUI 조작은
사람이 합니다.

| 일 | 담당 |
|----|------|
| 자동 스모크 실행(`windows-verify.ps1 -Smoke`) | Claude |
| 화면 캡처, 크롭, `docs/images` 반영, PR | Claude |
| SmartScreen 경고 진행, Rancher 설치, 더블클릭, 브라우저 업로드 | 사람 |
| 캡처할 GUI 화면을 맨 앞으로 띄워 두기 | 사람(그 뒤 캡처는 Claude) |

요령: 사람이 캡처할 화면을 띄워 둔 다음, Claude가 `windows-verify.ps1 -Capture <이름>`을
실행하면 카운트다운 뒤 그 화면을 PNG로 저장합니다.

## 사전: 자동 스모크 먼저 실행

수동 점검 전에 자동 스모크를 돌려 환경 기본기를 확인합니다. 턴키 키트로 실행합니다.

```powershell
powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Smoke
```

`windows-verify.ps1`은 `tests\windows-smoke.ps1`을 그대로 실행합니다. PASS/SKIP만 있고
FAIL이 없으면 다음으로 넘어갑니다. SKIP 항목(예: Git Bash 없음)은 이 체크리스트의 수동
단계에서 다시 확인합니다.

## 환경 매트릭스

같은 흐름을 아래 조건에서 반복합니다. 모두 돌릴 수 없으면 최소한 1행(Rancher Desktop, 한글,
비관리자, Docker 미설치 시작)은 반드시 수행합니다. 이 행이 A의 실제 상황에 가장 가깝습니다.

| Docker 엔진 | 콘솔 코드페이지 | 권한 | 시작 상태 | 결과 |
|-------------|----------------|------|-----------|------|
| Rancher Desktop | 한글(cp949) | 비관리자 | Docker 미설치 | |
| Docker Desktop | 한글(cp949) | 비관리자 | 설치됨 | |
| WSL2 + docker-ce | 한글(cp949) | 비관리자 | 설치됨 | |

## 데스크톱 앱 흐름 (권장 경로)

릴리스의 `SBOM-Generator-*.exe`를 받아 더블클릭하는 흐름을 점검합니다. 미서명이라 SmartScreen
경고가 정상적으로 뜨고, 우회 후 앱이 동작해야 합니다.

| # | 단계 | 기대 결과 | 통과 | 진단/메모 |
|---|------|-----------|------|-----------|
| 1 | 최신 릴리스에서 `SBOM-Generator-*.exe` 받기 | 파일명 버전이 릴리스와 일치 | ☐ | |
| 2 | exe 더블클릭 | "Windows가 PC를 보호했습니다" 경고 표시 | ☐ | |
| 3 | "추가 정보" 누르고 "실행" | 설치/실행이 진행됨 | ☐ | |
| 4 | 앱 시작 | 콘솔 창 없이 시작 화면(상태 로그)이 뜸 | ☐ | |
| 5 | Docker 미설치/미실행 상태로 실행(별도 시도) | 한국어 "Docker가 필요합니다" 안내 화면 | ☐ | |
| 6 | 첫 실행(이미지 미보유) | 이미지 다운로드 진행이 표시됨 | ☐ | |
| 7 | 준비 완료 | 앱 창에 웹 UI가 로드됨 | ☐ | |
| 8 | 앱 종료 | 컨테이너가 정리됨(`docker ps`에 남지 않음) | ☐ | |

## 본 흐름 — ZIP과 bat 대안 (가이드만으로 완주되는가)

데스크톱 앱 대신 ZIP과 `sbom-ui.bat` 경로도 점검합니다. `docs/notice-quickstart.md`의 방법 B를
보고 아래를 수행합니다. 각 단계의 기대 결과가 나오는지 확인하고, 어긋나면 진단 칸을 채웁니다.

| # | 단계 | 기대 결과 | 통과 | 진단/메모 |
|---|------|-----------|------|-----------|
| 1 | Rancher Desktop 설치 후 실행 | 작업 표시줄 아이콘이 안정되고 엔진이 준비됨 | ☐ | |
| 2 | 저장소 ZIP 받아 압축 해제 | `scripts` 폴더가 보임 | ☐ | |
| 3 | `scripts\check-setup.bat` 더블클릭 | 한국어로 ✅/❌ 점검 결과 출력, 글자 안 깨짐 | ☐ | |
| 4 | `scripts\sbom-ui.bat` 더블클릭(첫 실행) | 검은 창에 "이미지 내려받습니다(약 3~4GB)" 안내 표시 | ☐ | |
| 5 | 이미지 다운로드 완료 | 결과 폴더 안내(`C:\Users\...\sbom-output`)가 보임 | ☐ | |
| 6 | 브라우저 자동 열림 | `http://localhost:8080` 화면이 뜸 | ☐ | |
| 7 | 프로젝트 이름·버전 입력, "ZIP 업로드" 선택 | 업로드 입력란이 활성화됨 | ☐ | |
| 8 | 받은 소스 ZIP 업로드 후 스캔 실행 | 진행 로그가 실시간으로 흐름 | ☐ | |
| 9 | 스캔 완료 후 결과 확인 | `..._NOTICE.txt` / `..._NOTICE.html` 다운로드 항목이 보임 | ☐ | |
| 10 | 고지문 내려받기 | 두 파일이 실제로 받아지고 내용이 채워져 있음 | ☐ | |
| 11 | 결과 폴더 확인 | `C:\Users\...\sbom-output`에도 산출물이 저장됨 | ☐ | |

## 인코딩 점검

| 항목 | 기대 결과 | 통과 | 메모 |
|------|-----------|------|------|
| 한글 Windows에서 `sbom-ui.bat` 메시지 | 한국어가 깨지지 않고 표시됨 | ☐ | |
| 한글 Windows에서 `check-setup.bat` 메시지 | 한국어가 깨지지 않고 표시됨 | ☐ | |

## 막힘 진단 점검

도구가 실패 상황을 친절히 안내하는지 일부러 만들어 확인합니다.

| 상황 | 조작 | 기대 결과 | 통과 | 메모 |
|------|------|-----------|------|------|
| 엔진 꺼짐 | Rancher/Docker Desktop을 끈 뒤 `check-setup.bat` 실행 | "엔진이 실행 중이 아닙니다"와 켜는 방법 안내 | ☐ | |
| 포트 충돌 | 8080을 쓰는 다른 프로그램을 띄운 뒤 `check-setup.bat` 실행 | "포트 8080 사용 중"과 `UI_PORT` 변경 안내 | ☐ | |
| 비공유 경로 | `sbom-ui.bat` 대신 비공유 경로에서 CLI로 `--generate-only` 실행 | 산출물 없음을 오류로 알리고 홈 경로 사용을 안내 | ☐ | |

## 캡처할 화면 (windows-verify.ps1)

`docs/notice-quickstart.md`의 자리표시를 교체할 실제 스크린샷을 남깁니다. 사람이 해당 화면을
맨 앞으로 띄워 둔 뒤, 아래 명령으로 캡처합니다. 결과는 `docs/images/<이름>.png`로 저장됩니다.

```powershell
# 맨 앞 창만 캡처(권장). 실행 후 5초 안에 대상 창을 맨 앞으로.
powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Capture smartscreen -Window
```

| 캡처 이름 | 화면 | GUI 띄우기 | 캡처 |
|-----------|------|-----------|------|
| `smartscreen` | "Windows가 PC를 보호했습니다" 경고 | 사람(exe 더블클릭) | Claude |
| `rancher-install` | Rancher Desktop 설치 화면 | 사람 | Claude |
| `app-running` | 앱 창에 웹 UI가 로드된 화면 | 사람(앱 실행) | Claude |
| `app-results` | 결과 목록에서 NOTICE 파일이 보이는 화면 | 사람(스캔 완료) | Claude |
| `bat-console` | `sbom-ui.bat` 첫 실행 시 다운로드 안내가 뜬 검은 창 | 사람(bat 실행) | Claude |

캡처한 PNG를 문서 자리표시와 바꾸려면, 해당 `<!-- TODO(windows-capture): ... -->` 줄을
`![설명](images/<이름>.png)`로 교체하고 PR을 올립니다. 이 작업도 Claude가 합니다.

> 전체 화면을 찍으려면 `-Window`를 빼고, 대기 시간을 조절하려면 `-Delay 8`을 붙입니다.
> 자세한 사용법은 `Get-Help tests\windows-verify.ps1 -Full`.
