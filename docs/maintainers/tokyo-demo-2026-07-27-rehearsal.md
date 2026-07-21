# 도쿄 데모(2026-07-27) 참가자 시점 리허설 결과

대상: 참가자가 각자 Windows 노트북에서 BomLens를 직접 실행하는 시나리오.
실행 환경: Windows 11 Enterprise 26100, Rancher Desktop(시스템 전역 설치), PowerShell 5.1,
시스템 로캘 ko-KR. 관련 절차는 [windows-verification.md](windows-verification.md) 참고.

이 문서는 **자동화 가능한 범위**의 결과다. 설치 마법사와 SmartScreen은 사람 손이 필요해
아래 "남은 수동 항목"에 따로 적었다.

## 실측 수치 (데모 안내에 반영할 것)

| 항목 | 실측값 | 시사점 |
|---|---|---|
| Rancher Desktop 콜드 스타트 → `docker info` 성공 | **200초** | 참가자는 앱/런처 실행 **전에** Docker를 켜고 3분 이상 기다려야 한다. 안내문 첫 줄에 넣을 것 |
| `sbom-ui.bat` 정상 경로 전체 | 5.2초 | 대부분 docker CLI 호출 3회. 허용 범위 |
| 포트 검사 1회 | 1.82초 | 예약범위 캐싱 전에는 5.8초였다(아래 참고) |
| 전 구간 완전 예약 범위에서 포기까지 | 41초 | 20회 시도 후 명확한 오류. 이전에는 90초를 넘겨도 안 끝났다 |
| `ghcr.io/sktelecom/bomlens:latest` 실제 크기 | **997MB** | 사용자 문구는 "약 3~4GB"라고 안내한다 — 아래 미해결 항목 참고 |

## 통과한 항목

- **영어 경로**: `SBOM_LANG=en`에서 `sbom-ui.bat` / `check-setup.bat` 출력에 한글 0자.
  비한국어 로캘(일본 노트북 포함)은 자동으로 영어가 된다.
- **한국어 경로**: ko-KR 로캘에서 리다이렉션 없이 실행 시 정상 렌더. (리다이렉트로 캡처하면
  깨져 보이는데 이는 캡처 아티팩트이며 `test-bat-contract.ps1` 주석에도 같은 취지가 적혀 있다.)
- **엔진 정지 진단**: 엔진만 꺼진 상태에서 "Docker가 설치되어 있지 않습니다"가 아니라
  "엔진이 실행 중이 아닙니다"로 안내. `where docker`로 두 경우를 구분한다.
- **실패 시 창 유지**: 모든 실패 경로가 설명 + `pause`로 끝난다. 종료 코드도 표시된다.
- **설정 파일**: `bomlens.settings.txt`의 `UI_PORT`가 적용되고, 실제 환경변수가 있으면 그쪽이 이긴다.
- **예약 포트(핵심)**: 이 PC의 실제 예약 범위(5678, 5679, 8005, 61656-61755 ...)로 검증.
  `UI_PORT=5678` → **5680으로 자동 이동**(5678·5679 모두 예약이라 두 칸 건너뜀).
  `check-setup.bat`도 `[X] UI port is already in use or reserved`로 보고한다.
  **이 포트들에는 아무것도 LISTENING하지 않는다** — 기존 netstat-only 검사가 "사용 가능"이라
  오판하던 바로 그 false green light가 실제로 해소됐다.
- **오프라인 tar**: `SBOM_PULL=never` + `SBOM_IMAGE_TAR`로 `docker load` 후 정상 진행.
  스크립트 옆 `bomlens-image.tar` 자동 인식도 동작. (경로 검증용 소형 이미지로 확인했고,
  실제 4GB tar 생성은 하지 않았다.)
- **비ASCII 경로**: `...\결과_フォルダ` 경로로 마운트 왕복 성공(컨테이너가 쓴 파일을 호스트에서
  정상 판독). 일본어/한국어 사용자명 노트북에서 문제없다.
- **메타문자 경로 거부**: `&`가 든 폴더는 잘못된 마운트를 넘기는 대신 이유를 설명하고 거부한다.
  후행 백슬래시는 제거되어 `-v ...\plain:/scan-targets/mounted:ro`로 정상 전달된다.
- **전 구간 E2E**: `sbom-ui.bat` → 컨테이너 기동 → `/capabilities` 200 → SPA 응답 확인.

## 리허설 중 발견해 고친 것

1. **`resolveDockerBin`이 실제 Rancher 설치 위치를 놓쳤다.** 이 PC의 Rancher Desktop은
   `C:\Program Files\Rancher Desktop\...`(시스템 전역)인데 후보 목록에는 `%LOCALAPPDATA%`와
   `~/.rd`만 있었다. 관리형 사내 노트북에서 흔한 형태라 ProgramFiles 경로를 추가했다.
2. **포트 검사가 매 실행에 5.8초를 더했다.** 후보 포트마다 `netsh`를 다시 돌리고 예약범위
   행마다 `findstr`를 2개씩 띄우고 있었다. `netsh` 결과를 1회 스냅샷하고 숫자 판별을
   `set /a`로 바꿔 1.82초로 줄였다. 완전 예약 범위에서 90초 초과 → 41초.

## 미해결 / 데모 전 조치가 필요한 것

1. **로컬 `:latest` 이미지가 낡았다(중요).** 이 PC의 이미지는 **2026-07-13 빌드**라
   `server.py`의 펌웨어 이미지 기본값 수정(33ffbea, 2026-07-14)이 반영되어 있지 않다.
   그 결과 `/capabilities`가 옛 이름 `ghcr.io/sktelecom/sbom-scanner-firmware:latest`를 보고한다.
   저장소 코드는 정상(`docker/web/server.py:47` = `bomlens-firmware:latest`)이므로 **코드 버그가
   아니라 캐시 문제**다. 데모 전 `SBOM_PULL=always`로 한 번 갱신하거나 `docker pull` 할 것.
   이번에 추가한 `SBOM_PULL=always`가 정확히 이 문제를 위한 것이다.
2. **`mixed` 함정.** (문구 불일치는 해소됨 — 아래 조치 (b) 참고)

   `docker images`의 SIZE는 압축 해제된 디스크 크기이지 다운로드량이 아니다. 레지스트리
   매니페스트의 레이어 합(= 실제 다운로드)과 나란히 두면 이렇다.

   | 이미지 | 다운로드 | 디스크 | 언제 |
   |---|---|---|---|
   | `bomlens:latest` | **0.24GB** | 997MB | 첫 실행 |
   | `cdxgen-node20:v12` | 0.81GB | 2.85GB | 첫 스캔(node) |
   | `cdxgen-python312:v12` | 1.40GB | 5.21GB | 첫 스캔(python) |
   | `cdxgen-temurin-java21:v12` | 1.66GB | 5.26GB | 첫 스캔(java) |
   | `cdxgen:v12.5.0` (올인원) | **4.35GB** | 15.7GB | `mixed` 또는 `unknown`일 때만 |

   첫 실행 안내는 실제값에 맞춰 "약 250MB"로 고쳤고, 첫 스캔에서 언어별 이미지를 한 번 더
   받는다는 설명을 함께 넣었다. 단일 언어 프로젝트의 현실적인 총량은 다운로드 1~2GB 수준이다.

   진짜 위험은 올인원 이미지다. `docker/lib/source-detect.sh:52-54`의 판정 규칙상 최상위
   폴더에 **인식되는 매니페스트가 2개 이상이면 `mixed`**가 되고, `source-detect.sh:68`의
   기본 분기가 `cdxgen:v12.5.0`(다운로드 4.35GB)을 끌어온다. `package.json` +
   `requirements.txt` 같은 흔한 조합이 여기 해당한다. C/C++(conanfile, vcpkg.json)도
   전용 케이스가 없어 같은 분기를 탄다.

   조치: (a) 데모용 샘플 프로젝트는 **최상위 매니페스트가 정확히 하나**인지 확인할 것 —
   아니면 참가자 전원이 4.35GB를 받는다. (b) 첫 실행 문구는 조정 완료(런처·데스크톱 앱·문서).
   (c) 사전 배포 시 base + 사용할 언어 이미지 1개만 담으면 충분하다.

   참고: cdxgen 이미지에는 `docker pull`이 없다 — `docker run`이 암묵적으로 끌어온다
   (`docker/entrypoint.sh:103-111`). 그래서 진행률이 브라우저가 아니라 컨테이너 stdout으로
   흐르고, 첫 스캔 중 웹 UI가 멈춘 것처럼 보인다.
   `/var/run/docker.sock`을 마운트하지 않으면 syft만 쓰는 경량 경로로 떨어지지만
   (`entrypoint.sh:204-208`), SBOM이 `degraded`로 표시되고 직접 의존성만 잡힌다.
3. **`docker run -it`는 stdin이 터미널이 아니면 실패한다**(`cannot attach stdin to a TTY-enabled
   container`). 더블클릭은 실제 콘솔이라 무관하지만, 스케줄러·파이프·원격 실행 경로에서는
   런처를 쓸 수 없다. 데모 범위 밖이라 이번에는 손대지 않았다.
4. **`boot-recovery.spec.ts`는 Windows에서 skip된다**(POSIX 전용). 데스크톱 앱의 부팅 경로
   변경은 단위 테스트와 Linux CI에만 의존한다.
5. **`electron/test/health.test.mjs`의 타이밍 테스트가 부하 상황에서 간헐 실패**한다.
   단독 실행은 3/3 통과. 기존 flaky이며 이번 변경과 무관하다.
6. `check-docs-drift.sh`가 문서의 `bomlens:1.8.0` 핀 예시가 낡았다고 경고한다(현재 v1.8.2).
   비치명적이지만 참가자가 복사해 갈 수 있는 예시다.

## 남은 수동 항목 (사람 손 필요)

- NSIS 설치 마법사 **대화형** 실행. 지금까지 CI는 silent `/S`만 검증했다.
- SmartScreen "추가 정보 → 실행" 클릭스루 스크린샷 확보 → 참가자 핸드아웃용.
  빌드가 미서명인 한 참가자 전원이 이 화면을 만난다.
- 데스크톱 앱 첫 실행에서 진행률 표시와 "로그 폴더 열기" 버튼 육안 확인.
  (실패 화면 자체는 `SBOM_SMOKE_SCREEN=failed-pull:<사유>` 시드로 자동 검증된다.)
- 웹 UI 육안 확인: 결과 카드의 SPDX 칩, SPDX 다운로드, "같은 설정으로 재스캔" 토글 복원.
  v1.8.0에서 미검증으로 남은 항목이다.
