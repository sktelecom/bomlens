# 문서 사용성 검토 보고서 (신규 사용자 관점, 새 구조 기준)

작성일: 2026-06-24

처음 저장소에 온 사람이 (1) 무슨 프로젝트인지, (2) 무엇을 할 수 있는지, (3) 설치와 사용은 어떻게 하는지를 쉽고 간결하게 찾을 수 있는지 검토한 결과입니다. 2026-06-12 1차 검토 이후 문서가 새 구조(`docs/start/`, `docs/guides/`, `docs/concepts/`, `docs/reference/`, 영어 `.md` 기본 · 한국어 `.ko.md`)로 재편되었고, 제품 방향도 바뀌었습니다. 이번 검토는 새 구조와 새 방향을 기준으로 다시 수행했습니다.

## 검토 기준이 된 제품 방향

이번 검토는 다음 방향을 평가 기준으로 삼았습니다.

- 웹 UI와 데스크톱 앱(`.exe` 원클릭, Docker 자동 처리)이 모든 사용자의 1차 동선입니다. CLI와 Docker 직접 실행, 환경 변수는 일부 개발자를 위한 고급 기능입니다. 단 이는 사용성과 문서 위계의 방향이며, 제품 자체는 무계정, 서버 상태 없음, 로컬, 단발 구조를 유지합니다.
- 진입점 역할 분담: 문서 사이트가 사용자용 정본 경험(검색, 탐색, 한국어/영어 전환, 테마)입니다. `docs/*.md`는 그 사이트의 소스이자 GitHub에서 직접 읽을 때의 대체본입니다. README는 30초 소개와 가장 빠른 시작 한 경로, 사이트 링크만 담는 얇은 관문입니다.
- 표면은 간결하게, 깊이는 뒤로. 신규 방문자가 처음 보는 표면에는 사용자 핵심만 두고, 빌드와 배포, 아키텍처 심화, 기여 절차 같은 개발자용 문서는 아래나 별도 영역으로 내립니다.

## 검토 범위와 방법

범위는 사용자 문서 전체입니다. README.md, `docs/`의 영어/한국어 가이드, `examples/` README 11종, `docker/README.md`, `electron/README.md`, `mkdocs.yml` nav를 포함하고 `docs/internal/`(메인테이너 문서)은 제외했습니다. 검토 축 네 가지(온보딩 동선, 3중 진입점 중복과 정본, 인터페이스 위계, 언어 동기화와 용어 일관성)를 병렬로 정독하고, 핵심 명령을 실제로 실행해 확인한 뒤 주요 주장을 표본 재검증했습니다.

## 실측 검증 결과

| 검증 항목 | 결과 |
|-----------|------|
| 문서가 안내하는 세 이미지명 원격 존재 | `ghcr.io/sktelecom/bomlens:latest`, `sbom-generator:latest`, `sbom-scanner:latest` 모두 원격에 존재. 문서의 `docker pull` 명령은 셋 다 동작 |
| `mkdocs build --strict` | 통과(exit 0). 사이트 포함 문서에 깨진 내부 링크와 앵커 없음. i18n으로 nav 25개 항목 한국어 번역 |
| `.exe` 다운로드 링크 정확성 | README/index/first-scan/no-cli의 링크가 모두 `SBOM-Generator-Setup.exe`이고 `electron/electron-builder.yml`의 `artifactName`과 일치 |
| `--ui` 플래그 실재 | `scripts/scan-sbom.sh`에 실재(`:87`, `:131`). 문서의 웹 UI 기동 명령은 유효 |

명령의 정확성은 문제가 없습니다. 문제는 진입점 사이의 동선, 인터페이스 위계, 언어 동기화에 있습니다.

## 발견 사항

심각도는 세 단계입니다. "막힘"은 신규 사용자가 진행을 멈추는 문제, "혼란"은 헤매게 만드는 문제, "다듬기"는 고치면 좋은 문제입니다.

### 막힘

**1. 영어 사용자가 비개발자 빠른 시작을 누르면 한국어 문서로 떨어집니다.**

영어 `docs/start/no-cli.md`가 실재하고 완역되어 있는데도, README의 세 곳(`README.md:19`, `:62`, `:100`)과 영어 `docs/index.md` 본문이 모두 `no-cli.ko.md`(한국어)를 가리킵니다. 비개발자와 웹 UI 동선이 1차 동선인데, 그 안내가 영어 사용자에게는 한국어로만 제공되는 것처럼 보입니다. 새 콘텐츠가 필요한 문제가 아니라 링크 대상만 영어판으로 바꾸면 해소됩니다.

**2. 영어 진입 문서가 데스크톱 앱이 아니라 Docker 전제조건으로 시작합니다.**

`docs/start/first-scan.md:9-22`의 첫 본문이 "Prerequisites" 표(Docker 20.10+, 디스크 4GB)와 `docker run hello-world`입니다. 데스크톱 앱은 `:36` 아래 "Installation > Windows" 하위 항목으로 밀려 있습니다. 더블클릭으로 시작하고 앱이 Docker를 자동 점검하는 경험이 1차여야 하는데, 첫인상이 개발자용 설치 점검표입니다. 게다가 영어판(116줄)이 한국어판(269줄)의 절반 이하라, 기본 언어인 영어 사용자가 더 얕은 안내를 받습니다.

**3. 웹 UI 사용자가 후속 고급 기능에서 막다른 길에 부딪힙니다.**

비개발자를 웹 UI로 안내한 뒤, 일부 후속 가이드가 CLI 전용으로만 설명되어 웹 UI 사용자가 따라갈 수 없습니다.

- 펌웨어: `docs/guides/firmware.md:30-46`의 실행 절차가 전부 CLI이고, 웹 UI 안내는 환경 변수와 CLI를 묶은 한 줄(`SBOM_SCANNER_IMAGE=…bomlens-firmware $SBOM --ui`)뿐입니다. 앱에서 펌웨어를 선택하는 경로가 없습니다.
- 정밀 라이선스: `docs/reference/ui.md:44`는 웹 UI에 deep license 토글이 있다고 하는데, 정작 정본 가이드 `docs/guides/reports.md:114-128`는 `docker build --build-arg …`로 이미지를 직접 빌드하라고만 안내합니다. UI에서 켤 수 있는 기능을 가이드가 이미지 빌드 명령으로 막아 둔 셈입니다.

**4. PHP 예제 README가 깨진 11줄 스텁입니다.**

`examples/php/README.md`는 11줄이고, 4번 줄 "Composer-based PHP project example."이 인용 블록과 헤딩 사이에 줄바꿈 없이 끼어 마크다운 렌더링이 어긋납니다. 다른 모든 예제에 있는 Dependencies, Expected Output, Validate 섹션이 없습니다. 1차 검토에서 지적된 "PHP 11줄 스텁"이 그대로입니다.

**5. 가장 쉽다고 소개한 웹 UI 첫 명령이 복붙되지 않습니다.**

`README.md:54`와 `docs/start/first-scan.md:65`의 `/path/to/sbom-tools/scripts/scan-sbom.sh --ui`는 플레이스홀더입니다. "결과 폴더에서 실행하라"는 지시와 맞물려, 비개발자가 절대 경로를 직접 구성해야 합니다. 가장 쉬운 시작이라고 소개한 경로의 첫 명령이 가장 막히는 지점입니다.

### 혼란

**6. README가 얇은 관문보다 두껍습니다.**

`README.md`(109줄)가 웹 UI 실행, Windows 비개발자 5단계 절차(`:60-74`), CLI 4가지 입력 형태 예제(`:76-91`)를 모두 첫 화면 가까이에 담습니다. 가장 빠른 시작 한 경로가 아니라 `first-scan`, `no-cli`, `by-input`의 요약을 합친 형태입니다. 사이트 안내가 하단(`:93-104`)에 잘 있으므로, 절차와 예제를 줄이고 링크로 위임하면 관문 역할에 맞습니다.

**7. 같은 내용이 여러 곳에 중복됩니다.**

| 주제 | 중복 위치 | 비고 |
|------|-----------|------|
| 웹 UI 실행(`--ui` / `sbom-ui.bat` / `localhost:8080`) | README, first-scan, no-cli, reference/ui, by-input | 5곳. 가장 심함 |
| 설치 명령(`docker pull …bomlens`) | README:41, first-scan:49, docker-image:16, by-input:31 | 4곳 |
| 첫 스캔 명령 | README:80, first-scan:80, cli.md:78, by-input:56 | 4곳. README와 first-scan은 거의 동일 |
| 스캔 타깃 표(입력 형태 → 모드) | reference/ui:34-42, by-input:148-156 | 거의 같은 표 두 벌 |
| Windows 비개발자 절차 | README:60-74, no-cli.md, no-cli.ko.md | README가 no-cli 절차를 복제 |

`docs/reference/ui.md`가 웹 UI 정본인데 다른 문서가 각자 축약본을 들고 있어, 옵션이 바뀌면 동기화 지점이 늘어납니다.

**8. nav와 README가 웹 UI/앱 우선을 반영하지 못합니다.**

`mkdocs.yml`의 Reference 섹션 순서가 CLI options → Artifacts → Ecosystems → Web UI & app → Docker image입니다. 웹 UI 문서가 개발자 레퍼런스 안에, 그것도 CLI 뒤 네 번째에 있습니다. `docs/index.md`의 "Usage guide" 카드도 `reference/cli.md`로 바로 연결되어 사용자를 CLI 레퍼런스로 보냅니다. README의 "Quick Start" 첫 코드블록(`:35-44`)도 `git clone`과 `docker pull`이고, 데스크톱 앱은 `:72`에 "Prefer a real app over a `.bat`?"라는 부차적 위치로 나옵니다.

**9. 공급사 SBOM 검증의 웹 UI 경로가 Windows 곁가지로 보입니다.**

`docs/guides/supplier-sbom.md:29-39`의 본 실행은 `--analyze` CLI이고, 웹 UI 경로는 "> Windows: … sbom-ui.bat … SBOM upload" 인용구 한 줄입니다. 실제로 SBOM 업로드는 운영체제와 무관한데(`reference/ui.md:40`), Windows 전용처럼 읽힙니다. 공급사 SBOM 검증은 비개발자가 쓸 전형적 시나리오라 더 아쉽습니다.

**10. `docs/index.md`만 사이트 전용 문법을 써서 GitHub에서 깨집니다.**

`docs/index.md:11-22`가 버튼(`{ .md-button }`), 카드 그리드(`<div class="grid cards" markdown>`), 아이콘(`:material-rocket-launch:`)을 씁니다. `docs/*.md` 가운데 이 문법을 가진 파일은 index 한 쌍뿐이고, 나머지는 표준 마크다운이라 GitHub에서 그대로 읽힙니다. index는 사이트 홈으로 의도된 파일이라 위험은 낮지만, "GitHub에서도 깨지지 않게"라는 원칙의 유일한 예외입니다.

**11. 용어와 이미지명이 곳에 따라 다릅니다.**

- 산출물 파일명 표기가 `{ProjectName}_{Version}_bom.json`, `{P}_{V}_bom.json`, `{Project}_{Version}_bom.json`으로 갈립니다. 같은 `docs/reference/artifacts.md` 안에서도 `:9`와 `:15`가 다릅니다. 스타일 가이드(`korean-style-guide.md:12`)가 정한 `{Project}_{Version}` 표기로 통일이 필요합니다.
- 셋업 스크립트(`scripts/sbom-ui.bat`, `check-setup.sh`, `check-setup.bat`)와 예제 README 네 건(nodejs, python, java-maven, docker)이 레거시 이미지명 `sbom-generator`/`sbom-scanner`로 안내합니다. 동작은 같지만(별칭이 동일 다이제스트), 문서가 정본이라고 안내한 `bomlens`와 사용자가 화면에서 보는 이름이 어긋납니다.

**12. 예제 README의 서술 언어가 제각각입니다.**

11개 예제 가운데 제목이 한국어 4개(java-maven, nodejs, python, docker), 영어 7개입니다. 영어 기본 정책과 어긋납니다. 각 파일이 "English:" 안내를 달아 완충하지만, 한 목록을 훑는 사용자에게 일관성이 깨져 보입니다.

### 다듬기

**13. 영어 `index.md`에 no-CLI 카드가 없습니다.** 영어판 카드는 3개(`:20-40`), 한국어판은 6개(`:20-58`)로 비개발자 빠른 시작, 공급사 SBOM 검증, 고지문과 보안 보고서 카드가 한국어에만 있습니다. 본문의 no-CLI 안내(`index.md:14`)에는 링크조차 없습니다.

**14. 가이드의 웹 UI 안내가 끝이나 곁가지에 있습니다.** `docs/guides/by-input.md:138`의 "All at once in the web UI"가 모든 CLI 시나리오 뒤 맨 끝입니다. `reports.md:22-28`은 CLI(A)/웹 UI(B) 병기가 모범적이지만 순서가 여전히 CLI 우선입니다.

**15. 일부 예제 README가 빈약합니다.** dotnet(30줄), rust(30줄), swift(31줄)가 동일 골격에 의존 목록과 스캔 명령만 채운 수준입니다. go(96줄), java-gradle(87줄) 대비 Build/Run, Common Issues 보강이 없습니다.

**16. "정식 문서는 사이트" 안내가 README에만 있습니다.** GitHub에서 `docs/*.md`에 바로 도착한 사용자에게 검색과 탐색이 있는 사이트로 가라는 신호가 본문에 거의 없습니다.

## 진입점 역할 분담과 정본 정리

확정된 역할(사이트=사용자 정본, `docs/*.md`=사이트 소스이자 GitHub 대체본, README=얇은 관문)에 비추면 골격은 건강합니다. 콘텐츠가 단일 소스이고, GitHub 대체본이 깨지는 곳은 `index.md` 한 쌍뿐이며, CLI 옵션 전체 표는 `reference/cli.md` 한 곳에만 있습니다. 어긋난 점은 두 가지입니다. README가 관문보다 두꺼워 하위 문서를 복제하는 것(발견 6, 7), 그리고 정본 경험으로 유도하는 안내가 README 한 곳에만 걸린 것(발견 16)입니다.

## 인터페이스 위계 정리

새 방향에서 보면 표면 동선이 아직 CLI/Docker 중심입니다. README의 Quick Start 첫 블록, 영어 first-scan의 첫 화면, nav의 Reference 우선 배치가 모두 개발자 경로를 먼저 보여 줍니다(발견 2, 8). 반대로 `docs/guides/identify-vendored.md:38-46`은 CLI 예시 직후 "In the web UI, open Advanced and turn on …"을 스크린샷과 함께 병기해, 후속 고급 기능 중 유일하게 웹 UI 사용자가 막히지 않습니다. 이 문서를 다른 가이드의 본보기로 삼을 수 있습니다.

## 권장 목차(IA) 재설계

현재 nav를 부분 조정하는 데 그치지 않고, 사용자 동선을 앞에, 개발자 고급을 중간에, 기여를 뒤에 두는 한 구조를 README, `docs/index`, `mkdocs.yml`이 공유하도록 정렬하길 권합니다.

| 구역 | 권장 섹션 | 담는 문서 |
|------|-----------|-----------|
| 표면(모든 사용자) | Start here | no-cli(앱/웹 UI 우선)를 첫째로, first-scan을 앱 중심으로 재서술 |
| 표면(모든 사용자) | Guides | by-input, supplier-sbom, firmware, identify-vendored, upload, ci-cd, server-delivery (각 가이드에 웹 UI 경로를 1차로) |
| 표면(모든 사용자) | Outputs | reports, artifacts, reports-explained(산출물 읽기) |
| 중간(개발자 고급) | Advanced / CLI | cli, docker-image, ecosystems, 환경 변수 |
| 뒤(기여) | About / Contributing | architecture, local-first, package-managers, testing, release notes |

핵심 이동은 세 가지입니다. 웹 UI 문서(`reference/ui.md`)를 Reference 밖 사용자 섹션으로 올리고, `reference/cli.md`와 `docker-image.md`를 "고급/개발자" 섹션으로 명확히 묶고, `index.md`의 "Usage guide" 카드 목적지를 `cli.md`에서 사용자 가이드나 `ui.md`로 바꾸는 것입니다.

## 잘 되어 있는 점

- 한 줄 정체성이 명확합니다. `README.md:5` "BomLens is a local-first SBOM generator and open-source risk assessor … CLI or browser UI, no SaaS."가 첫 화면에서 무엇인지와 무엇을 하는지를 답합니다.
- 명령과 링크가 실물과 맞습니다. `.exe` 이름, `--ui` 플래그, 세 이미지명이 모두 실재를 가리키고 `mkdocs build --strict`가 통과합니다.
- `no-cli.ko.md`의 "막혔을 때" 절이 모범적입니다. SmartScreen, Docker 미기동, 빈 결과 폴더, 포트 충돌을 증상과 조치로 정리하고 `check-setup.bat` 자가 진단까지 연결합니다.
- 위계 분리의 기초가 갖춰져 있습니다. CLI 옵션이 단일 정본이고, 사용자용 `docker run`(`reference/docker-image.md`)과 기여자용 빌드(`docker/README.md`)가 분리되며, `internal/`이 사이트 빌드에서 제외됩니다. `docker-image.md:9-11`은 이미지 별칭 관계를 표로 정직하게 밝힙니다.

## 우선순위 개선안

| 순위 | 항목 | 대상 파일 | 작업 규모 |
|------|------|-----------|----------|
| 1 | no-CLI 링크를 영어판(`no-cli.md`)으로 교정, 영어 `index.md`에 비개발자 카드 추가 | README.md, docs/index.md | 문구 수정(소) |
| 2 | 영어 `first-scan.md`를 데스크톱 앱 우선으로 재서술하고 한국어판 수준으로 보강, Docker 전제조건은 고급 섹션으로 이동 | docs/start/first-scan.md | 재작성(중) |
| 3 | 웹 UI 첫 명령의 `/path/to/` 플레이스홀더 정리 | README.md, docs/start/first-scan.md | 문구 수정(소) |
| 4 | 후속 고급 기능 가이드에 웹 UI 경로를 1차로 추가(펌웨어, 정밀 라이선스, 공급사 SBOM) | docs/guides/firmware.md, reports.md, supplier-sbom.md | 신규 절(중) |
| 5 | nav 재설계: 웹 UI 문서를 사용자 섹션으로 올리고 CLI/Docker를 고급으로 분리, index 카드 목적지 교정 | mkdocs.yml, docs/index.md | 구조 수정(중) |
| 6 | README를 얇은 관문으로 축약: 비개발자 절차와 CLI 4형태를 링크로 위임 | README.md | 축약(중) |
| 7 | PHP 예제 README를 표준 구성으로 재작성, 깨진 렌더링 복구 | examples/php/README.md | 신규 작성(소) |
| 8 | 산출물 파일명 표기를 `{Project}_{Version}_bom.json`으로 통일 | docs/reference/artifacts.md 외 | 문구 수정(소) |
| 9 | 셋업 스크립트와 예제 4건의 이미지명을 `bomlens`로 정렬 | scripts/sbom-ui.bat, check-setup.*, examples/* | 문구 수정(소) |
| 10 | 중복 축소: 웹 UI 실행과 스캔 타깃 표를 `reference/ui.md`로 위임, 다른 문서는 링크로 | by-input.md, first-scan.md 외 | 통합(중) |
| 11 | dotnet, rust, swift 예제 README를 표준 구성으로 확충, 서술 언어 정책 통일 | examples/*/README.md | 신규 작성(중) |
| 12 | "정식 문서는 사이트" 안내를 주요 가이드 상단에 한 줄로 추가 | docs/ 주요 가이드 | 문구 수정(소) |

1번부터 3번이 가장 시급합니다. 영어 사용자의 첫 동선이 가장 약하고, 모두 기존 콘텐츠를 옮기거나 링크를 고치는 작업이라 위험이 작습니다. 4번과 5번은 새 방향(웹 UI/앱 우선)을 문서에 실제로 반영하는 핵심입니다.

## 검토 방법 비고

네 관점(온보딩 동선, 정보 구조와 정본, 인터페이스 위계, 언어와 용어)을 병렬로 정독하고, 핵심 주장을 직접 파일 확인으로 재검증했습니다. 영어 `first-scan.md`의 Docker 우선 시작, README의 no-CLI 한국어 링크, PHP 스텁은 해당 파일을 직접 열어 확인했습니다. 실측은 2026-06-24 macOS(Docker 29.2.1) 환경에서 이미지 원격 존재와 `mkdocs build --strict`를 실행해 수행했습니다.

## 구현 현황

위 우선순위 1~11 개선안은 같은 작업에서 반영했습니다. README를 얇은 관문으로 축약하고 데스크톱 앱과 웹 UI, CLI(고급) 순으로 재배열, 영어와 한국어 `first-scan`을 앱 우선으로 재서술(Docker 전제조건은 맨 뒤 "요구 사항"으로 이동), 후속 가이드(펌웨어, 정밀 라이선스, 공급사 SBOM)에 웹 UI 경로를 1차로 추가, `mkdocs.yml` nav를 사용자 동선(웹 UI를 Get started로) 앞에 두고 CLI와 Docker는 Advanced, 기여와 아키텍처는 About으로 재배치, PHP 예제 복구와 dotnet·rust·swift 예제 확충, 산출물 파일명을 `{Project}_{Version}`으로 통일, 이미지명을 `bomlens`로 정렬했습니다. 정렬 과정에서 예제의 `sbom-scanner:v1` 태그가 원격에 없는 깨진 안내였음을 확인하고 `bomlens:latest`로 교정했습니다.

12번("정식 문서는 사이트" 안내)은 가이드마다 배너를 반복하면 "표면 간결" 방향과 상충하므로, README와 `docs/index`의 기존 사이트 안내로 갈음하고 가이드별 추가는 보류했습니다. 변경 후 `mkdocs build --strict`는 통과합니다.
