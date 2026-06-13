# 문서 사용성 검토 보고서 (신규 사용자 관점)

작성일: 2026-06-12

처음 GitHub 저장소에 온 사람이 README와 사용자 가이드만으로 도구를 어려움 없이 쓸 수 있는지 검토한 결과입니다. 친절함, 내용 분산, 메뉴 구조, 과잉 여부, 인터페이스(CLI, 웹 UI, 데스크톱 앱) 혼재에 더해 영어 번역 동기화, 용어 일관성, 명령 복붙 검증, 실패 경로 안내를 함께 점검했습니다.

검토 범위는 README.md, docs/ 한국어 가이드 9종과 영어 번역본, examples/ README 11개, docker/README.md, mkdocs.yml nav입니다. 관점별 정독 검토와 함께 문서의 주요 명령을 실제로 실행해 확인했습니다.

## 실측 검증 결과

문서의 명령을 그대로 복사해 실행한 결과입니다.

| 검증 항목 | 결과 |
|-----------|------|
| `docker pull ghcr.io/sktelecom/sbom-generator:latest` (README) | 성공 |
| `../../scripts/scan-sbom.sh --project "PythonExample" --version "1.0.0" --generate-only` (examples-guide) | 성공. 컴포넌트 39개로 문서의 "약 30-40개" 안내와 일치. 산출물 8종의 파일명이 README의 `{Project}_{Version}_…` 패턴과 일치 |
| `scripts/scan-sbom.sh --ui` 기동 | 사용자 터미널 기준 정상. 스크립트가 `docker run --rm -it`(scripts/scan-sbom.sh:131)로 대화형 터미널을 전제하므로 CI 같은 비대화형 환경에서만 실패. 같은 이미지의 UI가 8080 포트에서 HTTP 200 응답을 반환함을 확인. 포트 충돌 시 `UI_PORT` 안내도 문서화되어 있음 |
| `mkdocs build --strict` | 통과. 사이트 포함 문서에 깨진 내부 링크 없음 |
| 산출물의 저장소 오염 여부 | 예제 폴더에서 스캔해도 `.gitignore`가 산출물을 모두 걸러 줌. 좋은 설계 |

요약하면, 한국어 문서의 명령은 복사해서 그대로 실행했을 때 전부 동작했습니다. 문제는 명령의 정확성이 아니라 구조와 번역 동기화에 있습니다.

## 발견 사항

심각도는 세 단계로 나눴습니다. "막힘"은 신규 사용자가 진행을 멈추는 문제, "혼란"은 헤매게 만드는 문제, "다듬기"는 고치면 좋은 문제입니다.

### 막힘

**1. 영어 사용자는 CLI로 첫 SBOM을 만들 수 없습니다.**

영어 번역본 9쌍 중 6쌍(usage-guide, scenarios-guide, notice-and-security, examples-guide, supplier-sbom-validation, firmware-analysis-guide)은 한국어판과 줄 단위로 동기화되어 있으나, 신규 사용자가 가장 먼저 보는 문서들이 뒤처져 있습니다.

- getting-started.en.md는 108줄로 한국어판 259줄의 절반 이하입니다. CLI의 4가지 입력 형태(소스, GitHub URL, Docker 이미지, 바이너리) 예제가 모두 빠졌고(`--target`, `--git`, `--firmware`, `--analyze` 등장 0회), "결과 파일 이해하기" 절(CycloneDX 구조, jq 예제)이 통째로 없습니다. Windows에서 WSL2 + docker-ce로 설치하는 무료 경로도 한국어판에만 있습니다.
- index.en.md는 카드가 3개뿐입니다(한국어판 6개). 비개발자 빠른 시작, 공급사 SBOM 검증, 고지문과 보안 보고서 카드가 빠져 있습니다.
- README의 English 문서 표는 3개 문서만 안내합니다. examples-guide.en.md, supplier-sbom-validation.en.md, firmware-analysis-guide.en.md가 실제로 존재하는데 링크가 없어, 영어 사용자는 이 문서들의 존재를 알 수 없습니다.

영어 우선이라는 프로젝트 방침과 정면으로 어긋나는 상태입니다.

**2. PHP 예제 README가 11줄짜리 스텁입니다.**

examples/php/README.md에는 스캔 명령 한 줄 외에 목적 설명, 사전 요구사항, 기대 결과가 없습니다. 같은 범주의 Java Maven 예제(186줄)와 비교하면 방치된 격차입니다.

**3. 웹 UI 사용자는 고급 기능에서 막다른 길에 부딪힙니다.**

usage-guide.md는 CLI 옵션 중심이라 웹 UI 사용자가 참조할 수 없습니다. 공급사 SBOM 검증의 웹 UI 흐름은 supplier-sbom-validation.md의 각주 한 줄(37행)이 전부이고, 정밀 라이선스(`--deep-license`)와 펌웨어 분석은 환경 변수를 지정해 UI를 띄우는 방법이 문서화되어 있지 않습니다. 비개발자를 웹 UI로 안내해 놓고, 그 다음 단계의 문서가 CLI로만 되어 있는 구조입니다.

### 혼란

**4. "첫 5분" 안내가 4곳에 분산되어 있고 Windows 경로의 우선순위가 문서마다 다릅니다.**

README Quick Start, getting-started, quickstart-no-cli, notice-and-security의 Quickstart 절이 모두 첫 실행을 안내합니다. 특히 Windows 사용자에게 README는 `.bat` 더블클릭을 먼저(54행), getting-started는 데스크톱 앱(`.exe`)을 먼저(57행) 권해 어느 길이 표준인지 알 수 없습니다.

**5. notice-and-security.md의 위상이 어중간합니다.**

- 제목이 세 주제(고지문, 보안 보고서, 웹 UI)를 묶고 있는데, 웹 UI의 상세 사용법은 이 문서에만 있어 처음 온 사람이 찾기 어렵습니다.
- 도입부가 "sbom-tools는"으로 시작해 정식 이름 "SBOM Generator"와 어긋납니다(3행).
- 다른 가이드가 모두 갖춘 상단 "관련 문서" 줄이 이 문서에만 없습니다.
- cosign 예제(172행, 180행)가 레거시 이미지명 `ghcr.io/sktelecom/sbom-scanner:latest`를 별도 표시 없이 사용합니다.
- mkdocs nav에서 "사용 가이드" 섹션에 들어 있는데, 내용은 산출물 해석과 웹 UI 사용법이라 섹션 성격과 어긋납니다.

**6. CLI와 웹 UI 안내가 한 문서 안에서 절 구분 없이 섞입니다.**

scenarios-guide.md는 5가지 시나리오를 전부 CLI 명령으로 설명한 뒤 마지막에 "웹 UI로 한 번에" 절을 한 번 두는 구조라, 웹 UI 사용자는 자기 시나리오에서 어떤 탭을 쓰는지 끝까지 가야 알 수 있습니다. 데스크톱 앱으로 시작한 사용자는 getting-started의 웹 UI 절에서 `.bat` 더블클릭 안내를 다시 만나는데, 이미 앱을 실행한 사람에게는 중복 안내입니다.

**7. 트러블슈팅이 세 문서에 흩어져 있고 정작 진입 문서에는 없습니다.**

quickstart-no-cli의 "막혔을 때" 절(106행부터)은 잘 만들어졌지만, getting-started와 README에는 트러블슈팅이 없습니다. CLI로 시작한 사용자가 Docker 미기동이나 파일 공유 문제를 만나면 갈 곳이 명확하지 않습니다. Docker 미실행 같은 같은 항목이 여러 문서에 중복으로 적혀 있기도 합니다.

**8. 예제 README의 언어와 분량이 제각각입니다.**

Java Maven, Node.js, Python, Docker 예제는 한국어가 주 언어이고, 나머지 7개는 영어로만 되어 있습니다. Ruby(39줄), Rust(30줄), dotnet(30줄), Swift(31줄)는 사전 요구사항과 언어별 특이사항이 거의 없습니다. 예상 컴포넌트 수 표기도 "약 50-80개", "~30-40개", "~10-15 gems"처럼 형식이 제각각입니다.

### 다듬기

**9. docker/README.md(502줄)는 사용자용과 기여자용이 섞여 있습니다.** 사용자에게 필요한 내용은 앞부분 두 절(개요, 사전 빌드 이미지 사용)뿐이고 나머지 400여 줄은 빌드, 멀티 플랫폼, 배포 등 기여자용입니다. README와 docs/ 어디에서도 이 문서로 가는 링크가 없어 이미지를 직접 쓰려는 사용자가 찾기 어렵습니다.

**10. 형식 불일치가 몇 곳 있습니다.** examples-guide.md의 관련 문서 줄만 굵게 표시가 없고, README의 한국어 문서 표 순서와 mkdocs nav 순서가 다릅니다.

**11. 고지문을 만든 뒤의 동선이 끊깁니다.** "배포물에 동봉하기 좋은 표준 텍스트"라는 설명은 있으나, 생성한 고지문을 자기 소프트웨어 릴리스에 어떻게 포함하는지의 안내는 없습니다.

## 잘 되어 있는 점

- 문서의 명령이 전부 실제로 동작합니다. 산출물 파일명 패턴(`{Project}_{Version}_…`)과 옵션 레퍼런스가 스크립트 실물과 정확히 일치하고, 옵션 별칭(`--analyze`/`--sbom`)과 상호 배타 규칙까지 문서화되어 있습니다.
- quickstart-no-cli.md의 완성도가 높습니다. SmartScreen 경고, Docker 파일 공유, 포트 충돌 등 비개발자가 실제로 만나는 문제를 예측해 "막혔을 때" 절로 정리했습니다.
- index.md의 카드형 안내와 scenarios-guide.md의 "한눈에 보기" 표가 목적별 진입을 빠르게 해 줍니다.
- 사이트 포함 문서 사이의 내부 링크가 깨진 곳 없이 관리되고 있습니다(`mkdocs build --strict` 통과).

## 우선순위 개선안

| 순위 | 항목 | 대상 파일 | 작업 규모 |
|------|------|----------|----------|
| 1 | getting-started.en.md에 CLI 입력 형태 4종 예제와 "Understanding the results" 절 보강, WSL2 설치 경로 추가 | docs/getting-started.en.md | 번역·보강 (중) |
| 2 | README English 표를 6개 문서로, index.en.md 카드를 6개로 확장 | README.md, docs/index.en.md | 문구 수정 (소) |
| 3 | 웹 UI 흐름 절 추가: 공급사 SBOM 검증, 펌웨어 분석, 정밀 라이선스의 UI 경로(환경 변수 지정 포함) | docs/supplier-sbom-validation.md, docs/firmware-analysis-guide.md, docs/notice-and-security.md | 신규 절 작성 (중) |
| 4 | PHP 예제 README를 표준 구성(목적, 요구사항, 명령, 기대 결과, 특이사항)으로 재작성 | examples/php/README.md | 신규 작성 (소) |
| 5 | Windows 진입 경로 우선순위 통일: 데스크톱 앱을 1순위로 README와 getting-started 정렬, notice-and-security의 Quickstart 절은 getting-started 링크로 대체 | README.md, docs/getting-started.md, docs/notice-and-security.md | 통합·수정 (중) |
| 6 | notice-and-security.md 정비: 도입부 명칭을 SBOM Generator로, 관련 문서 줄 추가, cosign 예제 이미지명을 sbom-generator로(레거시 병기), nav 위치 재검토 | docs/notice-and-security.md, mkdocs.yml | 문구 수정 (소) |
| 7 | scenarios-guide 각 시나리오 끝에 "웹 UI에서는 어느 탭" 한 줄 추가 | docs/scenarios-guide.md | 문구 수정 (소) |
| 8 | getting-started에 트러블슈팅 절 신설(또는 통합 FAQ 문서)하고 각 가이드에서 참조 | docs/getting-started.md 외 | 통합 (중) |
| 9 | 예제 README 최소 표준(80줄 내외, 5개 구성 요소) 정의 후 Ruby, Rust, dotnet, Swift 확충과 언어 정책 통일 | examples/*/README.md | 신규 작성 (대) |
| 10 | docker/README를 사용자용으로 축약하고 빌드·배포 내용은 기여자 문서로 이관, 진입 링크 추가 | docker/README.md, docs/contributing/ | 이동·분리 (중) |
| 11 | 형식 통일: 관련 문서 줄 표기, 컴포넌트 수 표기, README 표와 nav 순서 | 여러 문서 | 문구 수정 (소) |

1번과 2번이 가장 시급합니다. 영어 우선 방침에서 영어 사용자의 첫 동선이 가장 약한 상태이고, 두 항목 모두 기존 한국어 내용을 옮기는 작업이라 위험이 작습니다.

## 검토 방법 비고

관점별(온보딩, 정보 구조, 인터페이스 혼재, 일관성) 정독 검토와 영어 동기화 절별 대조, 예제 README 비교를 병렬로 수행한 뒤 핵심 주장을 표본 재검증했습니다. 재검증에서 "getting-started.en.md 파일이 없다"는 발견 1건이 오탐으로 확인되어 제외했습니다. 명령 검증은 2026-06-12 macOS(Docker 29.2.1) 환경에서 수행했습니다.
