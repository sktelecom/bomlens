# 5가지 입력 시나리오별 처리 가이드

> **관련 문서**: [시작하기](getting-started.md) | [사용 가이드](usage-guide.md) | [고지문·보안·UI 가이드](notice-security-ui-guide.md) | [공급사 SBOM 분석](supplier-sbom-analysis.md) | [펌웨어 분석](firmware-analysis.md)

## 목차

- [개요](#개요)
- [공통 준비](#공통-준비)
- [한눈에 보기](#한눈에-보기)
- [시나리오 1 — GitHub URL](#시나리오-1--github-url)
- [시나리오 2 — 소스 ZIP](#시나리오-2--소스-zip)
- [시나리오 3 — 로컬 C/C++ 소스 디렉터리](#시나리오-3--로컬-cc-소스-디렉터리)
- [시나리오 4 — 기존 SBOM JSON](#시나리오-4--기존-sbom-json)
- [시나리오 5 — 펌웨어 바이너리](#시나리오-5--펌웨어-바이너리)
- [산출물 3종 해석](#산출물-3종-해석)
- [웹 UI로 한 번에](#웹-ui로-한-번에)
- [트러블슈팅 / 한계](#트러블슈팅--한계)

## 개요

오픈소스 컴플라이언스 담당자는 여러 팀에서 서로 다른 형태로 산출물을 받습니다. 이 가이드는 5가지 입력 형태마다 동일한 3종 산출물을 발행하는 방법을 정리합니다.

**3종 산출물**

| 산출물 | 파일 | 의미 |
|--------|------|------|
| 오픈소스 고지문 | `{P}_{V}_NOTICE.{txt,html}` | 라이선스 의무 이행을 위한 고지문 |
| SBOM | `{P}_{V}_bom.json` | CycloneDX 1.6 구성요소 명세 |
| 오픈소스위험분석보고서 | `{P}_{V}_risk-report.{md,html}` | 라이선스+취약점 위험 집계(대응 기한 포함) |

어떤 입력 형태든 `--all --generate-only`를 붙이면 위 3종이 한 번에 생성됩니다(위험분석보고서는 기본 생성이며 `--no-report`로만 끕니다).

## 공통 준비

```bash
# Docker 20.10+ 필요. 스캐너 이미지 1회 받기(또는 직접 빌드).
docker pull ghcr.io/sktelecom/sbom-generator:latest   # 이전 이름 sbom-scanner 도 같은 이미지

# 편의를 위해 스크립트 경로를 변수로 둡니다.
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh
```

## 한눈에 보기

| 입력 형태 | 모드 | 핵심 명령(요약) | 산출물 |
|-----------|------|-----------------|--------|
| GitHub URL | SOURCE | `$SBOM --git <url> --all --generate-only` | 고지문·SBOM·위험분석보고서 |
| 소스 ZIP | SOURCE | `$SBOM --target app.zip --all --generate-only` | 〃 |
| 로컬 디렉터리(C/C++) | SOURCE | `cd dir && $SBOM --all --generate-only` | 〃 |
| 기존 SBOM JSON | ANALYZE | `$SBOM --analyze sbom.json --generate-only` | 〃 + 적합성 보고서 |
| 펌웨어 `.bin` | FIRMWARE | `$SBOM --target dev.bin --firmware --all --generate-only` | 〃 |

> 모든 명령에 `--project <이름> --version <버전>`이 필요합니다(아래 예시 참고).

## 시나리오 1 — GitHub URL

개발1팀이 GitHub 저장소 정보를 전달한 경우. 수동 `git clone` 없이 URL을 그대로 전달합니다.

```bash
$SBOM --project team1-app --version 1.0.0 \
  --git "https://github.com/org/team1-app" \
  --all --generate-only
```

- 특정 브랜치/태그: `--branch v1.2.3`
- 비공개 저장소: `GIT_TOKEN=ghp_xxx $SBOM ... --git https://github.com/org/private ...` (토큰은 로그에 남지 않음)
- 얕은 클론(`--depth 1`)으로 임시 디렉터리에 받은 뒤 분석하고, 산출물만 현재 디렉터리에 남깁니다.

**산출물**: `team1-app_1.0.0_NOTICE.{txt,html}`, `team1-app_1.0.0_bom.json`, `team1-app_1.0.0_risk-report.{md,html}`

## 시나리오 2 — 소스 ZIP

개발2팀이 소스 코드를 ZIP으로 전달한 경우. 수동 해제 없이 아카이브를 그대로 전달합니다.

```bash
$SBOM --project team2-app --version 1.0.0 \
  --target "./team2-app.zip" \
  --all --generate-only
```

- 지원 형식: `.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar`
- zip-slip(경로 탈출) 검사 후 임시 디렉터리에 해제하며, 최상위 폴더가 하나면 자동으로 그 안으로 진입합니다.

**산출물**: 고지문, SBOM, 위험분석보고서 (3종)

## 시나리오 3 — 로컬 C/C++ 소스 디렉터리

개발3팀이 공유 폴더로 전달해 로컬(`~/project/c-dev`)에 복사한 경우. 디렉터리 안에서 실행합니다.

```bash
cd ~/project/c-dev
$SBOM --project team3-dev --version 1.0.0 --all --deep-license --generate-only
```

**C/C++ 안내**

- 패키지 매니저가 있으면(Conan `conanfile.txt` / vcpkg `vcpkg.json`) 의존성이 해석되어 SBOM에 반영됩니다.
- 순수 CMake/Make 소스는 매니저 메타데이터가 없어 SBOM이 희소할 수 있습니다. 이때는 `--deep-license`로 1st-party 소스의 라이선스 헤더를 보강하고, 빌드 산출물(설치된 라이브러리가 있는 staging/rootfs)은 별도로 `$SBOM --target <build-dir> --all --generate-only`(syft)로 분석합니다.
- 패키지 매니저가 없어도 위험분석보고서는 생성되며, 탐지된 구성요소의 라이선스와 취약점을 집계합니다.

**산출물**: 고지문, SBOM, 위험분석보고서 (3종)

## 시나리오 4 — 기존 SBOM JSON

개발4팀이 SBOM(JSON)을 전달한 경우. 소스가 없어도 검증하고 분석합니다.

```bash
$SBOM --project team4-proj --version 2.0.0 \
  --analyze "./team4-sbom.json" \
  --generate-only
```

- CycloneDX와 SPDX(JSON/Tag-Value) 모두 입력 가능하며 내부에서 CycloneDX로 변환합니다.
- `--analyze`는 고지문과 보안을 자동으로 켜므로 `--all`을 따로 붙일 필요가 없습니다.
- 추가로 포맷 적합성 보고서(`_conformance.{json,md,html}`)가 생성되고, 위험분석보고서 1절에 적합성 검증 결과(필수 항목 충족 여부)가 들어갑니다.

**산출물**: 고지문, SBOM(변환본), 위험분석보고서, 적합성 보고서

## 시나리오 5 — 펌웨어 바이너리

개발5팀이 빌드된 펌웨어(`dev.bin`)를 전달한 경우. 언패킹 후 구성요소를 식별합니다.

```bash
$SBOM --project team5-fw --version 1.0.0 \
  --target "./dev.bin" --firmware \
  --all --generate-only
```

- 펌웨어 분석은 GPL 도구(unblob/cve-bin-tool 등)를 포함하는 opt-in 펌웨어 이미지가 필요합니다. 환경변수 `SBOM_FIRMWARE_IMAGE`로 지정하거나, 기본값(`ghcr.io/sktelecom/sbom-scanner-firmware:latest`)을 받습니다.
- 인식 가능한 확장자(`.bin/.img/.squashfs/.ubi/...`)는 `--firmware` 없이도 자동 감지되지만, 명시를 권장합니다.
- 자세한 동작과 한계는 [펌웨어 분석](firmware-analysis.md)을 참고하세요.

**산출물**: 고지문, SBOM, 위험분석보고서 (3종)

## 산출물 3종 해석

- **고지문(NOTICE)**: 라이선스별로 구성요소를 묶어 표기합니다. 배포할 때 동봉하거나 고지하는 의무를 이행하는 데 씁니다.
- **SBOM**: CycloneDX 1.6. 포털이나 취약점 관리 시스템에 올릴 때 기준이 되는 산출물입니다.
- **오픈소스위험분석보고서**: 취약점을 심각도별로 집계하고 대응 기한(Critical 7일, High 30일)을 명시합니다. 라이선스 요약과 (공급사 SBOM의 경우) 포맷 적합성 결과를 포함합니다.

## 웹 UI로 한 번에

CLI에 익숙하지 않다면 웹 UI를 사용합니다.

```bash
$SBOM --ui   # 브라우저에서 http://localhost:8080
```

UI 상단에서 스캔 대상을 고르고 각 형태에 맞게 입력합니다.

| 스캔 대상 | 입력 방법 |
|-----------|-----------|
| 현재 폴더 | UI를 실행한 폴더의 소스를 스캔 |
| GitHub URL | URL 입력 |
| ZIP 업로드 | `.zip`/tar 파일 업로드 |
| SBOM 업로드 | 기존 SBOM(JSON) 업로드, 분석(ANALYZE) 모드 |
| 펌웨어 업로드 | `.bin` 등 업로드(펌웨어 이미지에서 UI 실행 필요) |
| Docker 이미지 | 이미지명 입력 |

실행하면 진행 로그가 실시간으로 표시되고, 완료 후에는 고지문과 SBOM, 위험분석보고서(필요하면 적합성 보고서까지)를 화면에서 보거나 내려받을 수 있습니다. 적합성 결과(적합/부적합)는 상단 카드로 표시됩니다.

> 펌웨어 업로드 탭은 펌웨어 도구가 포함된 이미지에서 UI를 실행할 때만 활성화됩니다:
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/sbom-scanner-firmware:latest $SBOM --ui`

## 트러블슈팅 / 한계

- **GitHub URL**: 비공개 저장소는 `GIT_TOKEN`이 필요합니다. 허용되지 않은 URL 형식(셸 메타문자, `..`, 공백)은 보안상 거부됩니다.
- **ZIP/tar**: 경로 탈출(zip-slip)이 포함된 아카이브는 거부됩니다. Windows Git Bash에 `unzip`이 없으면 `tar`로 처리됩니다.
- **C/C++**: 패키지 매니저가 없는 순수 소스는 SBOM이 희소합니다([시나리오 3](#시나리오-3--로컬-cc-소스-디렉터리) 참고).
- **펌웨어**: 정적 링크 라이브러리와 벤더 변형 squashfs는 탐지율이 제한적입니다([펌웨어 분석](firmware-analysis.md) §한계).
- **SBOM 분석**: SPDX를 CycloneDX로 변환할 때 일부 라이선스 표현이 단순화될 수 있습니다.
