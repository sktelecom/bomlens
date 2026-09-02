---
description: GitHub URL, ZIP, 로컬 소스, 기존 SBOM, Yocto 빌드 디렉터리, 펌웨어, HuggingFace AI 모델 등 7가지 입력 형태별로 BomLens가 SBOM과 오픈소스 고지문, 위험분석보고서를 만드는 방법을 정리합니다.
---

# 입력 시나리오별 처리 가이드

## 개요

여러 팀에서 산출물을 소스, ZIP, 기존 SBOM, 펌웨어 등 서로 다른 형태로 받습니다. 이 가이드는 7가지 입력 형태마다 동일한 3종 산출물을 발행하는 방법을 정리합니다. (AI 모델은 약간 다릅니다. ML-BOM이고 보안 보고서가 없습니다. 시나리오 7 참고.)

**3종 산출물**

| 산출물 | 파일 | 의미 |
|--------|------|------|
| 오픈소스 고지문 | `{Project}_{Version}_NOTICE.{txt,html}` | 라이선스 의무 이행을 위한 고지문 |
| SBOM | `{Project}_{Version}_bom.json` | CycloneDX 1.6 구성요소 명세 |
| 오픈소스위험분석보고서 | `{Project}_{Version}_risk-report.{md,html}` | 라이선스+취약점 위험 집계(대응 기한 포함) |

어떤 입력 형태든 `--all --generate-only`를 붙이면 위 3종이 한 번에 생성됩니다(위험분석보고서는 기본 생성이며 `--no-report`로만 끕니다).

## 공통 준비

> **Windows 사용자**: 아래 명령은 macOS/Linux 기준입니다. 다음 중 하나를 고르세요. 설치는 [시작하기](../start/first-scan.ko.md)를 참고하세요.
>
> - `./scripts/scan-sbom.sh`를 `scripts\scan-sbom.bat`로 바꿔 실행합니다 (Git Bash 필요).
> - WSL2에서는 명령을 그대로 실행합니다.
> - CLI 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭합니다.

```bash
# Docker 20.10+ 필요. 스캐너 이미지 1회 받기(또는 직접 빌드).
docker pull ghcr.io/sktelecom/bomlens:latest   # 이전 이름 sbom-scanner 도 같은 이미지

# 편의를 위해 스크립트 경로를 변수로 둡니다.
SBOM=/path/to/bomlens/scripts/scan-sbom.sh
```

## 한눈에 보기

아래 모든 명령의 `$SBOM`은 [공통 준비](#공통-준비)에서 정의한 스크립트 경로 변수입니다. 그 단계를 건너뛰었다면 `$SBOM` 자리에 `scan-sbom.sh`의 전체 경로를 그대로 넣으면 됩니다.

| 입력 형태 | 모드 | 핵심 명령(요약) | 산출물 |
|-----------|------|-----------------|--------|
| GitHub URL | SOURCE | `$SBOM --git <url> --all --generate-only` | 고지문, SBOM, 위험분석보고서 |
| 소스 ZIP | SOURCE | `$SBOM --target app.zip --all --generate-only` | 〃 |
| 로컬 디렉터리(C/C++) | SOURCE | `cd dir && $SBOM --all --generate-only` | 〃 |
| 기존 SBOM JSON | ANALYZE | `$SBOM --analyze sbom.json --generate-only` | 〃 + 적합성 보고서 |
| Yocto 빌드 디렉터리 | ANALYZE | `$SBOM --target ~/poky/build --generate-only` | 〃 + 적합성 보고서 |
| 빌드 산출물(`.jar`, `.deb` 등) | BINARY | `$SBOM --target app.jar --all --generate-only` | 〃 |
| 설치 파일(`.exe`, `.msi`, `.dmg`) | FIRMWARE | `$SBOM --target installer.exe --all --generate-only` | 〃 |
| 모바일 앱(`.apk`, `.ipa`) | FIRMWARE | `$SBOM --target app.apk --all --generate-only` | 〃 |
| 펌웨어 `.bin` | FIRMWARE | `$SBOM --target dev.bin --firmware --all --generate-only` | 〃 |
| AI 모델(HuggingFace) | AIBOM | `$SBOM --model owner/name --generate-only` | 고지문, ML-BOM(1.7), 위험분석보고서(보안 없음) |
| AI 모델 파일(GGUF, safetensors 등) | MODELFILE | `$SBOM --model-file ./model.gguf --generate-only` | 고지문, ML-BOM(1.7), 위험분석보고서(보안 없음) |
| 공개 데이터셋(Figshare) | DATASET | `$SBOM --model <항목 주소> --generate-only` | 고지문, ML-BOM(1.7), 위험분석보고서(보안 없음) |

> 모든 명령에 `--project <이름> --version <버전>`이 필요합니다(아래 예시 참고).
>
> 패키지 매니저(Conan/vcpkg)가 없는 C/C++ 소스라면 `--identify-vendored`를 추가하세요. 소스 트리에 통째로 복사된 오픈소스를 이름 있는 구성요소로 탐지합니다. 이 경우 강력히 권장하며, 자세한 내용은 [시나리오 3](#시나리오-3--로컬-cc-소스-디렉터리)을 참고하세요.

## 시나리오 1 — GitHub URL

개발1팀이 GitHub 저장소 정보를 전달한 경우. 수동 `git clone` 없이 URL을 그대로 전달합니다. (`$SBOM`은 [공통 준비](#공통-준비)에서 정의했습니다.)

<!-- runnable -->
```bash
$SBOM --project team1-app --version 1.0.0 \
  --git "https://github.com/sktelecom/bomlens" \
  --all --generate-only
```

- 특정 브랜치/태그: `--branch v1.2.3`
- 비공개 저장소: `GIT_TOKEN=ghp_xxx $SBOM ... --git https://github.com/org/private ...` (토큰은 로그에 남지 않음)
- 얕은 클론(`--depth 1`)으로 임시 디렉터리에 받은 뒤 분석하고, 산출물만 현재 디렉터리 아래 `{Project}_{Version}/` 하위 폴더에 남깁니다.

**산출물**: `team1-app_1.0.0_NOTICE.{txt,html}`, `team1-app_1.0.0_bom.json`, `team1-app_1.0.0_risk-report.{md,html}`

## 시나리오 2 — 소스 ZIP

개발2팀이 소스 코드를 ZIP으로 전달한 경우. 수동 해제 없이 아카이브를 그대로 전달합니다.

<!-- runnable -->
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
- 순수 CMake/Make 소스는 매니저 메타데이터가 없어 SBOM이 희소할 수 있습니다. 이때는 `--deep-license`로 1st-party 소스의 라이선스 헤더를 보강하고, 빌드 산출물(설치된 라이브러리가 있는 staging/rootfs)은 별도로 `$SBOM --target <build-dir> --all --generate-only`(syft)로 분석합니다. OS rootfs와 애플리케이션, 정적 링크 의존성을 층별로 나눠 만드는 서버 SBOM 전체 흐름은 [서버 SBOM 작성 가이드](server-delivery.md)를 참고하세요. 웹 UI에서는 `--deep-license`가 고급 스캔 옵션의 **라이선스 스캔 (ScanCode)** 토글에 대응합니다. 선언된 의존성이 아니라 내 소스 파일(`/src`)을 스캔하며 느리므로, 파일 단위 라이선스 탐지가 필요할 때만 켜세요.
- 패키지 매니저 없이(순수 Make/CMake) 오픈소스를 소스 트리에 통째로 복사(vendored)해 쓰는 경우 — 임베디드와 펌웨어 소스에서 흔합니다 — `--identify-vendored`를 강력히 권장합니다. 이 옵션이 없으면 SBOM이 희소해 내장 라이브러리를 놓치고, 켜면 이들을 CPE가 붙은 이름 있는 구성요소로 탐지해 위험분석보고서가 CVE를 연결할 수 있습니다. [내장 오픈소스 식별](identify-vendored.md)을 참고하세요. BomLens는 이 상황을 감지하면 자동으로 이 옵션을 안내하기도 합니다.
- 패키지 매니저가 없어도 위험분석보고서는 생성되며, 탐지된 구성요소의 라이선스와 취약점을 집계합니다.

**산출물**: 고지문, SBOM, 위험분석보고서 (3종)

## 시나리오 4 — 기존 SBOM JSON

개발4팀이 SBOM(JSON)을 전달한 경우. 소스가 없어도 검증하고 분석합니다.

<!-- runnable -->
```bash
$SBOM --project team4-proj --version 2.0.0 \
  --analyze "./team4-sbom.json" \
  --generate-only
```

- CycloneDX와 SPDX(JSON/Tag-Value) 모두 입력 가능하며 내부에서 CycloneDX로 변환합니다.
- `--analyze`는 고지문과 보안을 자동으로 켜므로 `--all`을 따로 붙일 필요가 없습니다.
- 추가로 포맷 적합성 보고서(`_conformance.{json,md,html}`)가 생성됩니다. 받은 SBOM이 필수 항목(이름, 버전, 식별자 등)을 갖췄는지 점검한 결과이며, 위험분석보고서 1절에도 요약이 들어갑니다. 받은 SBOM을 검증하고 공급사에 보완을 요청하는 흐름은 [공급사 SBOM 검증](../guides/supplier-sbom.ko.md)을 참고하세요.

**산출물**: 고지문, SBOM(변환본), 위험분석보고서, 적합성 보고서

## 시나리오 5 — Yocto 빌드 디렉터리

Yocto로 임베디드 리눅스 이미지를 빌드하고 그 이미지에 무엇이 들어갔는지 확인하려는 경우. 빌드 디렉터리를 그대로 지정하면 됩니다. 빌드가 이미 기록해 둔 내용을 읽습니다.

```bash
$SBOM --project team5-image --version 1.0.0 \
  --target ~/poky/build \
  --generate-only
```

- `conf/local.conf`에 `INHERIT += "create-spdx-3.0"`과 `INHERIT += "vex"`를 넣고 빌드하면 가장 많은 정보를 얻습니다. 이 설정은 5.0 Scarthgap 이상에서만 쓸 수 있고, 4.0 Kirkstone에는 해당 클래스가 없습니다. 두 LTS의 기본값인 SPDX 2.2도 이미지 문서 옆의 `.spdx.tar.zst`와 함께 읽지만 CVE 판정은 담기지 않습니다. SPDX가 전혀 없는 빌드는 빌드가 남긴 매니페스트를 대신 읽고, 둘 다 없으면 스캔을 멈추고 알려 줍니다.
- 분석 대상은 `tmp/deploy/images/<machine>/` 아래의 이미지 SBOM입니다. 빌드 트리 자체는 훑지 않습니다. 이미지에 들어가지 않는 sysroot와 빌드용 도구가 결과에 섞이기 때문입니다.
- 구성요소는 이미지에 설치된 패키지이고, 취약점에는 빌드가 내린 판정(레시피가 패치함, 해당 없음, 아직 남음)이 함께 담깁니다. 남은 것만 발견 항목으로 셉니다.
- 머신이나 이미지를 여럿 빌드했다면 가장 최근 SBOM을 분석하고 후보 전체를 로그에 남깁니다. 다른 것을 고르려면 `--analyze <파일>`로 지정합니다.
- 웹 UI에서는 **디렉터리 / rootfs** 입력으로 그 폴더를 고르면 됩니다(`--ui --mount ~/poky/build`로 마운트하거나 데스크톱 앱의 폴더 추가 사용). 같은 감지가 동작합니다.
- 자세한 동작과 한계는 [공급사 SBOM 가이드의 Yocto 이미지 절](supplier-sbom.ko.md#yocto-이미지)을 참고하세요.

**산출물**: 고지문, SBOM, 위험분석보고서, 적합성 보고서

## 시나리오 6 — 펌웨어 바이너리

개발6팀이 빌드된 펌웨어(`dev.bin`)를 전달한 경우. 언패킹 후 구성요소를 식별합니다.

```bash
$SBOM --project team6-fw --version 1.0.0 \
  --target "./dev.bin" --firmware \
  --all --generate-only
```

- 펌웨어 분석은 GPL 도구(unblob/cve-bin-tool 등)를 포함하는 opt-in 펌웨어 이미지가 필요합니다. 환경변수 `SBOM_FIRMWARE_IMAGE`로 지정하거나, 기본값(`ghcr.io/sktelecom/bomlens-firmware:latest`)을 받습니다.
- 인식 가능한 확장자(`.bin/.img/.squashfs/.ubi/...`)는 `--firmware` 없이도 자동 감지되지만, 명시를 권장합니다.
- 자세한 동작과 한계는 [펌웨어 분석](../guides/firmware.ko.md)을 참고하세요.

**산출물**: 고지문, SBOM, 위험분석보고서 (3종)

## 시나리오 7 — AI 모델(HuggingFace)

개발팀이 코드 대신 HuggingFace 모델을 가리킨 경우. 모델 id만으로 ML-BOM을 생성합니다. 소스 코드도, 모델 가중치 다운로드도 필요 없습니다.

```bash
$SBOM --project bert-base --version 1.0.0 \
  --model "google-bert/bert-base-uncased" \
  --generate-only
```

- opt-in aibom 이미지(`ghcr.io/sktelecom/bomlens-aibom:latest`)가 필요하며 자동으로 받습니다. 다른 태그는 `SBOM_AIBOM_IMAGE`로 지정합니다.
- `--model`은 `--target`/`--analyze`/`--git`/`--merge`와 함께 쓸 수 없습니다.
- CycloneDX 1.7 **ML-BOM**(1.6 아님), 고지문, 위험분석보고서와 G7 최소 요소 적합성 검사를 만듭니다. **보안 보고서는 없습니다.** 모델에는 패키지 CVE가 없습니다.
- 모델 카드, 데이터셋, G7 세부는 [AI 모델 가이드](ai-model.ko.md)를 참고하세요.

**산출물**: 고지문, ML-BOM(CycloneDX 1.7), 위험분석보고서, G7 적합성

### 모델이 아니라 공개된 데이터셋이라면

연구 데이터는 논문이 올려 둔 곳에 있고, 여러 분야에서 그곳은 모델 허브가 아니라 Figshare 같은 저장소입니다. `--model`에 해당 항목을 그대로 넣습니다.

```bash
$SBOM --project cell-imaging-data --version 1.0.0 \
  --model "https://figshare.com/articles/dataset/Title/33412285" \
  --usage product --generate-only
```

- 페이지 주소, DOI, 항목 번호 모두 됩니다. 최신 버전이 아니라 특정 버전을 읽으려면 버전이 표시된 주소나 DOI를 주면 됩니다(`.../33412285/2`, `10.6084/m9.figshare.33413521.v1`).
- 계정도 별도 이미지도 필요 없습니다. 공개 항목 조회는 인증 없이 응답하고, 변환은 기본 이미지에 들어 있습니다.
- 항목은 CycloneDX `data` 컴포넌트가 되며 라이선스, DOI, 저자, 파일별 MD5 값을 담습니다. 표준 식별자로 옮길 수 있는 라이선스(Creative Commons 계열, MIT, Apache 2.0, GPL 계열, CC0)는 SPDX 식별자로 기록하고, 그 밖의 것은 추측하지 않고 표기 그대로 남깁니다.
- `--usage`는 모델과 마찬가지로 적용됩니다. 비상업 조건은 내부 연구용일 때와 외부에 제공할 때 의미가 다릅니다.
- 이름에 "figshare"가 없는 기관 DOI(`10.25916/sut.33412285.v1`)는 다른 DOI와 구분할 수 없으므로 항목 주소를 주십시오.
- 비공개, 엠바고, 철회된 항목은 계정 없이 읽을 수 없으며, 라이선스가 없는 데이터셋으로 기록하지 않고 오류로 알립니다.

산출물: 고지문, ML-BOM(CycloneDX 1.7), 위험분석보고서, 적합성 검사

### 모델 id가 아니라 모델 파일을 받았다면

공급사가 Hub 링크 대신 가중치 파일을 보내왔거나, 사내 모델이라 공개한 적이 없는 경우입니다. 파일을 직접 가리킵니다.

```bash
$SBOM --project internal-llm --version 1.0.0 \
  --model-file ./models/internal-llm-q4.gguf \
  --generate-only
```

- 파일의 헤더를 직접 읽습니다. 네트워크도 HuggingFace 계정도 필요 없고 기본 이미지에서 동작하므로 따로 받을 opt-in 이미지가 없습니다.
- 인식하는 형식은 GGUF, safetensors, PyTorch(`.pt`/`.pth`/`.ckpt`), pickle, npz, npy, ONNX입니다. 식별하지 못한 파일은 기술하지 않고 거부합니다.
- SBOM에 담기는 내용은 형식마다 다릅니다. GGUF는 이름과 라이선스, 아키텍처를 담고 있고 safetensors는 대개 텐서 정보와 dtype만 있습니다. 어떤 형식이든 파일의 SHA-256은 기록하며, 이 값이 받은 파일과 문서를 잇습니다. 파일이 선언하지 않은 값은 추측하지 않고 비워 둡니다.
- 산출물은 위와 같고, 모델 카드에서 오던 정보만 빠집니다.

## 산출물 3종 해석

- **고지문(NOTICE)**: 라이선스별로 구성요소를 묶어 표기합니다. 배포할 때 동봉하거나 고지하는 의무를 이행하는 데 씁니다.
- **SBOM**: CycloneDX 1.6. 취약점 관리 시스템에 올릴 때 기준이 되는 산출물입니다.
- **오픈소스위험분석보고서**: 취약점을 심각도별로 집계하고 권고 대응 기한(Critical 7일, High 30일)을 명시합니다. 라이선스 요약도 담고 있으며, 공급사 SBOM을 분석한 경우에는 포맷 적합성 결과가 더해집니다.

## 웹 UI로 한 번에

CLI에 익숙하지 않다면 웹 UI를 사용합니다.

```bash
$SBOM --ui   # 브라우저에서 http://localhost:8080
```

UI 상단에서 스캔 대상을 고르고 각 형태에 맞게 입력합니다.

| 스캔 대상 | 입력 방법 |
|-----------|-----------|
| 현재 폴더 | UI를 실행한 폴더의 소스를 스캔 |
| 디렉터리 경로 | 실행 폴더 하위 폴더(예: OS rootfs), `--ui --mount <dir>`로 마운트한 폴더, 데스크톱 앱에서는 "폴더 추가" 버튼으로 고른 폴더 |
| GitHub URL | URL 입력 |
| ZIP 업로드 | `.zip`/tar 파일 업로드 |
| 패키지 업로드 | 빌드 산출물 업로드 — `.jar`, `.war`, `.ear`, `.deb`, `.rpm`, `.whl` |
| SBOM 업로드 | 기존 SBOM(JSON) 업로드, 분석(ANALYZE) 모드 |
| 펌웨어 업로드 | `.bin` 등 업로드 — Docker 엔진이 켜져 있으면 타일이 자동으로 나타남 |
| Docker 이미지 | 이미지명 입력 |
| AI 모델 | HuggingFace 모델 id 입력 — Docker 엔진이 켜져 있으면 타일이 자동으로 나타남 |
| 모델 파일 | `.gguf`, `.safetensors`, `.pt` 등 업로드(최대 8GB) |

이 표는 이 가이드가 다루는 시나리오 기준입니다. 전체 10개 스캔 대상은 [웹 UI 레퍼런스](../reference/ui.ko.md#새-스캔)를 참고하세요.

소스 코드 스캔(현재 폴더, GitHub URL, ZIP 업로드)에서는 **고급 스캔 옵션** 섹션에서 어떤 파일을 만들지가 아니라 소스를 어떻게 분석할지를 바꾸는 토글을 제공합니다.

- **라이선스 스캔 (ScanCode)** — CLI `--deep-license`에 대응합니다. 내 소스 파일을 훑어 파일 단위 라이선스 텍스트·헤더(1st-party)를 탐지합니다. 선언된 의존성을 내려받거나 스캔하지는 않습니다.
- **파일 단위 식별 (SCANOSS)** — 소스 트리에 통째로 복사된 제3자 오픈소스(주로 C/C++)를 찾습니다. [내장 오픈소스 식별](identify-vendored.md)을 참고하세요.

둘 다 느리고 기본은 꺼져 있으니 필요할 때만 켜세요. ScanCode는 `--build-arg SBOM_DEEP_LICENSE=true`로 빌드한 이미지에서만 쓸 수 있습니다. 토글 전체 목록과 스캔 대상별 제공 여부는 [웹 UI 레퍼런스](../reference/ui.md)를 참고하세요.

실행하면 진행 로그가 실시간으로 표시되고, 완료 후에는 고지문과 SBOM, 위험분석보고서(필요하면 적합성 보고서까지)를 화면에서 보거나 내려받을 수 있습니다. 적합성 결과(적합/부적합)는 상단 카드로 표시됩니다.

> 펌웨어 업로드 탭은 Docker 엔진이 켜져 있으면 자동으로 나타납니다. 동작 방식과 이미지 태그를
> 바꾸는 방법은 [펌웨어 분석 가이드](firmware.ko.md)를 참고하세요.

## 트러블슈팅 / 한계

- **GitHub URL**: 비공개 저장소는 CLI에서 `GIT_TOKEN` 환경변수로 인증하고, 웹 UI에서는 URL 입력란 아래에 뜨는 별도 토큰 필드에 입력합니다(둘은 서로 다른 경로입니다). 허용되지 않은 URL 형식(셸 메타문자, `..`, 공백)은 보안상 거부됩니다.
- **ZIP/tar**: 경로 탈출(zip-slip)이 포함된 아카이브는 거부됩니다. Windows Git Bash에 `unzip`이 없으면 `tar`로 처리됩니다.
- **C/C++**: 패키지 매니저가 없는 순수 소스는 SBOM이 희소합니다([시나리오 3](#시나리오-3--로컬-cc-소스-디렉터리) 참고).
- **펌웨어**: 정적 링크 라이브러리와 벤더 변형 squashfs는 탐지율이 제한적입니다([펌웨어 분석](../guides/firmware.ko.md) §한계).
- **SBOM 분석**: SPDX를 CycloneDX로 변환할 때 일부 라이선스 표현이 단순화될 수 있습니다.

---

> **관련 문서**: [시작하기](../start/first-scan.ko.md) | [CLI 레퍼런스](../reference/cli.ko.md) | [고지문·보안 보고서 가이드](../guides/reports.ko.md)
