---
description: BomLens의 전체 CLI 옵션과 환경변수, 산출물 위치, 이미지 고정, 트러블슈팅 레퍼런스입니다.
---

# CLI 레퍼런스

BomLens의 전체 옵션과 분석 모드, CI/CD 통합 방법, 트러블슈팅을 설명합니다.

## 옵션 레퍼런스

```bash
./scripts/scan-sbom.sh [옵션]
```

> **Windows 사용자**: 위 명령은 macOS/Linux 기준입니다. 다음 중 하나를 고르세요. 설치는 [시작하기](../start/first-scan.ko.md)를 참고하세요.
>
> - `./scripts/scan-sbom.sh`를 `scripts\scan-sbom.bat`로 바꿔 실행합니다 (Git Bash 필요).
> - WSL2에서는 명령을 그대로 실행합니다.
> - CLI 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭하거나 데스크톱 앱을 내려받으세요.

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--project <이름>` | — | **(필수)** 프로젝트 이름 |
| `--version <버전>` | — | **(필수)** 프로젝트 버전 |
| `--target <대상>` | 현재 디렉터리 | 분석 대상: 디렉터리(소스 트리, 또는 OS rootfs·빌드 산출물 staging), Docker 이미지, 바이너리 파일, `.zip`/`.tar.gz` 아카이브 |
| `--git <url>` | — | git/GitHub URL을 얕은 클론(shallow) 후 소스로 분석 (비공개 저장소: `GIT_TOKEN` 환경변수) |
| `--branch <ref>` | 기본 브랜치 | `--git` 대상의 브랜치, 태그, 커밋 (별칭 `--ref`) |
| `--firmware` | false | `--target` 파일을 펌웨어 모드로 강제 (opt-in 펌웨어 이미지) |
| `--analyze <sbom>` | — | 공급사 SBOM 검증·분석 (별칭 `--sbom`). CycloneDX/SPDX. `--target`와 배타 |
| `--model <owner/name>` | — | HuggingFace 모델의 AI SBOM(CycloneDX 1.7 ML-BOM)을 OWASP AIBOM Generator로 생성(opt-in `bomlens-aibom` 이미지; 모델 카드 메타데이터를 네트워크로 가져옴). `--target`/`--analyze`/`--git`/`--merge`와 배타 |
| `--merge <a.json> <b.json> …` | — | CycloneDX SBOM 두 개 이상을 하나로 병합하고 purl 기준으로 중복을 제거한 뒤, 최상위 컴포넌트를 `--project`/`--version`으로 기재. 선택 기능으로, 외부 시스템이 제품당 단일 BOM을 요구할 때 씁니다. 그 외에는 층별로 따로 둡니다([서버 SBOM 작성 가이드](../guides/server-delivery.md) 참고). `--target`/`--analyze`/`--git`와 배타 |
| `--merge-root <file>` | — | `--merge`와 함께: 새 1.6 루트를 만드는 대신 이 입력 파일의 `specVersion`과 최상위 컴포넌트를 유지합니다(예: ML-BOM의 CycloneDX 1.7 루트와 모델 카드). `--merge` 입력 중 하나여야 하며, 유지된 루트의 이름과 버전은 `--project`/`--version`으로 바뀝니다 |
| `--generate-only` | false | 업로드 없이 로컬에만 저장 |
| `--upload-target <대상>` | `dependency-track` | 업로드 대상: `dependency-track`(DT 호환) 또는 `trusca`(네이티브 ingest) |
| `--trusca <project_id>` | — | TRUSCA에 업로드(= `--upload-target trusca` + project id). `API_URL`과 Bearer `API_KEY` 필요 |
| `--notice` | (기본 on) | 오픈소스 고지문(NOTICE, txt+html) 생성 |
| `--security` | (기본 on) | Trivy 보안 보고서(json+md+html) 생성. CVSS, EPSS, CISA KEV 우선순위 신호 포함 |
| `--spdx` | false | 최종 CycloneDX 결과를 변환한 SPDX 2.3 JSON(`_bom.spdx.json`)을 함께 생성 |
| `--all` | — | `--notice --security --spdx` |
| `--no-report` | false | 오픈소스위험분석보고서(risk-report) 생략 (아래 참고) |
| `--lang <en\|ko>` | `en` | 사람이 읽는 적합성·AI 준수 개요 보고서(`.md`/`.html`)의 언어. SBOM과 JSON 보고서는 언어와 무관하게 영어로 유지 |
| `--deep-license` | false | scancode 정밀 라이선스 탐지 (opt-in 이미지) |
| `--deep-cve` | false | grype로 Maven 컴포넌트를 CPE 기준으로 NVD와 추가 대조한다 (opt-in `bomlens-deep-cve` 이미지, 자동으로 내려받음). 오래된 Java 라이브러리에서 Trivy가 놓치는 NVD 전용 CVE를 찾아내며, `--security`를 자동으로 켠다. NVD 실시간 버전 범위로 확인하지 못한 결과는 보고서에 버전 미검증으로 표시된다 — [정밀 CVE 대조 가이드](../guides/reports.ko.md) 참고 |
| `--identify-vendored` | false | 패키지 매니저가 없는 C/C++ 소스에 복사돼 들어간(vendored) 오픈소스를 식별. 파일 지문을 OSSKB 서비스와 대조 (발행 이미지에 포함; 소스가 아니라 해시 전송). [내장 오픈소스 식별 가이드](../guides/identify-vendored.md) 참고 |
| `--byte-stable` | false | 결정론적(재현 가능) SBOM 출력 |
| `--sign` | false | cosign 서명 (`COSIGN_KEY` 필요) |
| `--output-dir <dir>` | 현재 디렉터리 | 산출물 베이스 디렉터리 (별칭 `-o`). 스캔마다 그 아래 `{Project}_{Version}/` 하위 폴더에 묶여 저장되어 소스 트리를 오염시키지 않음 |
| `--timestamp` | false | 실행 하위 폴더 이름에 `_YYYYMMDD-HHMMSS`를 덧붙여, 같은 프로젝트와 버전을 다시 스캔해도 덮어쓰지 않고 나란히 보관. 폴더 이름만 바뀌고 SBOM 내용은 그대로 |
| `--ui` | — | 로컬 웹 UI 실행 |
| `--mount <dir>` | — | `--ui`와 함께: 호스트 디렉터리를 웹 UI의 **디렉터리 경로** 입력에서 고를 수 있는 읽기 전용 스캔 대상으로 추가(여러 번 지정 가능). 실행 폴더 밖의 OS 트리를 스캔할 수 있고, `--mount /`로 실행 중인 호스트 OS도 스캔합니다. 결과는 그대로 실행 폴더에 저장됩니다 |
| `--help` | — | 도움말 출력 |

환경변수로 동작을 조정할 수 있습니다.

| 환경변수 | 기본값 | 설명 |
|----------|--------|------|
| `SBOM_SCANNER_IMAGE` | `ghcr.io/sktelecom/bomlens:latest` | 스캐너 이미지를 다른 태그로 재정의 |
| `SBOM_FIRMWARE_IMAGE` | `ghcr.io/sktelecom/bomlens-firmware:latest` | 펌웨어 분석용 이미지 지정 |
| `SBOM_AIBOM_IMAGE` | `ghcr.io/sktelecom/bomlens-aibom:latest` | AI 모델(ML-BOM) 생성용 이미지 지정 |
| `SBOM_DEEP_CVE_IMAGE` | `ghcr.io/sktelecom/bomlens-deep-cve:latest` | `--deep-cve`(grype maven CPE 매칭)용 이미지 지정 |
| `SBOM_OUTPUT_FLAT` | — | `1`로 두면 실행별 하위 폴더 없이 산출물을 베이스에 평면으로 저장(격리 이전 배치, 옛 경로를 기대하는 CI용) |
| `SBOM_OUTPUT_DIR` | `~/sbom-output` | 데스크톱 앱과 웹 UI의 산출물 베이스(CLI는 대신 `--output-dir` 사용). 스캔마다 그 아래 `{Project}_{Version}/` 하위 폴더에 저장 |
| `SBOM_UI_MOUNT_DIR` | — | CLI 인자를 받지 않는 Windows 실행 파일 `sbom-ui.bat`용: 웹 UI의 디렉터리 경로 입력에 읽기 전용 대상으로 추가할 폴더 하나(`--ui --mount`의 더블클릭 대응). `& ^ | < >` 가 없는 경로를 쓸 것 — 런처는 이런 문자가 있으면 잘못된 마운트를 Docker에 넘기는 대신 거부한다 |
| `SBOM_LANG` | 시스템 로캘 | Windows 런처와 데스크톱 앱의 언어. `en` 또는 `ko`. 한국어가 아니면 영어로 표시된다 |
| `SBOM_PULL` | `missing` | Windows 런처의 다운로드 동작. `missing`은 이미지가 없을 때만, `always`는 매번 레지스트리를 다시 확인(새 `:latest` 반영), `never`는 네트워크를 전혀 쓰지 않음 |
| `SBOM_IMAGE_TAR` | — | `docker save`로 만든 이미지 tar 경로. Windows 런처가 pull 대신 이 파일을 불러온다. 스크립트 옆에 `bomlens-image.tar`가 있으면 자동으로 사용한다. `SBOM_PULL=never`와 함께 쓰면 완전 오프라인 설치가 된다 |
| `CVE_BIN_TOOL_MODE` | `auto` | 펌웨어 CVE 매칭 방식. `auto`는 번들 CVE 데이터베이스가 있으면 그걸 쓰고, 없으면 네트워크에 닿을 때 NVD에서 내려받음. `offline`은 번들 데이터베이스로만 매칭. `online`은 항상 네트워크에서 갱신. `components-only`는 CVE 매칭을 건너뛰고 구성요소만 담은 SBOM을 생성 |
| `CVE_BIN_TOOL_HOME` | `/opt/cve-bin-tool-home` | 번들 cve-bin-tool CVE 데이터베이스 위치. cve-bin-tool은 캐시를 `HOME` 기준으로 잡으므로 `$CVE_BIN_TOOL_HOME/.cache/cve-bin-tool/cve.db`를 읽음 |
| `CVE_BIN_TOOL_DISABLE_SOURCES` | `GAD` | 펌웨어 스캔에서 비활성화할 cve-bin-tool 데이터 출처. `GAD`(GitLab Advisory)는 번들된 cve-bin-tool에서 fetch 시 크래시를 일으켜 기본 비활성화 |
| `SCANOSS_API_URL` | OSSKB 무료 API | `--identify-vendored`의 엔드포인트. 에어갭·대량 사용 시 SCANOSS 상용·자체 호스팅 엔드포인트로 지정 |
| `SCANOSS_API_KEY` | — | `SCANOSS_API_URL`이 요구하는 경우의 자격 증명 |
| `SCANOSS_MIN_FILES` | `2` | 라이브러리를 보고하기 위해 매치돼야 하는 최소 파일 수. 단발성 다운스트림 포크 노이즈를 거른다. `1`로 두면 단일 파일 매치도 모두 유지 |
| `GIT_TOKEN` | — | 비공개 git 저장소 클론에 쓰는 토큰 |
| `HF_TOKEN` | — | `--model`과 AI SBOM 분석의 데이터셋 메타데이터 조회에 쓰는 HuggingFace read 토큰. 비공개·게이트 저장소에 필요하며, 모델을 공개하기 전 검토할 때 쓴다. `HUGGING_FACE_HUB_TOKEN`도 별칭으로 받는다 |
| `COSIGN_KEY` | — | `--sign`에 쓰는 서명 키 경로 |
| `FETCH_LICENSE` | `true` | 소스 스캔 시 의존성 라이선스를 자동 조회. `false`면 조회를 생략해 속도를 높임 |
| `SECURITY_ENRICH` | `true` | 보안 보고서에 EPSS와 CISA KEV 신호를 보강. 폐쇄망에서는 `false`로 외부 조회 생략 |
| `SECURITY_NVD_VERIFY` | `false` | `--deep-cve`와 함께: grype의 `nvd:cpe` 결과를 NVD 실시간 버전 범위와 대조해 범위 밖 오탐을 걸러낸다 (`NVD_API_KEY`와 네트워크 필요, 수 분 추가). 기본은 꺼짐 — 결과를 버리지 않고 버전 미검증으로 표시한다 |
| `NVD_API_KEY` | — | `SECURITY_NVD_VERIFY`에 쓰는 NVD API 키. 컨테이너에 이름으로만 전달하며 명령줄에 노출하지 않는다 |
| `API_URL` | — | 업로드 서버 주소(DT 서버 또는 TRUSCA base) |
| `API_KEY` | — | 업로드 자격. DT는 `X-Api-Key`, TRUSCA는 Bearer 토큰으로 쓰임 |
| `UPLOAD_TARGET` | `dependency-track` | 업로드 대상: `dependency-track` 또는 `trusca` |
| `TRUSCA_PROJECT_ID` | — | TRUSCA 프로젝트 id(UUID). `trusca`일 때 필수 |
| `TRUSCA_REF` | `main` | ingest ref 라벨 |
| `TRUSCA_RELEASE` | `--version` 값 | ingest release 라벨 |

Windows에서는 명령 프롬프트에서 설정한 환경변수가 더블클릭 실행에는 적용되지 않습니다.
그래서 런처는 `UI_PORT`, `SBOM_LANG`, `SBOM_PULL`, `SBOM_IMAGE_TAR`, `SBOM_SCANNER_IMAGE`,
`SBOM_OUTPUT_DIR`, `SBOM_UI_MOUNT_DIR`을 텍스트 파일에서도 읽습니다.
`scripts/bomlens.settings.example.txt`를 스크립트 옆에 `bomlens.settings.txt`로 복사하거나
`%USERPROFILE%\.bomlens\settings.txt`에 두면 됩니다. 실제 환경변수가 있으면 그쪽이 우선합니다.

출력 플래그 상세는 [보고서 생성 가이드](../guides/reports.ko.md)를, 공급사 SBOM 검증은 [공급사 SBOM 검증](../guides/supplier-sbom.ko.md)을 참고하세요.

## 산출물 위치

스캔마다 자체 `{Project}_{Version}/` 하위 폴더에 격리되므로, 한 번 실행에서 나온 파일이 한곳에 모이고 CLI가 스캔하는 소스 트리를 오염시키지 않습니다. 이 하위 폴더는 베이스 디렉터리 아래에 만들어집니다.

- **CLI**(`scan-sbom.sh`): 베이스는 명령을 실행한 디렉터리입니다. `--output-dir <dir>`(별칭 `-o`)로 바꿉니다.
- **데스크톱 앱과 웹 UI**: 베이스는 `~/sbom-output`(Windows는 `C:\Users\<사용자>\sbom-output`)입니다. `SBOM_OUTPUT_DIR` 환경변수로 바꿉니다.

`--git`이나 아카이브 수집 시에도 클론과 해제는 종료할 때 정리되는 임시 디렉터리에서 이뤄지고, 출력 하위 폴더만 남습니다.

같은 프로젝트와 버전을 다시 스캔하면 기본적으로 그 하위 폴더를 덮어써 최신 결과만 남깁니다. 매번 따로 보관하려면 `--timestamp`를 붙입니다. 폴더 이름에 `_YYYYMMDD-HHMMSS`가 덧붙어, 예를 들어 `MyApp_1.0.0_20260626-143000/`가 됩니다. 이 옵션은 폴더 이름만 바꿀 뿐 SBOM 파일 이름과 내용은 그대로라서 `--byte-stable`과 함께 쓸 수 있습니다.

이전의 평면 배치, 즉 하위 폴더 없이 베이스에 파일을 바로 저장하던 방식으로 되돌리려면 `SBOM_OUTPUT_FLAT=1`을 설정합니다. 옛 경로를 기대하는 CI를 위한 옵션입니다.

## 특정 버전의 스캐너 이미지 사용

스캐너 이미지는 `SBOM_SCANNER_IMAGE` 환경변수로 재정의합니다.

```bash
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/bomlens:1.8.0" \
  ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only
```

## 트러블슈팅

### Windows: 산출물이 생기지 않음

스캔이 끝났는데 산출물 파일이 PC에 보이지 않으면, 실행 폴더가 Docker 파일 공유에 포함된 경로인지 확인하세요. 홈 디렉터리(`C:\Users\...`) 아래는 Rancher Desktop과 Docker Desktop 모두 기본 공유되므로 안전합니다. 공유되지 않은 위치에서 실행하면 컨테이너가 결과를 호스트에 쓰지 못합니다.

### Docker 권한 오류

```
Got permission denied while trying to connect to the Docker daemon
```

현재 사용자를 `docker` 그룹에 추가합니다.

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### 디스크 공간 부족

```
no space left on device
```

Docker 캐시를 정리합니다.

```bash
docker system prune -f
```

### 그 밖의 문제

1. `VERBOSE=true ./tests/test-scan.sh` 로 상세 로그를 확인합니다.
2. Docker 이미지를 최신 버전으로 업데이트합니다: `docker pull ghcr.io/sktelecom/bomlens:latest`
3. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/bomlens/issues)에 환경 정보와 로그를 첨부해 제보해 주세요.

모드별 사용법은 [입력 시나리오 가이드](../guides/by-input.ko.md), 산출물 종류는 [산출물 레퍼런스](artifacts.ko.md), 언어 감지는 [지원 생태계](ecosystems.ko.md)를 참고하세요.
