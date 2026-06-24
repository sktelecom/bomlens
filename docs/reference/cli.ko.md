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
> - CLI 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭합니다.

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--project <이름>` | — | **(필수)** 프로젝트 이름 |
| `--version <버전>` | — | **(필수)** 프로젝트 버전 |
| `--target <대상>` | 현재 디렉토리 | 분석 대상: 디렉토리(소스 트리, 또는 OS rootfs·빌드 산출물 staging), Docker 이미지, 바이너리 파일, `.zip`/`.tar.gz` 아카이브 |
| `--git <url>` | — | git/GitHub URL을 얕은 클론(shallow) 후 소스로 분석 (비공개 저장소: `GIT_TOKEN` 환경변수) |
| `--branch <ref>` | 기본 브랜치 | `--git` 대상의 브랜치, 태그, 커밋 |
| `--firmware` | false | `--target` 파일을 펌웨어 모드로 강제 (opt-in 펌웨어 이미지) |
| `--analyze <sbom>` | — | 공급사 SBOM 검증·분석 (별칭 `--sbom`). CycloneDX/SPDX. `--target`와 배타 |
| `--model <owner/name>` | — | HuggingFace 모델의 AI SBOM(CycloneDX 1.7 ML-BOM)을 OWASP AIBOM Generator로 생성(opt-in `bomlens-aibom` 이미지; 모델 카드 메타데이터를 네트워크로 가져옴). `--target`/`--analyze`/`--git`/`--merge`와 배타 |
| `--merge <a.json> <b.json> …` | — | CycloneDX SBOM 두 개 이상을 하나로 병합하고 purl 기준으로 중복을 제거한 뒤, 최상위 컴포넌트를 `--project`/`--version`으로 기재. 선택 기능으로, 제출 시스템이 제품당 단일 BOM을 요구할 때 씁니다. 그 외에는 층별로 따로 제출합니다([서버 납품 가이드](../guides/server-delivery.md) 참고). `--target`/`--analyze`/`--git`와 배타 |
| `--generate-only` | false | 업로드 없이 로컬에만 저장 |
| `--upload-target <대상>` | `dependency-track` | 업로드 대상: `dependency-track`(DT 호환) 또는 `trusca`(네이티브 ingest) |
| `--trusca <project_id>` | — | TRUSCA에 업로드(= `--upload-target trusca` + project id). `API_URL`과 Bearer `API_KEY` 필요 |
| `--notice` | (기본 on) | 오픈소스 고지문(NOTICE, txt+html) 생성 |
| `--security` | (기본 on) | Trivy 보안 보고서(json+md+html) 생성. CVSS, EPSS, CISA KEV 우선순위 신호 포함 |
| `--all` | — | `--notice --security` |
| `--no-report` | false | 오픈소스위험분석보고서(risk-report) 생략 (아래 참고) |
| `--deep-license` | false | scancode 정밀 라이선스 탐지 (opt-in 이미지) |
| `--identify-vendored` | false | 패키지 매니저가 없는 C/C++ 소스에 복사돼 들어간(vendored) 오픈소스를 식별. 파일 지문을 OSSKB 서비스와 대조 (발행 이미지에 포함; 소스가 아니라 해시 전송). [내장 오픈소스 식별 가이드](../guides/identify-vendored.md) 참고 |
| `--byte-stable` | false | 결정론적(재현 가능) SBOM 출력 |
| `--sign` | false | cosign 서명 (`COSIGN_KEY` 필요) |
| `--ui` | — | 로컬 웹 UI 실행 |
| `--help` | — | 도움말 출력 |

환경변수로 동작을 조정할 수 있습니다.

| 환경변수 | 기본값 | 설명 |
|----------|--------|------|
| `SBOM_SCANNER_IMAGE` | `ghcr.io/sktelecom/bomlens:latest` | 스캐너 이미지를 다른 태그로 재정의 |
| `SBOM_FIRMWARE_IMAGE` | `ghcr.io/sktelecom/bomlens-firmware:latest` | 펌웨어 분석용 이미지 지정 |
| `SCANOSS_API_URL` | OSSKB 무료 API | `--identify-vendored`의 엔드포인트. 에어갭·대량 사용 시 SCANOSS 상용·자체 호스팅 엔드포인트로 지정 |
| `SCANOSS_API_KEY` | — | `SCANOSS_API_URL`이 요구하는 경우의 자격 증명 |
| `SCANOSS_MIN_FILES` | `2` | 라이브러리를 보고하기 위해 매치돼야 하는 최소 파일 수. 단발성 다운스트림 포크 노이즈를 거른다. `1`로 두면 단일 파일 매치도 모두 유지 |
| `GIT_TOKEN` | — | 비공개 git 저장소 클론에 쓰는 토큰 |
| `COSIGN_KEY` | — | `--sign`에 쓰는 서명 키 경로 |
| `FETCH_LICENSE` | `true` | 소스 스캔 시 의존성 라이선스를 자동 조회. `false`면 조회를 생략해 속도를 높임 |
| `SECURITY_ENRICH` | `true` | 보안 보고서에 EPSS와 CISA KEV 신호를 보강. 폐쇄망에서는 `false`로 외부 조회 생략 |
| `API_URL` | — | 업로드 서버 주소(DT 서버 또는 TRUSCA base) |
| `API_KEY` | — | 업로드 자격. DT는 `X-Api-Key`, TRUSCA는 Bearer 토큰으로 쓰임 |
| `UPLOAD_TARGET` | `dependency-track` | 업로드 대상: `dependency-track` 또는 `trusca` |
| `TRUSCA_PROJECT_ID` | — | TRUSCA 프로젝트 id(UUID). `trusca`일 때 필수 |
| `TRUSCA_REF` | `main` | ingest ref 라벨 |
| `TRUSCA_RELEASE` | `--version` 값 | ingest release 라벨 |

출력 플래그 상세는 [보고서 생성 가이드](../guides/reports.ko.md)를, 공급사 SBOM 검증은 [공급사 SBOM 검증](../guides/supplier-sbom.ko.md)을 참고하세요.

## 산출물 위치

산출물은 명령을 실행한 현재 디렉터리(`$(pwd)`)에 저장됩니다(`{Project}_{Version}_*`). `--git`이나 아카이브 수집 시에도 클론과 해제는 임시 디렉터리에서 이뤄지고, 산출물만 현재 디렉터리에 남습니다. 임시 디렉터리는 종료 시 자동 정리됩니다.

## 특정 버전의 스캐너 이미지 사용

스캐너 이미지는 `SBOM_SCANNER_IMAGE` 환경변수로 재정의합니다.

```bash
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/bomlens:1.2.0" \
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
3. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)에 환경 정보와 로그를 첨부해 리포트해 주세요.

모드별 사용법은 [입력 시나리오 가이드](../guides/by-input.ko.md), 산출물 종류는 [산출물 레퍼런스](artifacts.ko.md), 언어 감지는 [지원 생태계](ecosystems.ko.md)를 참고하세요.
