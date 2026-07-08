---
description: BomLens 설치부터 첫 SBOM 생성까지. 명령어 없이 데스크톱 앱을 더블클릭하는 가장 빠른 길부터 웹 UI와 CLI까지, CycloneDX SBOM과 오픈소스 고지문, 보안 보고서를 만드는 단계별 가이드입니다.
---

# 시작하기

설치부터 첫 SBOM까지 단계별로 안내합니다. 가장 빠른 길은 명령어가 필요 없습니다. 앱을 받아 더블클릭하면 됩니다.

> 명령어 없이 SBOM이나 고지문만 빨리 만들고 싶다면 [비개발자 빠른 시작](../start/no-cli.ko.md)부터 보세요.

BomLens는 Docker 엔진 위에서 동작하지만, 데스크톱 앱과 웹 UI가 Docker를 점검하고 이미지를 대신 받아 줍니다. Docker를 직접 다루는 건 CLI를 쓸 때뿐입니다. 엔진을 새로 설치해야 한다면 아래 [요구 사항](#요구-사항)을 참고하세요.

## 명령어 없이 시작하기 (권장)

[Windows용 BomLens 내려받기 (.exe)](https://github.com/sktelecom/sbom-tools/releases/latest/download/BomLens-Setup.exe)를 눌러 받은 파일을 더블클릭하면 콘솔 창 없이 UI가 열립니다. 처음 실행할 때 Docker를 점검하고 스캐너 이미지(약 3–4 GB)를 받은 뒤 http://localhost:8080 을 엽니다. 아직 미서명이라 SmartScreen 경고가 뜨면 "추가 정보"를 누르고 "실행"을 고릅니다. 클릭만으로 따라가는 안내는 [비개발자 빠른 시작](../start/no-cli.ko.md)에 있습니다.

![데스크톱 앱 시작 화면 — Docker 점검과 이미지 다운로드, 컨테이너 준비 상황을 보여준다](../images/desktop-startup.png)

설치 파일 대신 스크립트로 쓰고 싶다면, 저장소 ZIP을 받아(초록색 Code 버튼, Download ZIP) 압축을 풀고 `scripts\sbom-ui.bat`를 더블클릭하면 같은 흐름입니다.

## 웹 UI

실행 외에는 명령어가 거의 필요 없습니다. 브라우저에서 실행해 스캔하고 결과를 내려받습니다.

```bash
git clone https://github.com/sktelecom/sbom-tools.git && cd sbom-tools
./scripts/scan-sbom.sh --ui     # http://localhost:8080 이 열리고, 산출물은 현재 폴더 아래 하위 폴더에 저장됩니다
#   Windows: scripts\sbom-ui.bat 더블클릭
```

실행한 폴더가 산출물 베이스이고, 스캔마다 그 아래 `{Project}_{Version}/` 하위 폴더에 저장됩니다. Windows에서는 그 폴더가 Docker 파일 공유에 포함된 경로여야 하며, 홈 디렉터리(`C:\Users\...`) 아래는 기본으로 공유됩니다. 포트가 충돌하면 `UI_PORT=9090`을 앞에 붙입니다. 현재 폴더 소스를 스캔하려면 그 프로젝트 폴더에서 실행하고, GitHub URL이나 ZIP, SBOM, 펌웨어, Docker 이미지는 UI에서 입력을 직접 주므로 아무 폴더에서나 실행해도 됩니다.

![BomLens 웹 UI](../images/web-ui.png)

1. 프로젝트 이름과 버전을 입력합니다.
2. 스캔 대상을 고릅니다. 현재 폴더, GitHub URL, ZIP 업로드, SBOM 업로드, 펌웨어 업로드, Docker 이미지 중에서 선택합니다.
3. 스캔 실행을 누르면 진행 로그가 실시간으로 표시됩니다.
4. 완료되면 SBOM, 고지문, 위험분석 보고서, 보안 보고서를 열거나 내려받습니다.

![결과 화면 — 종류별 결과물 카드와 전체 ZIP 다운로드](../images/app-results.png)

> 펌웨어 업로드 타일은 펌웨어 도구가 포함된 이미지에서 UI를 실행할 때만 활성화됩니다: `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens-firmware:latest ./scripts/scan-sbom.sh --ui`

UI 화면 구성과 스캔 대상별 상세는 [웹 UI 레퍼런스](../reference/ui.ko.md)를 참고하세요.

## 첫 번째 SBOM 생성 (CLI)

자동화와 CI를 위한 고급 방식입니다. 클론한 저장소에서 실행합니다. 아래 명령은 번들로 포함된 Node.js 예제를 스캔합니다. 자신의 폴더를 스캔하려면 `--target`을 그 경로로 바꾸고, 현재 디렉터리를 스캔하려면 `--target`을 빼면 됩니다.

<!-- runnable -->
```bash
# 번들 예제 프로젝트의 모든 산출물
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target examples/nodejs --all --generate-only
```

```bash
# GitHub URL에서 클론 없이 바로
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --git "https://github.com/org/repo" --all --generate-only
```

ZIP 소스(`--target app.zip`), 기존 SBOM(`--analyze sbom.json`), 펌웨어(`--target dev.bin --firmware`), Docker 이미지(`--target nginx:latest`) 등 입력 형태별 처리는 [시나리오별 가이드](../guides/by-input.ko.md)에 정리되어 있습니다.

> `--generate-only`는 산출물을 업로드 없이 로컬에만 저장합니다(취약점 스캔은 그대로 수행). `--all`은 고지문, SBOM, 위험분석 보고서를 한 번에 만듭니다. 전체 옵션은 [CLI 레퍼런스](../reference/cli.ko.md#옵션-레퍼런스)에, 업로드는 `--trusca <project_id>`(또는 `UPLOAD_TARGET`)로 하며 절차는 [업로드 가이드](../guides/upload.ko.md)에 있습니다.

## 결과 파일 이해하기

스캔마다 `{Project}_{Version}/` 하위 폴더에 저장되고, 그 안의 파일 이름은 `{Project}_{Version}_…` 형식입니다. 예: `MyApp_1.0.0/MyApp_1.0.0_bom.json`.

| 파일 | 내용 |
|------|------|
| `{Project}_{Version}_bom.json` | SBOM (CycloneDX 1.6) |
| `{Project}_{Version}_NOTICE.{txt,html}` | 라이선스별로 묶은 오픈소스 고지문 |
| `{Project}_{Version}_security.{json,md,html}` | Trivy 취약점 보고서 |
| `{Project}_{Version}_risk-report.{md,html}` | 오픈소스 위험분석 보고서(기본 생성) |

SBOM은 [CycloneDX 1.6](https://cyclonedx.org/) 형식의 JSON입니다.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-15T10:30:00Z",
    "component": {
      "type": "application",
      "name": "MyApp",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [
        { "license": { "id": "MIT" } }
      ]
    }
  ]
}
```

### 주요 필드 설명

| 필드 | 설명 |
|------|------|
| `metadata.component` | 분석 대상 프로젝트 정보 (이름, 버전) |
| `components` | 발견된 오픈소스 컴포넌트 목록 |
| `components[].purl` | Package URL — 패키지의 고유 식별자 |
| `components[].licenses` | 라이선스 정보 (SPDX ID) |

### SBOM 내용 빠르게 확인하기

아래 예시는 `jq`를 씁니다. WSL2(우분투)는 `sudo apt-get install jq`, Windows Git Bash는 `winget install jqlang.jq`로 설치합니다. 설치가 번거롭다면 웹 UI 개요 화면에서 컴포넌트 수와 라이선스를 바로 볼 수 있습니다.

<!-- runnable -->
```bash
# 컴포넌트 수 확인
jq '.components | length' MyApp_1.0.0/MyApp_1.0.0_bom.json

# 사용된 라이선스 목록
jq '[.components[].licenses[]?.license.id] | unique' MyApp_1.0.0/MyApp_1.0.0_bom.json
```

## 요구 사항

BomLens에 필요한 건 Docker "엔진"뿐이고, 특정 제품에 묶이지 않습니다.

| 항목 | 최소 요구사항 |
|------|-------------|
| Docker | 20.10 이상 |
| 디스크 공간 | 4 GB 이상 (Docker 이미지 포함) |
| OS | Linux, macOS, Windows |
| 아키텍처 | AMD64, ARM64 |

이미 Docker를 쓰고 있다면(Docker Desktop, Rancher Desktop, WSL2의 docker-ce 등 무엇이든) 동작만 확인하고 넘어가세요.

```bash
docker run --rm hello-world
```

### Windows에서 Docker를 처음 설치한다면

Docker Desktop이 가장 간단하지만 일정 규모 이상의 조직에서는 유료 라이선스가 필요합니다. 무료로 쓰려면 다음을 권장합니다.

| 옵션 | 특징 |
|------|------|
| **WSL2 + docker-ce** (권장, 완전 무료) | WSL2 우분투에 docker-ce를 설치하고 그 안에서 `scan-sbom.sh`를 실행. `.bat`와 Windows 명명 파이프가 필요 없고 경로 변환 문제도 없음 |
| **Rancher Desktop** (무료, GUI) | Docker Desktop 대체 GUI, `docker` CLI 제공. `.bat`와 데스크톱 앱 흐름에 그대로 사용 |
| Docker Desktop | 가장 간편하지만 조직 사용 시 유료 라이선스 확인 필요 |

WSL2 + docker-ce 설치 요약(관리자 PowerShell):

```powershell
wsl --install -d Ubuntu          # 설치 후 재부팅, 우분투 초기 설정
```

재부팅 뒤 WSL(우분투) 안에서:

```bash
sudo apt-get update && curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"  # 로그아웃/로그인 후 적용
docker pull ghcr.io/sktelecom/bomlens:latest
```

이후 WSL 안에서 저장소를 클론하고 `./scripts/scan-sbom.sh ...`를 그대로 실행합니다. WSL2 없이 Windows에서 CLI를 쓰려면 [Git for Windows](https://git-scm.com/download/win)(Git Bash)를 설치하고 `scripts\scan-sbom.bat`를 씁니다.

## 다음 단계

| 목표 | 문서 |
|------|------|
| 입력 형태(GitHub, ZIP, SBOM, 펌웨어 등)별 처리 | [시나리오별 가이드](../guides/by-input.ko.md) |
| 고지문, 보안 보고서, 위험분석보고서, 웹 UI | [고지문·보안 보고서 가이드](../guides/reports.ko.md) |
| 전체 옵션과 CI/CD 연동 방법 | [CLI 레퍼런스](../reference/cli.ko.md) |
| 언어별 예제 프로젝트 실습 | [지원 생태계](../reference/ecosystems.ko.md) |
| 내부 구조 이해 | [아키텍처](../concepts/architecture.ko.md) |
| 프로젝트 기여 | [기여 가이드](https://github.com/sktelecom/sbom-tools/blob/main/CONTRIBUTING.md) |

---

> **관련 문서**: [CLI 레퍼런스](../reference/cli.ko.md) | [지원 생태계](../reference/ecosystems.ko.md) | [시나리오 가이드](../guides/by-input.ko.md)
