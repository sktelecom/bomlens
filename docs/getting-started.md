# 시작하기

> **관련 문서**: [사용 가이드](usage-guide.md) | [예제 가이드](examples-guide.md) | [아키텍처](architecture.md)

SBOM Generator를 처음 사용하는 분을 위한 설치부터 첫 번째 SBOM 생성까지의 단계별 가이드입니다.

## 목차

- [필수 요구사항](#필수-요구사항)
- [설치](#설치)
- [가장 쉬운 시작: 웹 UI (권장)](#가장-쉬운-시작-웹-ui-권장)
- [첫 번째 SBOM 생성 (CLI)](#첫-번째-sbom-생성-cli)
- [결과 파일 이해하기](#결과-파일-이해하기)
- [다음 단계](#다음-단계)

## 필수 요구사항

| 항목 | 최소 요구사항 |
|------|-------------|
| Docker | 20.10 이상 |
| 디스크 공간 | 4 GB 이상 (Docker 이미지 포함) |
| OS | Linux, macOS, Windows |
| 아키텍처 | AMD64, ARM64 |

이 도구에 필요한 건 Docker "엔진"뿐이고, 특정 제품에 묶이지 않습니다. 이미 Docker를 쓰고 있다면(Docker Desktop, Rancher Desktop, WSL2의 docker-ce 등 무엇이든) 새로 설치할 필요 없이 동작만 확인하고 넘어가세요.

```bash
docker run --rm hello-world
```

환영 메시지가 출력되면 준비가 끝난 것이니 [설치](#설치)로 바로 넘어가면 됩니다. Docker가 아직 없다면 [공식 설치 문서](https://docs.docker.com/get-docker/)를 참고하고, Windows에서 처음 설치한다면 아래에서 무료 엔진을 고르세요.

### Windows에서 Docker를 처음 설치한다면

이미 Docker가 있다면 이 절은 건너뛰어도 됩니다. 처음 설치하는 경우, Docker Desktop이 가장 간단하지만 일정 규모 이상의 조직에서는 유료 라이선스가 필요합니다. 무료로 쓰려면 다음을 권장합니다.

| 옵션 | 특징 | 이 도구와의 관계 |
|------|------|------------------|
| **WSL2 + docker-ce** (권장, 완전 무료) | WSL2 우분투 안에 docker-ce 설치 | WSL 안에서 `scan-sbom.sh`를 직접 실행. `.bat`·Windows 명명 파이프가 필요 없고 경로 변환 문제도 없음 |
| **Rancher Desktop** (무료, GUI) | Docker Desktop 대체 GUI, `docker` CLI 제공 | `scripts\sbom-ui.bat` 더블클릭 흐름을 그대로 사용 |
| Docker Desktop | 가장 간편 | 동작하지만 조직 사용 시 유료 라이선스 확인 필요 |

WSL2 + docker-ce 설치 요약(관리자 PowerShell):

```powershell
wsl --install -d Ubuntu          # 설치 후 재부팅, 우분투 초기 설정
```
재부팅 뒤 WSL(우분투) 안에서:
```bash
sudo apt-get update && curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"  # 로그아웃/로그인 후 적용
docker pull ghcr.io/sktelecom/sbom-generator:latest
```
이후 WSL 안에서 이 저장소를 클론하고 `./scripts/scan-sbom.sh ...`를 그대로 실행하면 됩니다.

Windows에서 웹 UI만 쓴다면(Rancher Desktop/Docker Desktop) 추가 도구 없이 `scripts\sbom-ui.bat`를 더블클릭하면 됩니다. 명령줄 래퍼(`scripts\scan-sbom.bat`)를 쓸 때만 [Git for Windows](https://git-scm.com/download/win)(Git Bash)가 추가로 필요합니다. WSL2 경로를 쓴다면 둘 다 필요 없습니다(WSL 안에서 `.sh`를 직접 실행).

## 설치

설치 방법은 운영체제에 따라 다릅니다. Windows에서 명령줄 없이 쓰려면 아래 다운로드 방식이 가장 쉽고, macOS와 Linux, WSL2에서는 CLI로 설치합니다.

### Windows — 다운로드 후 더블클릭 (명령줄 불필요)

[![Download Windows ZIP](https://img.shields.io/badge/Download-Windows%20ZIP-2496ED?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/sktelecom/sbom-tools/archive/refs/heads/main.zip)

1. 위 버튼으로 ZIP을 받아 압축을 풉니다.
2. 압축을 푼 폴더에서 `scripts\sbom-ui.bat`를 더블클릭합니다.
3. 잠시 뒤 브라우저에 `http://localhost:8080`이 열립니다.

스캐너 이미지는 처음 실행할 때 자동으로 내려받습니다(약 3–4 GB). `sbom-ui.bat`이 Docker 설치와 실행 여부를 먼저 확인하고, 문제가 있으면 해결 방법을 안내합니다.

명령줄을 쓰고 싶다면 [Git for Windows](https://git-scm.com/download/win)(Git Bash)를 설치한 뒤 `scripts\scan-sbom.bat`를 사용하거나, WSL2에서 아래 macOS/Linux 절차를 그대로 따르면 됩니다.

### macOS / Linux — CLI

#### 1. 저장소 클론

```bash
git clone https://github.com/sktelecom/sbom-tools.git
cd sbom-tools
```

git이 설치되어 있지 않다면 GitHub 저장소 페이지에서 Code 버튼을 눌러 Download ZIP으로 받은 뒤 압축을 풉니다.

스크립트만 필요하다면 단독으로 내려받을 수도 있습니다.

```bash
curl -O https://raw.githubusercontent.com/sktelecom/sbom-tools/main/scripts/scan-sbom.sh
chmod +x scan-sbom.sh
```

#### 2. Docker 이미지 다운로드

```bash
docker pull ghcr.io/sktelecom/sbom-generator:latest   # 이전 이름 sbom-scanner 도 같은 이미지로 제공됩니다
```

이미지 크기는 약 3–4 GB입니다. 네트워크 상황에 따라 수 분이 소요될 수 있습니다.

#### 3. 설치 확인

```bash
./scripts/scan-sbom.sh --help
```

사용 가능한 옵션 목록이 출력되면 설치가 완료된 것입니다.

## 가장 쉬운 시작: 웹 UI (권장)

명령어에 익숙하지 않아도 됩니다. 브라우저에서 실행해 스캔하고 결과를 내려받는 세 단계면 끝입니다. (UI 서버는 스캐너 이미지에 내장되어 있어 추가 설치가 필요 없습니다.)

### UI 실행

```bash
# 결과물을 저장할 폴더에서 실행 (어디든 무방)
cd ~/sbom-output
/path/to/sbom-tools/scripts/scan-sbom.sh --ui
#  → 잠시 후 브라우저에서 http://localhost:8080 가 자동으로 열립니다
```
Windows에서는(Rancher Desktop/Docker Desktop) `scripts\sbom-ui.bat`를 더블클릭합니다. UI를 실행한 폴더가 산출물 저장 위치가 되는데, 이 폴더는 Docker 엔진의 파일 공유에 포함된 경로여야 합니다. 홈 디렉터리(`C:\Users\...`) 아래는 두 엔진 모두 기본으로 공유되므로 안전합니다. (WSL2 + docker-ce를 쓴다면 `.bat` 대신 WSL 안에서 `scan-sbom.sh --ui`를 실행하며, 이 파일 공유 제약은 없습니다.) 공유되지 않은 위치에서 실행하면 스캔이 끝나도 산출물이 PC에 나타나지 않습니다. 포트가 충돌하면 `UI_PORT=9090`을 앞에 붙입니다.

> 실행 위치(현재 폴더)는 산출물이 저장되는 곳이자, 스캔 대상으로 "현재 폴더"를 골랐을 때 스캔되는 소스입니다. GitHub URL이나 ZIP, SBOM, 펌웨어 업로드, Docker 이미지를 쓴다면 입력을 UI에서 직접 주므로 아무 폴더에서나 실행해도 됩니다. 현재 폴더 소스를 스캔하려면 그 프로젝트 폴더에서 실행하세요.

### 스캔

![SBOM Generator 웹 UI](images/web-ui.png)

1. 프로젝트 이름과 버전을 입력합니다.
2. 스캔 대상을 고릅니다. 현재 폴더, GitHub URL, ZIP 업로드, SBOM 업로드, 펌웨어 업로드, Docker 이미지 중에서 선택할 수 있습니다.
3. 스캔 실행을 누르면 진행 로그가 실시간으로 표시됩니다.

### 결과 확인

완료되면 화면에 컴포넌트 수와 취약점 심각도(공급사 SBOM이면 적합성도)가 카드로 뜨고, 표에서 SBOM, 오픈소스 고지문, 오픈소스 위험분석 보고서, 보안 보고서를 바로 열거나 내려받을 수 있습니다.

> 펌웨어 업로드 탭은 펌웨어 도구가 포함된 이미지에서 UI를 실행할 때만 활성화됩니다:
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/sbom-scanner-firmware:latest ./scripts/scan-sbom.sh --ui`

UI 화면 구성과 스캔 대상별 상세는 [고지문·보안·UI 가이드](notice-security-ui-guide.md#웹-ui---ui)를 참고하세요. 아래는 같은 작업을 명령줄(CLI)로 하는 방법입니다.

## 첫 번째 SBOM 생성 (CLI)

분석 대상에 따라 아래 중 원하는 방법을 선택하세요.

### 소스 코드 분석

프로젝트 루트 디렉토리에서 실행합니다. 패키지 매니저 파일(`pom.xml`, `package.json`, `go.mod` 등)을 자동으로 감지합니다.

```bash
cd /path/to/your/project
/path/to/sbom-tools/scripts/scan-sbom.sh \
  --project "MyApp" \
  --version "1.0.0" \
  --generate-only
```

### GitHub URL에서 바로 생성

수동 클론 없이 저장소 URL을 전달합니다(얕은 클론 후 분석).

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --git "https://github.com/org/repo" \
  --all --generate-only
```

ZIP 소스(`--target app.zip`), 기존 SBOM(`--analyze sbom.json`), 펌웨어(`--target dev.bin --firmware`) 등 입력 형태별 처리는 [시나리오별 가이드](scenarios-guide.md)에 정리되어 있습니다.

### Docker 이미지 분석

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" \
  --version "1.0.0" \
  --target "nginx:latest" \
  --generate-only
```

### 바이너리 파일 분석

```bash
./scripts/scan-sbom.sh \
  --project "MyFirmware" \
  --version "2.0.0" \
  --target "./firmware.bin" \
  --generate-only
```

> `--generate-only` 옵션은 산출물을 업로드 없이 로컬에만 저장합니다(취약점 스캔은 그대로 수행). `--all`을 함께 쓰면 고지문, SBOM, 오픈소스 위험분석 보고서가 한 번에 생성됩니다. 전체 옵션은 [사용 가이드](usage-guide.md#옵션-레퍼런스)를 참고하세요.

## 결과 파일 이해하기

분석이 완료되면 현재 디렉토리에 `{ProjectName}_{Version}_bom.json` 파일이 생성됩니다.

예시: `MyApp_1.0.0_bom.json`

파일은 [CycloneDX 1.6](https://cyclonedx.org/) 형식의 JSON입니다.

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

아래 예시는 `jq`를 사용합니다. WSL2(우분투)에는 `sudo apt-get install jq`로, Windows Git Bash에는 기본 포함되지 않으니 [jq 릴리스](https://jqlang.github.io/jq/download/)에서 받거나 `winget install jqlang.jq`로 설치하세요. 설치가 번거롭다면 웹 UI의 요약 카드에서 컴포넌트 수·라이선스를 바로 확인할 수 있습니다.

```bash
# 컴포넌트 수 확인
jq '.components | length' MyApp_1.0.0_bom.json

# 사용된 라이선스 목록
jq '[.components[].licenses[]?.license.id] | unique' MyApp_1.0.0_bom.json
```

## 다음 단계

| 목표 | 문서 |
|------|------|
| 입력 형태(GitHub·ZIP·SBOM·펌웨어 등)별 처리 | [시나리오별 가이드](scenarios-guide.md) |
| 고지문·보안보고서·위험분석보고서·웹 UI | [고지문·보안·UI 가이드](notice-security-ui-guide.md) |
| 전체 옵션 및 CI/CD 연동 방법 | [사용 가이드](usage-guide.md) |
| 언어별 예제 프로젝트 실습 | [예제 가이드](examples-guide.md) |
| 내부 구조 이해 | [아키텍처](architecture.md) |
| 프로젝트 기여 | [기여 가이드](../CONTRIBUTING.md) |
