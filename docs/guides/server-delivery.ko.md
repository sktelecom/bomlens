---
description: 공급사가 납품 서버의 SBOM을 만드는 방법. OS rootfs, 애플리케이션, 정적 링크 의존성을 층별로 따로 스캔해 제출하고, 제출 시스템이 단일 BOM을 요구할 때만 병합한다.
---

# 서버 납품 가이드

## 개요

납품 서버는 단일 소스 트리가 아닙니다. 운영체제가 있고, 그 위에 설치된 애플리케이션이 있으며, 빌드 과정에서 바이너리에 링크된 라이브러리가 있습니다. 이 중 하나만 스캔하면 나머지가 빠지고, 이것이 서버 SBOM이 반려되는 흔한 원인입니다.

이 가이드는 서버를 두 층(OS와 애플리케이션)으로 보고 각 층을 BomLens로 스캔합니다. 층별 SBOM을 따로 제출하는 것이 기본이며, 그래야 각 층을 그 자체로 검토할 수 있습니다. 제출 시스템이 단일 파일을 요구할 때만 하나의 제품 SBOM으로 병합합니다([선택: 단일 SBOM으로 병합](#선택-단일-sbom으로-병합) 참고).

| 층 | 대상 | 누락 시 증상 |
|----|------|--------------|
| OS | 운영체제와 설치된 패키지 전체 (예: CentOS와 rpm 데이터베이스의 모든 패키지) | OS 취약점 누락 |
| 애플리케이션 | 납품 애플리케이션과 패키지 매니저 의존성(직접·전이) | 앱 의존성 누락 |

두 층 외에, 정적 링크된 라이브러리(빌드 시 바이너리에 포함된 openssl·liblfds 등)는 사각지대입니다. 패키지 매니저가 선언하지 않고 OS 패키지 데이터베이스에도 올라 있지 않아 두 층의 스캔이 모두 놓칩니다. 따라서 별도로 탐지·기재해야 하며, 이를 빠뜨리는 것이 가장 흔한 반려 원인입니다. 아래 [정적 링크 라이브러리](#정적-링크-라이브러리--두-층의-사각지대)를 참고하세요.

두 층 모두 BomLens 하나로 만듭니다. 층마다 입력만 바꾸면 됩니다. 요구사항은 OS·애플리케이션·정적 링크 라이브러리를 모두 빠짐없이 담는 것이지, 하나의 파일로 합치는 것이 아닙니다.

## 공통 준비

> **Windows**: 아래 명령은 macOS/Linux 기준입니다. `scan-sbom.bat`와 WSL2 사용법은 [시작 가이드](../start/first-scan.ko.md#설치)를 참고하세요.

```bash
# Docker 20.10+ 필요. 스캐너 이미지를 한 번 받습니다.
docker pull ghcr.io/sktelecom/bomlens:latest

# 스크립트 경로를 변수에 둡니다.
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh
```

## 1층 — OS 패키지

서버의 rootfs(추출한 루트 파일시스템)나 그 컨테이너 이미지를 스캔합니다. Syft가 rpm/dpkg/apk 데이터베이스를 읽어 설치된 패키지를 모두 실제 purl(`pkg:rpm/...`)로 기록합니다.

```bash
# rootfs 디렉터리를 대상으로:
$SBOM --project mms-relay-os --version 6.10 \
  --target /path/to/server-rootfs \
  --all --generate-only

# 서버가 컨테이너 이미지로 패키징돼 있다면:
$SBOM --project mms-relay-os --version 6.10 \
  --target mms-relay:6.10 \
  --all --generate-only
```

대상에는 패키지 데이터베이스가 들어 있어야 합니다. 설치 파일만 풀어 놓고 rpm 데이터베이스가 없는 폴더를 스캔하면 purl이 비어 반려됩니다. 실제 rootfs나 이미지를 대상으로 하세요.

## 2층 — 애플리케이션 코드와 의존성

빌드를 마친 뒤 애플리케이션 소스를 스캔합니다. 패키지 매니저(Maven, npm, pip, Go modules, Conan 등)를 쓰면 전이 의존성까지 자동으로 해석됩니다.

```bash
cd /path/to/app-source
$SBOM --project mms-relay-app --version 2.0.0 --all --generate-only
```

빌드를 먼저 하세요. 빌드나 설치 전 상태에서 스캔하면 전이 의존성이 해석되지 않습니다. 매니페스트가 없는 순수 CMake/Make 애플리케이션은 컴포넌트 목록이 희소해지므로, `--deep-license`로 자체 소스의 라이선스를 보강합니다.

## 정적 링크 라이브러리 — 두 층의 사각지대

소스 스캐너는 바이너리에 정적 링크된 라이브러리를 보지 못하고, OS 패키지 데이터베이스에도 올라 있지 않습니다. 이것이 두 층이 남기는 사각지대입니다. 완전 자동 경로가 없으므로 두 가지를 함께 씁니다.

도구가 찾을 수 있는 만큼은 납품 바이너리나 펌웨어 이미지를 분석해 잡습니다.

```bash
$SBOM --project mms-relay-bin --version 2.0.0 \
  --target /path/to/delivered-binary \
  --all --generate-only
```

스캔으로도 빠지는 부분은 빌드 스크립트에서 소스와 버전을 직접 기재합니다. 예를 들어 빌드가 가져오는 openssl 버전(`openssl 1.1.1za`)을 적습니다. 정적 링크 구성요소를 정밀하게 식별하는 것은 바이너리 구성 분석(BDBA)의 몫이며, SKT가 보완 검증으로 수행하므로 공급사가 이 부담을 혼자 지지는 않습니다.

## 제출 전 층별 자가 검증

층별 SBOM과 정적 링크 SBOM을 그대로 제출합니다. 합친 파일이 아니라 각 SBOM을 따로 확인해, 문제를 해당 위치에서 바로 잡습니다. 각 SBOM이 올바른 형식이고 컴포넌트가 실제 purl을 갖는지 봅니다.

```bash
for bom in mms-relay-os_6.10_bom.json mms-relay-app_2.0.0_bom.json mms-relay-bin_2.0.0_bom.json; do
  echo "$bom: $(jq '.components | length' "$bom") 컴포넌트, \
$(jq '[.components[] | select(.purl)] | length' "$bom") purl 보유"
done
```

각 층에서 두 값은 비슷해야 합니다. 차이가 크면 purl 없는 컴포넌트가 많다는 뜻이고, 보통 원시 디렉터리 스캔이나 수기 작성이 원인입니다. 그다음 [CycloneDX validator](https://github.com/CycloneDX/cyclonedx-cli)로 스키마 유효성을 확인합니다.

층을 분리해 두는 것이 기본인 이유가 있습니다. 검토자가 어느 층이 빠졌는지, 취약점이 어디 있는지 한눈에 보고, 각 SBOM이 자체 의존성 그래프(`dependencies`)를 그대로 유지하기 때문입니다.

## 선택: 단일 SBOM으로 병합

제출이나 업로드 시스템이 제품당 단일 BOM을 요구할 때만 병합합니다(Dependency-Track과 TRUSCA 모두 프로젝트당 BOM 하나를 등록합니다). `--merge`는 층을 합치고 purl 기준으로 컴포넌트 중복을 제거한 뒤, 최상위 컴포넌트를 납품 제품명·버전으로 기재합니다.

```bash
$SBOM --project mms-relay-server --version 1.0.0 \
  --merge mms-relay-os_6.10_bom.json \
          mms-relay-app_2.0.0_bom.json \
          mms-relay-bin_2.0.0_bom.json \
  --generate-only
```

이 명령은 `mms-relay-server_1.0.0_bom.json`을 만들고, `metadata.component`를 서버 제품으로 설정하며, 병합된 컴포넌트 집합 위에 고지문과 위험분석보고서를 생성합니다. 각 컴포넌트에는 `bomlens:layer` 속성이 남으므로 층별로 걸러 볼 수 있습니다(`jq '.components[] | select(.properties[]?.value == "centos")'`).

한 가지 절충이 있습니다. 병합은 층별 `dependencies` 트리를 버립니다(`bom-ref` 네임스페이스가 충돌하기 때문). 전이 의존성 그래프가 검토에 중요하면 층을 분리해 제출하세요.

## 서버 SBOM이 반려되는 경우

- **수기 작성 SBOM.** `tool: manual` SBOM은 거의 항상 컴포넌트가 누락됩니다. 반드시 도구로 생성하세요.
- **`pkg:generic` 컴포넌트.** 취약점 매칭이 되도록 표준 purl 타입(`pkg:rpm`, `pkg:maven` 등)을 쓰세요.
- **메타데이터 없는 원시 디렉터리 스캔.** 패키지 데이터베이스 없이 설치 파일만 풀어 놓은 폴더를 스캔하면 purl이 비어 전체가 반려됩니다. 실제 rootfs나 이미지를 대상으로 하세요.
- **빌드 전 스캔.** 빌드 전 소스로 SBOM을 만들면 전이 의존성이 빠집니다.

## 웹 UI 사용

OS층과 애플리케이션층은 웹 UI(`$SBOM --ui`)에서도 실행할 수 있습니다. UI를 실행한 폴더 하위에 rootfs를 두고 **디렉터리 경로** 입력을 쓰거나, 컨테이너 이미지를 **Docker 이미지** 입력으로 스캔합니다. 실행 폴더 밖 경로는 안전을 위해 거부되므로, 정적 링크층과 선택적 병합은 CLI에서 다루는 것이 가장 직접적입니다.

---

> **관련**: [입력 시나리오](by-input.md) | [펌웨어 분석](firmware.md) | [받은 SBOM 검증](supplier-sbom.md) | [CLI 레퍼런스](../reference/cli.md)
