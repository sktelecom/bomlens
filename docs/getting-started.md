# 시작하기

> **관련 문서**: [사용 가이드](usage-guide.md) | [예제 가이드](examples-guide.md) | [아키텍처](architecture.md)

SBOM Tools를 처음 사용하는 분을 위한 설치부터 첫 번째 SBOM 생성까지의 단계별 가이드입니다.

## 목차

- [필수 요구사항](#필수-요구사항)
- [설치](#설치)
- [첫 번째 SBOM 생성](#첫-번째-sbom-생성)
- [결과 파일 이해하기](#결과-파일-이해하기)
- [다음 단계](#다음-단계)

## 필수 요구사항

| 항목 | 최소 요구사항 |
|------|-------------|
| Docker | 20.10 이상 |
| 디스크 공간 | 4 GB 이상 (Docker 이미지 포함) |
| OS | Linux, macOS, Windows (Git Bash) |
| 아키텍처 | AMD64, ARM64 |

Docker가 설치되어 있지 않다면 [Docker 공식 설치 문서](https://docs.docker.com/get-docker/)를 참고하세요.

## 설치

### 1. 저장소 클론

```bash
git clone https://github.com/sktelecom/sbom-tools.git
cd sbom-tools
```

스크립트만 필요하다면 단독으로 내려받을 수도 있습니다.

```bash
curl -O https://raw.githubusercontent.com/sktelecom/sbom-tools/main/scripts/scan-sbom.sh
chmod +x scan-sbom.sh
```

### 2. Docker 이미지 다운로드

```bash
docker pull ghcr.io/sktelecom/sbom-scanner:latest
```

이미지 크기는 약 3–4 GB입니다. 네트워크 상황에 따라 수 분이 소요될 수 있습니다.

### 3. 설치 확인

```bash
./scripts/scan-sbom.sh --help
```

사용 가능한 옵션 목록이 출력되면 설치가 완료된 것입니다.

## 첫 번째 SBOM 생성

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

> **`--generate-only` 옵션**: 산출물을 업로드 없이 로컬에만 저장합니다(취약점 스캔은 그대로 수행). `--all`을 함께 쓰면 **고지문·SBOM·오픈소스위험분석보고서**가 한 번에 생성됩니다. 전체 옵션은 [사용 가이드](usage-guide.md#옵션-레퍼런스)를 참고하세요.

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

```bash
# 컴포넌트 수 확인
cat MyApp_1.0.0_bom.json | python3 -m json.tool | grep '"name"' | wc -l

# jq 사용 시
jq '.components | length' MyApp_1.0.0_bom.json
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
