---
description: 외부에서 받은 SBOM(CycloneDX/SPDX)이 요구사항을 충족하는지 BomLens로 검증하고, 라이선스와 취약점을 분석해 위험 보고서를 만드는 방법.
---

# 공급사 SBOM 검증 가이드

협력사나 다른 팀에서 받은 SBOM(JSON)이 요구사항을 충족하는지 검증하는 방법을 설명합니다. 검증에 이어 라이선스와 취약점을 분석하고, 위험 보고서까지 만듭니다. 소스 코드가 없어도 SBOM 파일 하나만 있으면 됩니다.

설계 배경과 검증 로직의 내부 동작은 메인테이너용 [공급사 제출 SBOM 검증·분석](https://github.com/sktelecom/bomlens/blob/main/docs/maintainers/supplier-sbom-analysis.md) 문서를 참고하세요.

## 언제 쓰나

협력사나 다른 팀이 소스 대신 SBOM 파일을 전달했고, 그 SBOM이 품질 기준을 갖췄는지 확인한 뒤 라이선스와 취약점을 점검해야 할 때 씁니다. 입력은 CycloneDX와 SPDX(JSON, Tag-Value) 모두 가능하며, 내부에서 CycloneDX로 변환해 분석합니다.

검증 기준은 SBOM이 의존성 점검에 쓸 만한 품질을 갖췄는지를 보는 항목들입니다. 조직마다 요구사항이 다를 수 있으니, 참고 사례로 SK텔레콤 [공급망 보안 가이드](https://sktelecom.github.io/guide/supply-chain/for-suppliers/)의 [SBOM 요구사항](https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/)을 둘 수 있습니다.

| 구분 | 기준 |
|------|------|
| 포맷 | CycloneDX v1.3~1.6 또는 SPDX v2.2~2.3 |
| 필수 메타데이터 | timestamp, 생성 도구 정보, 최상위 컴포넌트 이름과 버전 |
| 필수 컴포넌트 필드 | name, version, 표준 `pkg:type/name@version` 형식의 PURL(`pkg:generic` 금지) |
| 완전성 | 직접 의존성과 추이적(transitive) 의존성 모두 포함 |
| 권장 | supplier, 라이선스(SPDX ID), hash |

> 위 허용 포맷 범위는 SK텔레콤 제출 기준의 기본값입니다. 조직이 다른 범위를 허용한다면 `CYCLONEDX_SPEC_VERSIONS`, `AI_CYCLONEDX_SPEC_VERSIONS`(AI SBOM), `SPDX_SPEC_VERSIONS` 환경 변수(공백으로 구분한 목록)로 덮어쓸 수 있습니다. 목록은 [Docker 이미지 환경 변수](../reference/docker-image.md)에 있습니다.

## 한 번에 실행하기

### 웹 UI에서

웹 UI를 열고 **SBOM 업로드**를 골라 받은 파일을 올린 뒤, 프로젝트 이름과 버전을 입력하고 스캔을 실행합니다.

Java(Maven) 비중이 큰 SBOM이라면 스캔 옵션에서 **심층 CVE 매칭 (maven, NVD)**을 켜세요. 오래된 Maven 라이브러리를 NVD 전용 취약점까지 대조해 다른 출처가 놓치는 항목을 찾아내며, 대신 스캔이 더 오래 걸립니다. 이 옵션은 SBOM 업로드에서만 나타나고, 처음 실행할 때 deep-cve 이미지를 한 번 내려받습니다. CLI의 `--deep-cve`와 같은 매칭입니다.

```bash
./scripts/scan-sbom.sh --ui     # http://localhost:8080 이 열립니다
#   Windows: scripts\sbom-ui.bat 더블클릭
```

설치는 [시작하기](../start/first-scan.ko.md)를 참고하세요.

### CLI에서

스캐너 이미지를 한 번 받아 두고(`docker pull ghcr.io/sktelecom/bomlens:latest`), 받은 SBOM 파일을 `--analyze`에 넘깁니다.

```bash
./scripts/scan-sbom.sh --project supplier-app --version 2.0.0 \
  --analyze "./supplier-sbom.json" \
  --generate-only
```

`--analyze`는 고지문과 보안 분석을 자동으로 켜므로 `--all`을 따로 붙일 필요가 없습니다. `--generate-only`는 산출물만 현재 디렉터리 아래 `{Project}_{Version}/` 하위 폴더에 남기고 임시 작업본은 정리합니다. 나머지 옵션은 [CLI 레퍼런스](../reference/cli.ko.md#옵션-레퍼런스)를 참고하세요.

## 산출물 4종

| 산출물 | 파일 | 의미 |
|--------|------|------|
| 적합성 보고서 | `{Project}_{Version}_conformance.{json,md,html}` | 품질 기준 충족 여부와 누락 항목 |
| SBOM(변환본) | `{Project}_{Version}_bom.json` | SPDX 입력은 CycloneDX 1.6으로 변환, CycloneDX 입력은 원본 spec 버전 유지 |
| 오픈소스 고지문 | `{Project}_{Version}_NOTICE.{txt,html}` | 라이선스별 구성요소 고지문 |
| 위험분석보고서 | `{Project}_{Version}_risk-report.{md,html}` | 적합성·취약점·라이선스 종합과 대응 기한 |

자체 생성 SBOM과 달리, 받은 SBOM에는 적합성 보고서가 추가로 생성되고 위험분석보고서 1절에 그 요약이 들어갑니다.

## 적합성 보고서 읽기

적합성 보고서는 받은 SBOM이 품질 기준을 갖췄는지 항목별로 점검한 결과입니다. 검증은 변환 전 원본을 기준으로 하므로, SPDX를 넣어도 원본 SPDX의 필드를 그대로 확인합니다.

- 필수 항목이 하나라도 미달이면 `fail`입니다. 필수 항목은 [언제 쓰나](#언제-쓰나)의 기준 표와 같습니다 — 스펙 버전 범위(CycloneDX v1.3~1.6, SPDX v2.2~2.3), timestamp, 도구 정보, 최상위 컴포넌트, name/version 커버리지, PURL 커버리지와 문법(표준 `pkg:type/name@version` 형식, `pkg:generic` 금지), 추이적 의존성. AI SBOM은 AIBOM 도구가 산출하는 CycloneDX 1.7도 허용합니다.
- 권장 항목(라이선스, hash 커버리지)이 미달이면 `warn`이며, `fail`로 보지는 않습니다.
- HTML 보고서 상단 카드에 적합/부적합과 누락 목록이 표시됩니다.

`fail`이 나오면 SBOM을 보낸 쪽에 어떤 필드가 빠졌는지 알려 보완을 요청합니다. 가장 흔한 미충족 항목은 PURL 누락, `pkg:generic` 사용, 추이적 의존성 누락(직접 의존성만 포함)입니다.

## 위험분석보고서 읽기

위험분석보고서(`_risk-report`)는 새로 스캔하지 않고 위의 산출물을 재집계해 만든 문서입니다. 네 부분으로 구성됩니다.

1. 요구사항 충족 — 적합성 결과 표. `fail`이면 미충족 항목을 명시합니다.
2. 취약점 집계와 대응 기한 — 심각도별 집계와 함께 권고 대응 기한(Critical 7일, High 30일 이내 대응 계획이나 위험 정당화 마련)을 표로 정리합니다.
3. 라이선스 요약 — 고지문과 라이선스 커버리지.
4. 다음 단계 — 대응 계획 안내.

## SPDX 입력

SPDX(JSON, Tag-Value)를 넣으면 내부에서 `syft convert`로 CycloneDX로 바꾼 뒤 동일한 파이프라인으로 분석합니다. 적합성 검증은 변환 전 SPDX 원본을 기준으로 합니다. 변환 과정에서 timestamp나 도구, 추이적 의존성 같은 메타데이터가 정규화되거나 사라질 수 있기 때문입니다. SPDX의 라이선스 표현 일부는 CycloneDX로 옮기면서 단순화될 수 있습니다.

## 보완 요청하기

검증과 분석이 끝나면 위험분석보고서(`_risk-report.html`)를 SBOM을 보낸 쪽에 전달하고 다음을 요청합니다.

- 적합성 `fail` 항목 보완 후 SBOM 재전달.
- Critical 취약점은 7일, High 취약점은 30일 이내에 대응 계획이나 위험 정당화 마련(권고 대응 기한).

대응 추적, 예외 승인, 이력 관리는 이 도구의 범위가 아니라 별도의 취약점·위험 관리 시스템의 몫입니다. 이 도구는 로컬에서 단일 SBOM을 검증하고 분석해 보고서를 만드는 데까지 담당합니다.

## 한계

- 검증은 필수 필드의 존재와 커버리지를 기준으로 합니다. PURL이 실제 패키지를 정확히 가리키는지, 버전이 진짜인지 같은 의미적 정확성까지는 보장하지 못합니다.
- 추이적 의존성 포함 여부는 의존성 그래프의 edge 유무로 추정하며, 그래프가 완전하다는 증명은 아닙니다.
- 취약점과 라이선스 분석의 정확도는 입력 SBOM의 품질, 특히 PURL과 버전 정확성에 직접 좌우됩니다.

---

> **관련 문서**: [시작하기](../start/first-scan.ko.md) | [시나리오 가이드](../guides/by-input.ko.md) | [고지문·보안 보고서 가이드](../guides/reports.ko.md)
