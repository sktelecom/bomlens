---
description: 공급사가 제출한 SBOM(CycloneDX/SPDX)이 요구사항을 충족하는지 BomLens로 검증하고, 라이선스와 취약점을 분석해 공급사에 보낼 위험 보고서를 만드는 방법.
---

# 공급사 SBOM 검증 가이드

공급사가 제출한 SBOM(JSON)이 제출 요구사항을 충족하는지 검증하는 방법을 설명합니다. 검증에 이어 라이선스와 취약점을 분석하고, 공급사에 보낼 위험 보고서까지 만듭니다. 소스 코드가 없어도 SBOM 파일 하나만 있으면 됩니다.

설계 배경과 검증 로직의 내부 동작은 메인테이너용 [공급사 제출 SBOM 검증·분석](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/supplier-sbom-analysis.md) 문서를 참고하세요.

## 언제 쓰나

공급사나 다른 팀이 소스 대신 SBOM 파일을 전달했고, 그 SBOM이 제출 기준을 갖췄는지 확인한 뒤 라이선스와 취약점을 점검해야 할 때 씁니다. 입력은 CycloneDX와 SPDX(JSON, Tag-Value) 모두 가능하며, 내부에서 CycloneDX로 변환해 분석합니다.

검증 기준은 SK텔레콤 [공급망 보안 가이드](https://sktelecom.github.io/guide/supply-chain/for-suppliers/)의 [SBOM 제출 요구사항](https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/)을 따릅니다.

| 구분 | 기준 |
|------|------|
| 포맷 | CycloneDX v1.3~1.6 또는 SPDX v2.2~2.3 |
| 필수 메타데이터 | timestamp, 생성 도구 정보, 최상위 컴포넌트 이름과 버전 |
| 필수 컴포넌트 필드 | name, version, PURL(`pkg:generic` 금지) |
| 완전성 | 직접 의존성과 추이적(transitive) 의존성 모두 포함 |
| 권장 | supplier, 라이선스(SPDX ID), hash |

## 한 번에 실행하기

### 웹 UI에서

웹 UI를 열고 **SBOM 업로드**를 골라 받은 파일을 올린 뒤, 프로젝트 이름과 버전을 입력하고 스캔을 실행합니다.

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

`--analyze`는 고지문과 보안 분석을 자동으로 켜므로 `--all`을 따로 붙일 필요가 없습니다. `--generate-only`는 산출물만 현재 디렉터리에 남기고 임시 작업본은 정리합니다. 나머지 옵션은 [사용 가이드](../reference/cli.ko.md#옵션-레퍼런스)를 참고하세요.

## 산출물 4종

| 산출물 | 파일 | 의미 |
|--------|------|------|
| 적합성 보고서 | `{Project}_{Version}_conformance.{json,md,html}` | 제출 기준 충족 여부와 누락 항목 |
| SBOM(변환본) | `{Project}_{Version}_bom.json` | 입력을 정규화한 CycloneDX 1.6 |
| 오픈소스 고지문 | `{Project}_{Version}_NOTICE.{txt,html}` | 라이선스별 구성요소 고지문 |
| 위험분석보고서 | `{Project}_{Version}_risk-report.{md,html}` | 적합성·취약점·라이선스 종합과 대응 기한 |

자체 생성 SBOM과 달리, 받은 SBOM에는 적합성 보고서가 추가로 생성되고 위험분석보고서 1절에 그 요약이 들어갑니다.

## 적합성 보고서 읽기

적합성 보고서는 받은 SBOM이 제출 기준을 갖췄는지 항목별로 점검한 결과입니다. 검증은 변환 전 원본을 기준으로 하므로, SPDX를 넣어도 원본 SPDX의 필드를 그대로 확인합니다.

- 필수 항목이 하나라도 미달이면 `fail`입니다. 필수 항목은 [언제 쓰나](#언제-쓰나)의 기준 표와 같습니다 — timestamp, 도구 정보, 최상위 컴포넌트, name/version 커버리지, PURL 커버리지(`pkg:generic` 금지), 추이적 의존성.
- 권장 항목(라이선스, hash 커버리지)이 미달이면 `warn`이며, 반려 사유는 아닙니다.
- HTML 보고서 상단 카드에 적합/부적합과 누락 목록이 표시됩니다.

`fail`이 나오면 공급사에 어떤 필드가 빠졌는지 알려 재제출을 요청합니다. 가장 흔한 반려 사유는 PURL 누락, `pkg:generic` 사용, 추이적 의존성 누락(직접 의존성만 제출)입니다.

## 위험분석보고서 읽기

위험분석보고서(`_risk-report`)는 새로 스캔하지 않고 위의 산출물을 재집계해 만든 공급사 전달용 문서입니다. 네 부분으로 구성됩니다.

1. 요구사항 충족 — 적합성 결과 표. `fail`이면 반려 사유를 명시합니다.
2. 취약점 집계와 대응 기한 — 심각도별 집계와 함께 Critical은 7일, High는 30일 안에 대응 계획이나 위험 정당화를 제출해야 한다는 기준을 표로 정리합니다.
3. 라이선스 요약 — 고지문과 라이선스 커버리지.
4. 다음 단계 — 대응 계획 제출 안내.

## SPDX 입력

SPDX(JSON, Tag-Value)를 넣으면 내부에서 `syft convert`로 CycloneDX로 바꾼 뒤 동일한 파이프라인으로 분석합니다. 적합성 검증은 변환 전 SPDX 원본을 기준으로 합니다. 변환 과정에서 timestamp나 도구, 추이적 의존성 같은 메타데이터가 정규화되거나 사라질 수 있기 때문입니다. SPDX의 라이선스 표현 일부는 CycloneDX로 옮기면서 단순화될 수 있습니다.

## 공급사에 보완 요청하기

검증과 분석이 끝나면 위험분석보고서(`_risk-report.html`)를 공급사에 전달하고 다음을 요청합니다.

- 적합성 `fail` 항목 보완 후 SBOM 재제출.
- Critical 취약점은 7일, High 취약점은 30일 안에 대응 계획이나 위험 정당화 제출.

전사 등록과 대응 추적, 이력 관리는 이 도구의 범위가 아니라 SKT 내부 시스템(TOSCA)과 포털의 몫입니다. 이 도구는 로컬에서 단일 SBOM을 검증하고 분석해 보고서를 만드는 데까지 담당합니다.

## 한계

- 검증은 필수 필드의 존재와 커버리지를 기준으로 합니다. PURL이 실제 패키지를 정확히 가리키는지, 버전이 진짜인지 같은 의미적 정확성까지는 보장하지 못합니다.
- 추이적 의존성 포함 여부는 의존성 그래프의 edge 유무로 추정하며, 그래프가 완전하다는 증명은 아닙니다.
- 취약점과 라이선스 분석의 정확도는 입력 SBOM의 품질, 특히 PURL과 버전 정확성에 직접 좌우됩니다.

---

> **관련 문서**: [시작하기](../start/first-scan.ko.md) | [시나리오 가이드](../guides/by-input.ko.md) | [고지문·보안 보고서 가이드](../guides/reports.ko.md)
