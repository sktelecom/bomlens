---
description: 외부에서 받은 SBOM(CycloneDX/SPDX)이 요구사항을 충족하는지 BomLens로 검증하고, 라이선스와 취약점을 분석해 위험 보고서를 만드는 방법.
---

# 공급사 SBOM 검증 가이드

협력사나 다른 팀에서 받은 SBOM(JSON)이 요구사항을 충족하는지 검증하는 방법을 설명합니다. 검증에 이어 라이선스와 취약점을 분석하고, 위험 보고서까지 만듭니다. 소스 코드가 없어도 SBOM 파일 하나만 있으면 됩니다.

## 직접 만든 SBOM을 제출할 때

SK텔레콤에 소프트웨어를 납품하는 공급사라면, SBOM을 보내기 전에 제출 기준을 충족하는지 확인합니다.

1. 스캔할 때 적합성 검사 기준을 SKT 제출 기준으로 고릅니다. 데스크톱 앱이나 웹 UI에서는 스캔 설정의 **출력 형식**을 열고 **적합성 검사 기준**을 SKT 제출 기준으로 바꿉니다. CLI에서는 `--conformance-profile skt-submission`을 붙입니다. 기본 검사 기준은 바뀌지 않으므로 스캔할 때마다 고릅니다.
2. 결과에서 **적합성 검사**를 엽니다. 실패하면 실패한 항목이 알려 주는 내용을 고치고 다시 스캔합니다([적합성 검사 보고서 읽기](#적합성-검사-보고서-읽기)).
3. 통과하면 결과 폴더의 `{Project}_{Version}_bom.json` 하나만 제출합니다. 나머지 파일은 직접 검토할 때 씁니다.

## 언제 쓰나

협력사나 다른 팀이 소스 대신 SBOM 파일을 전달했고, 그 SBOM이 품질 기준을 갖췄는지 확인한 뒤 라이선스와 취약점을 점검해야 할 때 씁니다. 입력은 CycloneDX(JSON, XML)와 SPDX(JSON, Tag-Value) 모두 가능하며, 내부에서 CycloneDX로 변환해 분석합니다. SPDX RDF/XML은 아직 지원하지 않습니다.

BomLens는 SK텔레콤의 공급사 SBOM 제출을 위해 만든 도구이며, 아래 표는 그 요구사항을 따릅니다. 검증 기준은 SBOM이 의존성 점검에 쓸 만한 품질을 갖췄는지를 보는 항목들입니다. 조직마다 요구사항이 다를 수 있으니, 참고 사례로 SK텔레콤 [공급망 보안 가이드](https://sktelecom.github.io/guide/supply-chain/for-suppliers/)의 [SBOM 요구사항](https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/)을 둘 수 있습니다.

| 구분 | 기준 |
|------|------|
| 포맷 | CycloneDX v1.3~1.7 또는 SPDX v2.2~2.3 |
| 필수 메타데이터 | timestamp, 생성 도구 정보, 최상위 컴포넌트 이름과 버전 |
| 필수 컴포넌트 필드 | name, version, 표준 `pkg:type/name@version` 형식의 PURL. 타입이 요구하는 네임스페이스 포함(`pkg:maven/<groupId>/<artifactId>`, `pkg:rpm/<배포판>/<이름>`), purl-spec에 정의된 타입 사용, `pkg:generic` 금지 |
| 완전성 | 직접 의존성과 추이적(transitive) 의존성 모두 포함 |
| 권장 | supplier, 라이선스(SPDX ID), hash |

> 위 허용 포맷 범위는 SK텔레콤 제출 기준의 기본값입니다. 조직이 다른 범위를 허용한다면 `CYCLONEDX_SPEC_VERSIONS`, `AI_CYCLONEDX_SPEC_VERSIONS`(AI SBOM), `SPDX_SPEC_VERSIONS` 환경 변수(공백으로 구분한 목록)로 덮어쓸 수 있습니다. 목록은 [Docker 이미지 환경 변수](../reference/docker-image.ko.md)에 있습니다.

위 표의 `pkg:generic` 금지 항목은 기본 검사 기준이 아니라 `skt-submission` 기준에서 나옵니다. 기본 기준은 `pkg:generic`을 권고 사항으로만 다루고 PURL 포함률도 100%가 아니라 90%를 기준으로 삼습니다. 웹 UI의 SBOM 업로드는 바꾸지 않으면 `skt-submission`을 쓰고, CLI는 `--conformance-profile skt-submission`을 붙여야 합니다.

## 한 번에 실행하기

### 데스크톱 앱이나 웹 UI에서

데스크톱 앱이나 웹 UI를 열고(설치는 [첫 스캔](../start/first-scan.ko.md) 참고) **SBOM 업로드**를 골라 받은 파일을 올린 뒤, 프로젝트 이름과 버전을 입력하고 스캔을 실행합니다. Yocto SPDX 2.2 빌드는 문서가 아니라 `<image>.spdx.tar.zst`를 건네는데, 그 빌드가 만드는 유일한 SBOM이므로 이 아카이브도 그대로 올릴 수 있습니다.

Java(Maven) 비중이 큰 SBOM이라면 스캔 옵션에서 **심층 CVE 매칭 (NVD CPE)**을 켜세요. 오래된 Maven 라이브러리를 NVD 전용 취약점까지 대조해 다른 출처가 놓치는 항목을 찾아내며, 대신 스캔이 더 오래 걸립니다. CLI의 `--deep-cve`와 같은 매칭입니다. 어느 스캔 모드에서 이 옵션이 나타나는지, 처음 실행할 때 무엇을 내려받는지는 [정밀 CVE 대조](reports.ko.md#정밀-cve-대조---deep-cve)를 참고하세요.

### CLI에서

명령줄 없이 하고 싶다면 [비개발자 빠른 시작](../start/no-cli.ko.md)을 먼저 보세요. 아래는 CLI 기준입니다.

받은 SBOM 파일을 `--analyze`에 넘깁니다. 스캐너 이미지는 첫 스캔이 알아서 받습니다.

```bash
./scripts/scan-sbom.sh --project supplier-app --version 2.0.0 \
  --analyze "./supplier-sbom.json" \
  --conformance-profile skt-submission \
  --generate-only
```

`--analyze`는 고지문과 보안 분석을 자동으로 켜므로 `--all`을 따로 붙일 필요가 없습니다. `--generate-only`는 산출물만 현재 디렉터리 아래 `{Project}_{Version}/` 하위 폴더에 남기고 임시 작업본은 정리합니다. 나머지 옵션은 [CLI 레퍼런스](../reference/cli.ko.md#옵션-레퍼런스)를 참고하세요.

## 산출물 4종

| 산출물 | 파일 | 의미 |
|--------|------|------|
| 적합성 검사 보고서 | `{Project}_{Version}_conformance.{json,md,html}` | 품질 기준 충족 여부와 누락 항목 |
| SBOM(변환본) | `{Project}_{Version}_bom.json` | SPDX 입력은 CycloneDX 1.6으로 변환, CycloneDX 입력은 원본 spec 버전 유지 |
| 오픈소스 고지문 | `{Project}_{Version}_NOTICE.{txt,html}` | 라이선스별 구성요소 고지문 |
| 오픈소스 위험 보고서 | `{Project}_{Version}_risk-report.{md,html}` | 적합성·취약점·라이선스 종합과 대응 기한 |

자체 생성 스캔도 이제 기본으로 같은 적합성 검사 보고서 파일을 만듭니다([입력 시나리오별 처리](by-input.ko.md#4종-산출물) 참고). 어느 쪽이든 그 요약은 오픈소스 위험 보고서 1절에 들어갑니다. 웹 UI는 두 경우 모두 결과를 **적합성 검사**에 보여 주며, 어떤 검사 기준으로 판정했는지도 함께 표시합니다.

## 적합성 검사 보고서 읽기

적합성 검사 보고서는 SBOM 자체의 항목을 선택한 검사 기준에 따라 한 행씩 점검합니다. SPDX 입력은 변환 전 원본 문서를 점검합니다. 이 화면의 통과와 실패는 선택한 적합성 검사 기준의 형식 요건에 대한 결과입니다. 법규 준수 여부를 판정하지 않습니다. 화면의 판정은 통과 또는 실패로 표시되고, 아래의 `fail`과 `warn`은 보고서 파일에 적히는 값입니다.

- 필수 행이 미달이면 `fail`이고, `fail`이 하나라도 있으면 SBOM 전체가 실패입니다.
- 권장 행이 미달이면 `warn`이며 판정을 바꾸지 않습니다.
- SBOM을 보낸 쪽에 `fail` 항목을 고쳐 다시 보내 달라고 요청합니다. 가장 흔한 것은 PURL 누락, `pkg:generic` 사용, 표시 이름으로 만들어 네임스페이스가 빠진 PURL, 추이적 의존성 누락입니다.

| 행 | 기본 기준 | `skt-submission` |
|----|-----------|------------------|
| 스펙 버전(CycloneDX v1.3~1.7, SPDX v2.2~2.3), timestamp, 도구 정보 | `fail` | `fail` |
| 최상위 컴포넌트 이름과 버전 | `fail`. `.`이나 `/scan` 같은 고정 이름은 `warn` | `fail` |
| 패키지 컴포넌트의 name/version 포함률(100%) | `fail` | `fail` |
| PURL 포함률 | 90% 미만이면 `fail` | 100% 미만이면 `fail` |
| PURL 문법과 타입이 요구하는 네임스페이스(`pkg:maven/<groupId>/...`) | `fail` | `fail` |
| `pkg:generic` | `warn` | `fail` |
| purl-spec에 정의된 PURL 타입 | `warn` | `fail` |
| OS 패키지 네임스페이스가 배포판인지, 버전 값이 버전인지 | `warn` | `fail` |
| 추이적 의존성 | `fail` | `fail` |
| 버전 보충 필요(버전이나 공급사 사유) | 검사하지 않음 | `fail` |
| upstream purl 없음 | 검사하지 않음 | `warn` |
| 라이선스, hash 등 컴포넌트별 필드, 2026년 최소 요소 | `warn` | `warn` |

`skt-submission`에서 펌웨어, 루트 파일시스템, 바이너리, Yocto 빌드 스캔은 일부 행을 `warn`으로 완화합니다. 그 조건과 자체개발 구성요소 예외, `--resolve-purl`, 수정 제안, 검사하지 않는 항목은 [산출물 레퍼런스](../reference/artifacts.ko.md#적합성-검사-보고서)에 있습니다.

## 오픈소스 위험 보고서 읽기

오픈소스 위험 보고서(`_risk-report`)는 새로 스캔하지 않고 위의 산출물을 재집계해 만든 문서입니다. 네 부분으로 구성됩니다.

1. 요구사항 충족 — 적합성 결과 표. `fail`이면 미충족 항목을 명시합니다.
2. 취약점 집계와 대응 기한 — 심각도별 집계와 함께 권고 대응 기한(Critical 7일, High 30일 이내 대응 계획이나 위험 정당화 마련)을 표로 정리합니다.
3. 라이선스 요약 — 고지문과 라이선스 커버리지.
4. 다음 단계 — 대응 계획 안내.

## SPDX 입력

CycloneDX XML 문서는 검증 전에 CycloneDX JSON으로 다시 쓰며, 컴포넌트 해시와 루트 컴포넌트, 루트에서 이어지는 의존성 연결은 그대로 보존합니다. services, vulnerabilities, pedigree, evidence 절은 옮기지 않으며 건너뛴 절은 스캔 로그에 이름이 남습니다. DTD나 엔티티를 선언한 문서는 거부합니다. SPDX(JSON, Tag-Value)를 넣으면 내부에서 `syft convert`로 CycloneDX로 바꾼 뒤 동일한 파이프라인으로 분석합니다. 적합성 검증은 변환 전 SPDX 원본을 기준으로 합니다. 변환 과정에서 timestamp나 도구, 추이적 의존성 같은 메타데이터가 정규화되거나 사라질 수 있기 때문입니다. SPDX의 라이선스 표현 일부는 CycloneDX로 옮기면서 단순화될 수 있습니다.

Yocto SPDX 문서와 Yocto 빌드 디렉터리는 전용 파서로 읽습니다. [Yocto 빌드 SBOM 가이드](yocto.ko.md)를 참고하세요.

## 보완 요청하기

검증과 분석이 끝나면 오픈소스 위험 보고서(`_risk-report.html`)를 SBOM을 보낸 쪽에 전달하고 다음을 요청합니다.

- 적합성 `fail` 항목 보완 후 SBOM 재전달.
- Critical 취약점은 7일, High 취약점은 30일 이내에 대응 계획이나 위험 정당화 마련(권고 대응 기한).

`--analyze`로 만든 적합성 보고서 끝에는 "공급사에 보낼 문장" 절이 있습니다. 실패한 항목마다(그리고 구성요소를 짚는 경고마다) 해당 구성요소 이름과 고치는 방법을 한 문장으로 적어 두므로, 요청문에 그대로 붙여 넣으면 됩니다. 실패한 항목은 보고서 안에 보완 방법도 따로 있고, 최상위 구성요소의 이름이나 버전이 없으면 그 사실을 문장으로 알립니다.

대응 추적, 예외 승인, 이력 관리는 이 도구의 범위가 아니라 별도의 취약점·위험 관리 시스템의 몫입니다. 이 도구는 로컬에서 단일 SBOM을 검증하고 분석해 보고서를 만드는 데까지 담당합니다.

## 한계

- 검증은 필수 필드의 존재와 커버리지를 기준으로 합니다. PURL이 실제 패키지를 정확히 가리키는지, 버전이 진짜인지 같은 의미적 정확성까지는 보장하지 못합니다.
- 추이적 의존성 포함 여부는 의존성 그래프의 edge 유무로 추정하며, 그래프가 완전하다는 증명은 아닙니다.
- 취약점과 라이선스 분석의 정확도는 입력 SBOM의 품질, 특히 PURL과 버전 정확성에 직접 좌우됩니다.

---

> **관련 문서**: [첫 스캔](../start/first-scan.ko.md) | [시나리오 가이드](../guides/by-input.ko.md) | [고지문·보안 보고서 가이드](../guides/reports.ko.md) | [보고서 읽는 법](../concepts/reports-explained.ko.md)
