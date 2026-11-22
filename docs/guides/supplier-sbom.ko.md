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

위 표의 `pkg:generic` 금지 항목은 도구 자체의 기본값이 아니라 `skt-submission` 적합성 검사 기준(`--conformance-profile skt-submission`)입니다. 기본 검사 기준은 `pkg:generic`을 권고 사항으로만 다루고 PURL 포함률도 100%가 아니라 90%를 기준으로 삼습니다. 웹 UI의 제출 전 점검 화면은 이미 `skt-submission`을 기본값으로 쓰지만 CLI는 그렇지 않으므로, 이 표 기준으로 검사하려면 플래그를 직접 붙여야 합니다.

## 한 번에 실행하기

### 데스크톱 앱이나 웹 UI에서

데스크톱 앱이나 웹 UI를 열고(설치는 [첫 스캔](../start/first-scan.ko.md) 참고) **SBOM 업로드**를 골라 받은 파일을 올린 뒤, 프로젝트 이름과 버전을 입력하고 스캔을 실행합니다. Yocto SPDX 2.2 빌드는 문서가 아니라 `<image>.spdx.tar.zst`를 건네는데, 그 빌드가 만드는 유일한 SBOM이므로 이 아카이브도 그대로 올릴 수 있습니다.

Java(Maven) 비중이 큰 SBOM이라면 스캔 옵션에서 **심층 CVE 매칭 (NVD CPE)**을 켜세요. 오래된 Maven 라이브러리를 NVD 전용 취약점까지 대조해 다른 출처가 놓치는 항목을 찾아내며, 대신 스캔이 더 오래 걸립니다. CLI의 `--deep-cve`와 같은 매칭입니다. 어느 스캔 모드에서 이 옵션이 나타나는지, 처음 실행할 때 무엇을 내려받는지는 [정밀 CVE 대조](reports.ko.md#정밀-cve-대조---deep-cve)를 참고하세요.

### CLI에서

명령줄 없이 하고 싶다면 [비개발자 빠른 시작](../start/no-cli.ko.md)을 먼저 보세요. 아래는 CLI 기준입니다.

스캐너 이미지를 한 번 받아 두고(`docker pull ghcr.io/sktelecom/bomlens:latest`), 받은 SBOM 파일을 `--analyze`에 넘깁니다.

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

적합성 검사 보고서는 SBOM 자체의 항목을 선택한 검사 기준에 따라 한 행씩 점검합니다. SPDX 입력은 변환 전 원본 문서를 점검합니다. 이 화면의 통과와 실패는 선택한 적합성 검사 기준의 형식 요건에 대한 결과입니다. 법규 준수 여부를 판정하지 않습니다.

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

## Yocto 이미지

Yocto 빌드는 자체 SPDX SBOM을 만들 수 있고, BomLens는 이를 일반 SPDX 경로가 아니라 전용 파서로 읽습니다. Yocto 문서에는 일반 경로가 잃어버리는 정보가 두 가지 들어 있기 때문입니다.

SBOM을 만들려면 `local.conf`에 다음을 넣고 평소대로 빌드합니다.

```
INHERIT += "create-spdx-3.0"
INHERIT += "vex"
```

어떤 SPDX 버전을 만들 수 있는지는 릴리스마다 다릅니다.

| 릴리스 | 기본 SPDX | `create-spdx-3.0` 사용 |
|--------|-----------|------------------------|
| 4.0 Kirkstone (LTS) | 2.2 | **불가** — 이 릴리스에는 해당 클래스가 없습니다 |
| 5.0 Scarthgap (LTS) | 2.2 | 가능 |
| 5.1 Styhead 이후 | 3.0 | 가능(기본값) |

Kirkstone에서는 위 설정을 쓸 수 없습니다. 그 빌드는 SPDX 2.2를 만들고, 아래에 적은 방식으로 읽습니다.

그다음 빌드 디렉터리를 그대로 스캔 대상으로 지정합니다. 빌드가 SBOM을 어디에 두었는지 알 필요가 없습니다.

```bash
./scripts/scan-sbom.sh --project my-image --version 1.0.0 \
  --target ~/poky/build --generate-only
```

빌드 디렉터리로 인식하고, 빌드가 만든 이미지 SBOM인 `tmp/deploy/images/<machine>/<image>.rootfs.spdx.json`(OpenEmbedded 빌드는 `tmp-glibc/…`)을 분석합니다. 빌드 트리 자체는 훑지 않습니다. 디렉터리로 스캔하면 이미지에 들어가지 않는 sysroot와 빌드용 도구까지 결과에 섞이기 때문입니다.

머신이나 이미지를 여럿 빌드해 SBOM이 여러 개면 가장 최근에 쓰인 것을 분석하고 후보 전체를 로그에 남깁니다. 다른 것을 고르려면 `--analyze <파일>`로 직접 지정합니다. `DEPLOY_DIR`를 옮겨 이미지를 완전히 다른 위치에 쓰는 빌드도 이 방법으로는 찾지 못하니 같은 방식으로 지정합니다. SBOM 파일 하나만 받은 경우에는 그 파일을 웹 UI에 올리거나 `--analyze`로 넘기면 됩니다.

웹 UI도 같은 폴더를 읽습니다. 디렉터리 입력으로 그 폴더를 고르면 됩니다(`--ui --mount ~/poky/build`로 먼저 마운트하거나 데스크톱 앱의 폴더 추가 사용). 감지는 명령줄과 똑같이 동작합니다.

빌드 디렉터리 스캔의 적합성 검사 보고서는 빌드가 만든 문서가 아니라 스캔이 쓴 SBOM(`<Project>_<Version>_bom.json`)을 점검합니다. 제출할 파일이 이것이기 때문입니다. 이 SBOM에는 `bomlens:scanMode`로 `YOCTO`가 기록되고, `--conformance-profile skt-submission`에서는 펌웨어 스캔과 같은 방식으로 판정합니다. 의존 관계 그래프가 아니라 설치된 패키지를 기록하기 때문입니다. `--analyze`로 넘긴 Yocto 문서는 적힌 그대로 판정합니다.

이 SBOM은 스캔이 직접 만든 것이므로 다른 스캔이 만든 SBOM과 같은 방식으로 정보를 채웁니다. `--sbom-author`, `--supplier`, `--license`(`concluded`)를 기록하고, 도구 목록에 BomLens를, 수명 주기 단계로 `build`를 적습니다. 이미지는 빌드가 정한 이름을 그대로 두고 `bom-ref`를 받으며, 빌드가 버전을 적지 않았으면 `--version`을 받고, 설치된 모든 패키지에 의존하는 것으로 기록됩니다. 빌드가 생성 시각을 적지 않았으면(매니페스트에는 없음) 스캔 시각을 적습니다. 이 세 옵션을 주면 `bsi-tr-03183-2`의 SBOM 작성자, 의존 관계 그래프, 최상위 구성요소 항목이 통과할 수 있습니다. `--analyze`로 따로 넘긴 Yocto 문서는 다른 사람이 만든 SBOM이므로 이 처리를 하지 않습니다.

### 자체 레시피와 공급사 바이너리

빌드는 설치한 패키지를 모두 기록합니다. 사내 레시피와 칩 제조사의 바이너리 레시피도 여기에 들어 있지만, 어느 것이 자체개발이고 누가 공급했는지는 빌드 기록에 없습니다. 이 정보는 선언 파일에 적어 `--components`로 넘깁니다. 산출물 경로는 머신과 작업 디렉터리마다 다르므로, 구성요소에는 파일 경로 대신 `bomlens:yocto-recipe`에 레시피 이름(버전을 뺀 PN)을 적습니다.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "application",
      "name": "media-daemon",
      "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
      "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
      "properties": [
        { "name": "bomlens:origin", "value": "first-party" },
        { "name": "bomlens:yocto-recipe", "value": "media-daemon" }
      ]
    }
  ]
}
```

```bash
./scripts/scan-sbom.sh --project my-image --version 1.0.0 \
  --target ~/poky/build --components meta-example/sbom-declared.cdx.json
```

선언은 이미지에 설치된 그 레시피의 패키지 전부(예: `media-daemon`과 `media-daemon-cli`)에 적용됩니다. 각 패키지는 빌드가 기록한 이름, 버전, purl, CPE를 그대로 두고, 선언한 유형, 공급자, 라이선스(`concluded`), `bomlens:origin`을 받으며 `bomlens:declared`로 표시됩니다. SPDX 문서가 그 패키지에 기록한 파일은 해시, 파일 이름과 함께 패키지 아래 하위 구성요소로 들어갑니다. Yocto는 패키지가 아니라 파일 단위로 해시를 냅니다. SPDX 3.0은 SHA-256을, Yocto 6.1부터는 SHA-512도 기록하고, SPDX 2.2는 SHA-1과 SHA-256을 기록하며, 매니페스트에는 파일 목록이 없습니다. BomLens는 패키지 해시를 따로 만들지 않습니다. 그래서 `--conformance-profile bsi-tr-03183-2`에서는 빌드가 기록하지 않은 SHA-512와 파일 이름, Yocto 기록에 없는 파일 속성을 원본 SBOM에 없음으로 보고하고 경고로 표시합니다. `skt-submission`에서 자체개발 구성요소가 PURL 항목에서 빠지려면 SHA-512가 있어야 하므로, 6.1 이전 빌드에서는 자체 패키지에도 purl이 필요합니다(이 패키지의 `pkg:yocto` purl은 upstream 저장소가 없는 purl로 셉니다).

선언한 레시피가 이미지에 패키지를 하나도 설치하지 않았으면 스캔은 레시피 이름을 알리며 실패하고, 그때까지 만든 SBOM을 `<Project>_<Version>_bom.refused.json`으로 남깁니다. 레시피 선언에는 `bomlens:artifact`를 함께 적을 수 없고, 빌드가 정하는 `hashes`, `purl`, `cpe`도 적을 수 없습니다. 레시피도 파일도 없는 구성요소(예: 장치가 실행 중에 불러오는 바이너리)는 소스 스캔과 같은 방식으로 추가됩니다. 다만 이미지에 설치된 패키지와 이름이 같으면 거부하며, 그 패키지는 레시피로 선언합니다.

패키지는 빌드가 기록한 레시피로만 맞춥니다(SPDX 문서, SPDX가 없는 빌드에서는 `license.manifest`). 빌드가 레시피를 기록하지 않은 패키지는 이름이 같아도 맞추지 않으며, 거부 메시지에 그 패키지 이름이 나옵니다. 레시피의 멀티립과 SDK 변형(`lib32-media-daemon`, `nativesdk-media-daemon`)은 별도 레시피이므로 따로 선언하며, 이미지에 설치된 변형이 있으면 로그에 경고가 나옵니다. 선언은 `--target`으로 준 빌드 디렉터리에 적용됩니다. `--analyze`로 준 SBOM은 받은 SBOM이므로 바꾸지 않으며, `--components`와 함께 쓰면 거부합니다. 웹 UI에서는 아직 Yocto 레시피를 선언할 수 없습니다.

공급자만은 빌드에서 가져올 수도 있습니다. SPDX 3.0에서는 레이어에 레시피별로 다음과 같이 지정하고 다시 빌드합니다.

```
SPDX_PACKAGE_SUPPLIER_name:pn-media-daemon = "Example Corp"
SPDX_PACKAGE_SUPPLIER_type:pn-media-daemon = "organization"
```

Yocto는 이 값을 패키지의 `suppliedBy`로 기록하고, BomLens는 이를 공급자로 읽습니다. 다만 이름만 있고 BSI TR-03183-2가 제작자에 요구하는 URL이나 이메일은 없으며, 자체개발 여부도 표시하지 않습니다. 그래서 `bomlens:origin`은 여전히 선언 파일에 적습니다. SPDX 2.2는 `SPDX_SUPPLIER`를 기록하는데, 기본값이 실제 공급자가 아니라 OpenEmbedded이므로 BomLens는 이 값을 읽지 않습니다.

### SPDX를 전혀 만들지 않은 빌드

`create-spdx`를 켜는 것은 빌드 설정을 바꾸는 일이라, 완료된 빌드 디렉터리만 가진 사람은 그렇게 하지 못할 수 있습니다. 빌드는 SPDX가 없어도 무엇을 넣었는지 기록해 두므로, 그 기록을 대신 읽습니다.

| 파일 | 위치 | 얻는 정보 |
|------|------|-----------|
| 이미지 패키지 매니페스트 | `tmp/deploy/images/<machine>/<image>.manifest` | 설치된 패키지와 버전 |
| 라이선스 매니페스트 | `tmp/deploy/licenses/**/license.manifest` | 패키지별 라이선스와 출처 레시피 |
| cve-check 보고서 | `tmp/log/cve/cve-summary.json` | CVE별로 레시피가 패치했는지, 해당 없다고 판정했는지, 남았는지 |

세 가지 입력 중 가장 약한 경로이며, 이유를 알아 둘 만합니다. CPE가 없어 취약점 매칭이 패키지 이름과 버전에만 기댑니다. CVE 판정도 그 빌드가 실행한 `cve-check` 범위까지만 정확합니다(`cve-check`를 돌리지 않은 빌드는 판정이 없다고 보고하며, 없는 판정을 지어내지 않습니다). 적합성 검사 보고서는 다른 빌드 디렉터리 스캔처럼 이 기록에서 읽은 SBOM을 점검합니다. 위의 `local.conf` 두 줄을 넣고 다시 빌드하는 편이 여전히 낫습니다.

Yocto 빌드 디렉터리인데 SPDX 문서도 이미지 매니페스트도 없으면 디렉터리 스캔으로 넘어가지 않고 스캔을 멈춘 뒤 위 설정 두 줄을 안내합니다. 그대로 스캔하면 이미지 내용과 다른 결과가 나오기 때문입니다.

일반 SBOM 스캔과 결과가 세 가지 면에서 다릅니다.

구성 목록에는 이미지에 설치된 패키지만 담깁니다. Yocto 문서에는 빌드가 사용한 소스 압축 파일도 전부 기록되는데, 출처를 따질 때는 쓸모가 있지만 제품에 실제로 들어간 것과는 다릅니다. 그래서 목록에서 뺍니다.

취약점은 빌드가 판정한 결과를 그대로 씁니다. Yocto는 빌드하면서 CVE 분석을 돌리고 항목마다 판정을 기록하므로 레시피가 패치를 적용했는지 압니다. 그 판정을 빌드에서 패치한 것, 해당 없다고 판정한 것, 아직 남은 것 세 가지로 나눠 보여주고 남은 것만 발견 항목으로 셉니다. 기준 이미지인 `core-image-minimal`에서는 이 차이가 취약점 12255건을 보고하느냐 한 건도 없다고 보고하느냐를 가릅니다. 전부 빌드에서 이미 닫혔기 때문입니다.

컴포넌트에는 펌웨어 스캔과 같이 upstream 저장소 purl이 붙습니다. 패키지를 만든 레시피나, SPDX 2.2라면 레시피의 소스 내려받기 주소로 BomLens가 프로젝트를 알아낼 수 있는 경우입니다. 어떤 프로젝트를 다루는지는 [upstream 저장소 purl](firmware.ko.md#upstream-저장소-purl)을 참고하세요.

시작하기 전에 알아 둘 한계가 두 가지 있습니다.

SPDX 2.2도 읽지만 담기는 정보가 적습니다. Yocto 4.0 Kirkstone과 5.0 Scarthgap은 기본값이 SPDX 2.2인데, 이 형식은 문서 하나가 아닙니다. deploy 디렉터리에는 `<image>.spdx.tar.zst` 하나만 놓이고, 그 안에 이미지 문서와 설치 패키지별 문서, 레시피별 문서가 들어 있습니다. BomLens는 이 아카이브를 직접 읽습니다. 공개된 Yocto 5.0.14 `core-image-minimal`로 확인한 결과, 이미지 매니페스트가 나열한 36개 패키지를 라이선스와 CPE까지 그대로 얻었습니다.

없는 것은 빌드의 CVE 판정입니다. 레시피가 어떤 CVE를 패치했는지는 SPDX 3.0에만 기록되므로, `--security`를 켜면 취약점을 이미지에 들어 있는 NVD CPE 인덱스와 CPE로 대조합니다(벤더가 `*`인 CPE는 모든 벤더에서 제품명으로 찾으므로, 다른 프로젝트와 제품명이 같으면 그 프로젝트의 CVE도 나올 수 있음). 그래서 빌드가 이미 패치한 CVE가 열린 것으로 보일 수 있습니다. 아카이브에서 이미지 문서만 꺼내 따로 올리면 결과가 거의 비는데, 이때는 깨끗한 스캔처럼 보이게 두지 않고 그 사실을 알려 줍니다. 빌드 디렉터리에 두 형식이 함께 있으면 2.2 쪽이 더 최근이더라도 SPDX 3.0 문서를 분석합니다. `--analyze`로 넘긴 아카이브는 적합성 검사 보고서를 만들지 않습니다. 아카이브는 제출된 문서가 아니라 문서 묶음이라, 제출 기준과 대조할 대상이 아니기 때문입니다. 빌드 디렉터리에서 찾은 아카이브라면 거기서 읽은 SBOM을 대신 점검합니다.

PURL에 기대는 적합성 항목은 실패합니다. Yocto는 패키지를 PURL이 아니라 CPE로 식별하므로 PURL 적용률과 거기서 파생되는 항목은 통과할 수 없습니다. 보고서에는 몇 개가 CPE로 식별됐는지 함께 적히고, 그 행 아래에 두 식별자를 모두 인정하는 기준(BSI TR-03183-2, 미국 SBOM 최소 요소)이 표시됩니다. 즉 이 판정은 기준이 아니라 제출 요구사항의 것입니다. 기본 취약점 매칭이 PURL을 키로 쓰기 때문에 여기서는 PURL을 요구합니다.

필수 항목 하나가 더 실패하는데, 도구가 아니라 문서 쪽 사정입니다. 최상위 컴포넌트가 버전이 없어 실패합니다. bitbake가 이미지 패키지에 이름만 쓰고 `software_packageVersion`을 넣지 않습니다(기준 이미지 `core-image-minimal`에서 확인). 빌드 디렉터리를 스캔하면 이미지가 대신 `--version`을 받습니다.

업로드 크기는 100MB까지 받습니다. 참고로 기준 이미지인 `core-image-minimal` 문서는 설치 패키지 35개에 15.8MB입니다. `--target`으로 빌드 디렉터리를 스캔할 때는 디스크에서 파일을 읽으므로 이 제한이 적용되지 않습니다.

## 보완 요청하기

검증과 분석이 끝나면 오픈소스 위험 보고서(`_risk-report.html`)를 SBOM을 보낸 쪽에 전달하고 다음을 요청합니다.

- 적합성 `fail` 항목 보완 후 SBOM 재전달.

`--analyze`로 만든 적합성 보고서 끝에는 "공급사에 보낼 문장" 절이 있습니다. 실패한 항목마다(그리고 구성요소를 짚는 경고마다) 해당 구성요소 이름과 고치는 방법을 한 문장으로 적어 두므로, 요청문에 그대로 붙여 넣으면 됩니다. 실패한 항목은 보고서 안에 보완 방법도 따로 있고, 최상위 구성요소의 이름이나 버전이 없으면 그 사실을 문장으로 알립니다.
- Critical 취약점은 7일, High 취약점은 30일 이내에 대응 계획이나 위험 정당화 마련(권고 대응 기한).

대응 추적, 예외 승인, 이력 관리는 이 도구의 범위가 아니라 별도의 취약점·위험 관리 시스템의 몫입니다. 이 도구는 로컬에서 단일 SBOM을 검증하고 분석해 보고서를 만드는 데까지 담당합니다.

## 한계

- 검증은 필수 필드의 존재와 커버리지를 기준으로 합니다. PURL이 실제 패키지를 정확히 가리키는지, 버전이 진짜인지 같은 의미적 정확성까지는 보장하지 못합니다.
- 추이적 의존성 포함 여부는 의존성 그래프의 edge 유무로 추정하며, 그래프가 완전하다는 증명은 아닙니다.
- 취약점과 라이선스 분석의 정확도는 입력 SBOM의 품질, 특히 PURL과 버전 정확성에 직접 좌우됩니다.

---

> **관련 문서**: [첫 스캔](../start/first-scan.ko.md) | [시나리오 가이드](../guides/by-input.ko.md) | [고지문·보안 보고서 가이드](../guides/reports.ko.md) | [보고서 읽는 법](../concepts/reports-explained.ko.md)
