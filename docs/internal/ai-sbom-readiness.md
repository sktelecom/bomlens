# AI SBOM 대응 준비 (AI SBOM Readiness)

> **관련 문서**: [방향성 조사 보고서](direction-study.md) | [공급사 SBOM 검증·분석](supplier-sbom-analysis.md) | [개선 로드맵](improvement-roadmap.md) | [외부 등록 채널](seo-external-listings.md)
>
> 성격: 메인테이너용 조사·전략 문서입니다. 코드 변경 없이, AI SBOM 규제·가이드가 BomLens에 요구하는 바와 우리가 준비할 항목, 필요한 도구를 정리합니다. 구체적 구현은 이 문서로 방향을 합의한 뒤 별도로 진행합니다.

## 요약 (Executive Summary)

2025년 하반기부터 AI 시스템을 위한 SBOM 요구가 규제와 산업 가이드 양쪽에서 구체화되었습니다. 세 건의 1차 자료를 검토했습니다.

- **OpenChain AI SBOM 컴플라이언스 가이드 v1.0** (2025-10-20). ISO/IEC 5230(오픈소스 라이선스 컴플라이언스)을 AI 공급망으로 확장한 컴플라이언스 프로그램입니다. 추적 대상을 코드에서 모델 가중치, 학습 데이터셋, 모델 트리까지 넓힙니다.
- **G7 AI SBOM 최소요소** (2026-05-12, 독일 BSI·이탈리아 ACN 주도). 7개 클러스터로 구성된 데이터 필드 명세입니다. 비구속 권고이지만 향후 공공 조달과 EU 규제의 참조점이 될 가능성이 높습니다.
- **OpenChain-KWG AI SBOM 가이드**. 위 v1.0의 운영 안내로, 4단계 구축 로드맵과 도구 성숙도 평가를 담습니다.

세 자료 모두 구현 매개로 **CycloneDX ML-BOM(modelCard)** 과 **SPDX 3.0 AI/Dataset Profile** 두 포맷을 지목합니다. 또한 라이선스 의무 해석은 도구가 자동 보장할 수 없고 사람과 정책이 맡아야 한다고 공통으로 짚습니다.

BomLens는 현재 CycloneDX 1.6 기반 소프트웨어 SBOM 도구로, 모델·데이터셋·modelCard·ML-BOM을 다루지 않습니다. `component.type`은 application/library/file/firmware만 씁니다. 다만 재사용할 수 있는 기반은 탄탄합니다. PURL→CPE 변환, 라이선스 정규화 단일 소스, 적합성 검증(conformance), 외부 SBOM 검증·변환(ANALYZE 모드), 고지문·위험 보고서, 웹 UI 탭 구조가 그것입니다.

권고하는 우선 역량은 세 가지입니다. AIBOM 생성 모드, G7 최소요소 적합성 검사, 모델·데이터셋 라이선스 검토입니다. 착수 순서는 의존이 가장 적은 적합성 검사부터입니다. 출력 포맷은 AI 경로만 CycloneDX 1.7로 내보내고(1.7 modelCard가 EU AI Act 기술문서에 맞춰 설계됨) 소프트웨어 SBOM은 1.6을 유지합니다. 자세한 근거는 4절에 있습니다.

---

## 목차
- [1. 배경과 범위](#1-배경과-범위)
- [2. 세 자료 요구사항 요약](#2-세-자료-요구사항-요약)
- [3. BomLens 갭 분석](#3-bomlens-갭-분석)
- [4. 포맷 비교와 권고](#4-포맷-비교와-권고)
- [5. 필요 도구 평가](#5-필요-도구-평가)
- [6. 우선 역량 3종 로드맵](#6-우선-역량-3종-로드맵)
- [7. UI/UX 구현 방향](#7-uiux-구현-방향)
- [8. 도구로 해결되지 않는 영역](#8-도구로-해결되지-않는-영역)
- [9. 권고 요약과 다음 단계](#9-권고-요약과-다음-단계)

---

## 1. 배경과 범위

세 자료는 성격이 서로 다릅니다. 이 차이를 먼저 구분해야 BomLens가 무엇을 맡을지 정할 수 있습니다.

- G7 최소요소는 "무엇을 기록할 것인가"를 정하는 데이터 필드 명세입니다. 도구가 직접 채우거나 검사할 대상입니다.
- OpenChain 가이드는 "조직이 무엇을 입증할 것인가"를 정하는 컴플라이언스 프로그램입니다. 대부분 정책·절차·거버넌스이며 도구가 일부만 거듭니다.
- OpenChain-KWG 가이드는 위 프로그램의 실행 안내로, 도구 성숙도와 구축 단계를 제시합니다.

규제 타임라인이 이 작업의 시급성을 정합니다. EU 인공지능법(AI Act)의 고위험 의무와 투명성 의무가 2026-08-02부터 본격 적용되며, Annex IV 기술문서 요구가 G7 클러스터와 상당 부분 겹칩니다. 사이버 복원력법(CRA)은 일반 SBOM 작성을 직접 명령하므로, AI 요소는 일반 SBOM 위에 누적되는 2층 구조로 대응할 수 있습니다. BomLens는 이미 일반 SBOM 층을 담당하므로, AI 층을 더하면 이 2층 구조에 자연스럽게 들어맞습니다.

이 문서가 답하는 질문은 셋입니다. 세 자료가 BomLens에 무엇을 요구하는가, 현재 무엇이 있고 무엇이 없는가, 어떤 도구로 결손을 메울 것인가.

## 2. 세 자료 요구사항 요약

### 2.1 OpenChain AI SBOM 컴플라이언스 가이드 (10개 요구사항)

ISO/IEC 5230과 동일하게 요구사항에서 검증자료, 근거로 이어지는 구조를 따르며, 3.1부터 3.10까지 열 개 조항에 19개 입증자료를 둡니다. 도구 관점에서 핵심은 세 조항입니다.

- **3.5 라이선스 의무**. 코드뿐 아니라 모델 가중치와 학습 데이터셋의 라이선스까지 검토합니다. RAIL, Llama 커뮤니티 라이선스처럼 행동 사용 제한을 담은 비표준 라이선스를 추적해야 합니다.
- **3.6 투명성 의무**. 생성 프로세스와 학습 데이터 출처·특성을 문서화합니다.
- **3.9 AI SBOM**. 포맷을 강제하지 않되 AI SBOM의 생성·관리 절차를 갖춥니다. 식별하고 추적·검토·승인한 뒤 보관하는 흐름입니다.

나머지 조항(정책, 역량, 인지, 범위, 접근, 자원, 거버넌스)은 조직 운영 영역으로, 도구가 아니라 사람과 프로세스가 충족합니다.

### 2.2 G7 AI SBOM 최소요소 (7개 클러스터)

| 클러스터 | 요소 수 | 도구 관점의 핵심 |
|---|---|---|
| 메타데이터 | 10 | 작성자, 버전, 서명, 타임스탬프, 생성 맥락(빌드 전/빌드/빌드 후) |
| 시스템 수준 속성 | 9 | 데이터 흐름, 입출력, 외부 API, 에이전트 통신, 웹 그라운딩 |
| 모델 | 13 | 식별자, 무결성 해시, 학습 속성, 개방성 4축 |
| 데이터셋 속성 | 10 | 출처, 민감도(PII·저작권), 수집 방법(크롤링·상업계약·합성) |
| 인프라 | 2 | 소프트웨어 의존성, HBOM 링크 |
| 보안 속성 | 4 | 암호화, AI 특화 통제, 취약점 참조 |
| 핵심성과지표 | 2 | 보안 벤치마크, 운영 지표 |

특히 모델 개방성을 open weight, open architecture, open data, open training 네 축으로 분해해 무엇이 공개되었는지 구체적으로 표시하도록 요구합니다. 식별자는 CPE·PURL을 우선하고 UUID·커밋 해시·OmniBOR·SWHID를 허용합니다. 해시는 NIST 승인 알고리즘, 서명은 FIPS 186-5 등 승인 메커니즘, 타임스탬프는 RFC 9557을 권고합니다. 에이전트 자율성(autonomy)은 관할마다 안전 요건이 달라 별도 항목으로 넣지 않았습니다.

전문가 평가는 "최소 요소는 가시성을 만들지만 보증을 만들지 않는다"는 것입니다. 특히 KPI와 보안 속성 클러스터는 조직 간 일관된 측정 기준이 아직 부족합니다.

### 2.3 OpenChain-KWG 운영 가이드 (4단계 + 도구 성숙도)

구축을 네 단계로 안내합니다. 프로그램 기반 수립, AI 확장 프로세스(라이선스·투명성 의무), 운영 체계, 거버넌스입니다. 도구 성숙도 평가가 BomLens에 시사점을 줍니다. 코드·의존성 SBOM 생성과 LLM·AI 패키지 식별, SBOM 저장·취약점 모니터링은 성숙 단계이고, AI 모델 BOM 생성과 모델 바이너리 정적 분석은 도구가 막 등장한 단계이며, 라이선스 의무 해석은 미성숙으로 사람과 정책이 필요하다고 봅니다.

## 3. BomLens 갭 분석

### 3.1 재사용 가능한 기존 자산

AI SBOM으로 확장할 때 새로 만들지 않고 활용할 수 있는 부분입니다.

| 자산 | 위치 | AI SBOM에서의 쓸모 |
|---|---|---|
| PURL→CPE 변환 | `docker/lib/normalize-sbom.sh` `VENDORED_CPE_FIX`(L66), `docker/lib/vendored-purl-map.json` | G7의 CPE·PURL 식별자 요구에 직접 대응. 모델 컴포넌트의 CVE 연결에 재사용 |
| 라이선스 정규화 단일 소스 | `docker/lib/spdx-normalize.jq` | 모델·데이터셋 라이선스 검토의 토대. 비표준 라이선스 매핑 확장 지점 |
| 적합성 검증 | `docker/lib/validate-sbom.sh`, `_conformance.{json,md,html}` 산출 | G7 최소요소 검사의 확장 지점 |
| 외부 SBOM 검증·변환 | ANALYZE 모드(`docker/entrypoint.sh` L201-214), `docker/lib/convert-to-cdx.sh` | 외부에서 받은 AIBOM 입력 검증에 재사용 |
| 고지문·위험 보고서 | `docker/lib/generate-notice.sh`, `docker/lib/generate-risk-report.sh` | 개방성 4축, 비표준 라이선스 표기 출력 지점 |
| 웹 UI 탭 구조 | `docker/web/frontend/src/components/ResultDashboard.tsx` 외 | 모델·데이터셋 뷰 추가 지점 |
| 2단계 아키텍처 | 1단계 생성(cdxgen/syft), 2단계 후처리(normalize·notice·security·risk) | AIBOM 생성 엔진을 1단계에 끼우면 후처리를 그대로 재사용 |

### 3.2 핵심 결손

구현이 필요한 부분입니다.

- modelCard·ML-BOM 컴포넌트 타입을 다루지 않습니다. 생성, 정규화, UI 전 구간에 걸칩니다.
- 모델·데이터셋을 입력으로 받는 모드가 없습니다. HuggingFace 모델 디렉토리, GGUF, Modelfile 입력 경로가 없습니다.
- 개방성 4축, 데이터셋 출처·민감도(PII·저작권), 시스템 데이터 흐름(에이전트 통신·웹 그라운딩) 필드를 채우지 못합니다.
- G7 7클러스터를 검사하는 적합성 룰셋이 없습니다.

요약하면 후처리·검증·출력·UI 기반은 갖췄고, AI 고유의 입력 수집과 필드 생성, AI 전용 적합성 룰이 비어 있습니다.

## 4. 포맷 비교와 권고

AIBOM은 소프트웨어 SBOM과 별도 출력 파일이므로, 진짜 선택지는 CycloneDX 1.6과 1.7 사이입니다. AI 경로만 1.7로 내보내도 소프트웨어 경로(1.6)와 한 파일에 섞이지 않습니다. SPDX 3.0 AI Profile은 그다음 대안입니다.

| 기준 | CycloneDX 1.6 ML-BOM | CycloneDX 1.7 ML-BOM |
|---|---|---|
| modelCard 성숙도 | 부분 목록 수준 | 커뮤니티 모델 카드 형식을 반영한 완전한 투명성 산출물 |
| EU AI Act 적합 | 약함 | 기술문서 요구 충족을 명시적 목표로 설계 |
| 표준 위상 | ECMA-424 1판(2024-06) | ECMA-424 2판(2025-10), 1.x 최종판 |
| 파이프라인 영향 | 기존 1.6 그대로 | AI 출력만 1.7(별도 파일), 소프트웨어는 1.6 유지 |
| 생성 도구 | cdxgen `aibom` 출력 | cdxgen `aibom` 출력(specVersion은 확장 시 확인) |
| 식별자 | PURL·CPE 1급, 기존 PURL→CPE 재사용 | 동일 |

권고는 **AI 경로만 CycloneDX 1.7**입니다. 이 작업의 동기가 EU AI Act·G7 정합성인데, 1.7 modelCard가 바로 그 목적에 맞춰 설계됐고 1.6은 부분 목록에 그칩니다. AIBOM은 별도 파일이라 소프트웨어 SBOM의 1.6 파이프라인을 건드리지 않고 공존하며, 식별자(CPE·PURL)와 PURL→CPE 변환은 1.7에서도 그대로 재사용합니다.

이전에는 도구·포맷을 올렸을 때 출력 변화를 볼 장치가 없다는 이유로 1.6 고정이 안전해 보였으나, 출력 회귀 스냅샷 안전장치([도구 버전 업그레이드 안전장치](dependency-upgrade-policy.md))가 들어오면서 1.7 채택 위험이 낮아졌습니다. cdxgen `aibom`의 실제 출력 specVersion과 후처리(normalize·validate)의 1.7 수용 여부는 구현 착수 시 스냅샷으로 확인합니다.

SPDX 3.0 AI Profile은 후순위입니다. 조달이나 상호운용 요구가 생기면 ANALYZE 모드의 `convert-to-cdx.sh` 변환 경로를 내보내기 방향으로 확장해 대응합니다.

## 5. 필요 도구 평가

AI SBOM 영역에서 검토 대상 도구와 BomLens 2단계 아키텍처에 붙는 지점입니다.

- **OWASP AIBOM Generator** (권고 1차 엔진) — HuggingFace 모델 id를 입력받아 CycloneDX를 생성하고 완전성 점수를 매깁니다. 사전 검증(부록 B)에서 모델 카드·라이선스·데이터셋을 실제로 추출하고 **CycloneDX 1.6과 1.7을 모두 출력**(1.7 스키마 검증 통과)함을 확인했습니다. 우리가 정한 1.7 결정과 맞아떨어집니다. 완전성 점수(섹션별 분해)는 G7 적합성 검사 설계에 그대로 참고할 만합니다.
- **cdxgen `aibom`** — 출력이 CycloneDX 1.7이라 포맷은 맞지만, 사전 검증(부록 A)에서 12.2.0과 핀 버전 12.5.0 모두 HuggingFace 모델 디렉토리·Modelfile을 0 components로 처리했고 lib에 huggingface·gguf·safetensors 수집 코드가 없었습니다. 현재 버전은 모델을 읽지 못해 생성 엔진으로 부적합합니다.
- **커스텀 추출기(대안)** — 사전 검증에서 HuggingFace 모델 디렉토리의 `README.md` frontmatter가 라이선스(apache-2.0)와 데이터셋(bookcorpus, wikipedia)을, `config.json`이 아키텍처를 담고 있음을 확인했고, 이를 직접 읽어 1.7 modelCard를 만드는 30줄짜리 개념 증명이 동작했습니다(부록 B). OWASP 도구가 막히거나 개방성 4축처럼 그 도구가 못 채우는 필드가 필요할 때의 대비책입니다.
- **Lab700x AI SBOM Scanner** — 모델 바이너리 정적 분석 도구로, 도구가 막 등장한 단계입니다. 펌웨어 분석에서 cve-bin-tool을 쓴 것과 같은 방식으로, 필요 시 opt-in 이미지에 후보로 검토합니다.
- **Syft·Trivy** — AI·LLM 패키지(예: transformers, llama.cpp) 식별과 취약점 매칭은 이미 성숙 단계입니다. 기존 IMAGE/BINARY 모드에서 그대로 활용됩니다.

펌웨어 분석에서 적용한 역할 분리 원칙이 여기서도 유효합니다. 모델·데이터셋 메타데이터 수집은 전용 도구(OWASP AIBOM Generator)에 맡기고, 식별·라이선스·CVE·검증은 BomLens가 이미 가진 후처리로 처리합니다.

## 6. 우선 역량 3종 로드맵

사용자가 선택한 세 역량을, 기존 자산 재사용 비중과 의존 관계로 정렬했습니다.

| 역량 | 신규 구현 비중 | 기존 자산 재사용 | 의존 |
|---|---|---|---|
| G7 최소요소 적합성 검사 | 중 | `validate-sbom.sh`, `_conformance.*` 산출 패턴 | 낮음(독립 착수 가능) |
| 모델·데이터셋 라이선스 검토 | 중 | `spdx-normalize.jq`, 고지문·위험 보고서 | 낮음 |
| AIBOM 생성 모드 | 높음 | 2단계 아키텍처, 후처리 전체 | cdxgen `aibom` 통합 필요 |

권고 착수 순서는 적합성 검사부터입니다. 외부에서 받은 AIBOM(또는 cdxgen으로 만든 샘플)을 G7 7클러스터 기준으로 점검하는 기능은 의존이 적고, 우리가 무엇을 생성해야 하는지 기준을 먼저 세워 줍니다. 이 기준이 곧 AIBOM 생성 모드의 출력 명세가 됩니다.

1. **G7 최소요소 적합성 검사** (구현됨). `validate-sbom.sh`를 확장해 SBOM에 machine-learning-model 컴포넌트가 있으면 G7 모델·데이터셋·메타데이터 클러스터 검사를 `_conformance.*` 리포트에 덧붙입니다(모델 식별자 PURL/CPE, 라이선스, 모델 카드 파라미터, 무결성 해시, 데이터셋 참조, 개방성 4축). 모두 권고(warn)라 전체 result를 fail시키지 않고, OWASP 엔진이 못 채우는 무결성 해시·개방성 4축은 WARN으로 정직하게 표면화합니다. AIBOM 모드와 ANALYZE(공급사 AI SBOM) 양쪽에서 동작. 시스템·인프라·KPI 클러스터는 단일 모델 AI SBOM에서 점검 불가라 제외.
2. **모델·데이터셋 라이선스 검토**. `spdx-normalize.jq`에 RAIL, Llama 커뮤니티 라이선스와 개방성 4축 표기를 추가하고, 고지문과 위험 보고서에 비표준 라이선스와 행동 사용 제한 조항을 표시합니다. 해석의 한계는 7절에 명시합니다.
3. **AIBOM 생성 모드**. cdxgen `aibom`을 1차 엔진으로 HuggingFace 모델 디렉토리·GGUF·Modelfile 입력을 CycloneDX 1.7 ML-BOM으로 생성하고, 기존 후처리 파이프라인에 합류시킵니다. 가장 큰 신규 작업이며, 앞의 두 역량이 만든 검사·라이선스 기준을 출력 목표로 삼습니다.

각 역량은 독립적으로 가치를 내므로 한 번에 모두 구현할 필요는 없습니다.

## 7. UI/UX 구현 방향

원칙은 새 화면을 만들지 않고 기존 웹 UI의 조건부 탭, 자동 감지 넛지, 적합성 표시 패턴을 그대로 확장하는 것입니다. 디자인 정체성 원칙(간결·일관, 상용 SaaS 기능 추종 금지, 있는 산출물 데이터를 그대로 표현)에 맞춥니다. 신규 컴포넌트는 사실상 없고, 입력 타입 하나와 조건부 탭 한둘, 배지 몇 개를 기존 패턴에 끼우는 수준입니다.

### 7.1 입력 쪽

- **입력 타입 추가**. `docker/web/frontend/src/components/InputTypeSelector.tsx`는 `SOURCE_TYPES` 배열과 `LABEL_KEY` 맵으로 토글 버튼을 그립니다. 여기에 모델 입력(HuggingFace 디렉토리 ZIP·GGUF·Modelfile) 항목을 더하고, 서버(`docker/web/server.py`)에 `/upload?kind=model` 업로드 종류를 추가합니다.
- **조건부 비활성화는 펌웨어 패턴 재사용**. firmware 탭이 capability가 없으면 `firmwareDisabled`로 잠기듯, AIBOM 생성 엔진(cdxgen `aibom`)이 없는 환경이면 같은 방식으로 모델 입력을 잠급니다.
- **자동 감지 넛지**. `ResultDashboard.tsx`에 이미 있는 `suggestIdentifyVendored` 앰버 배너가 vendored 식별을 제안하는 패턴입니다. 업로드물에서 모델 가중치(`.safetensors`·`.gguf`·`config.json`)가 보이면 같은 배너로 AIBOM 생성을 제안합니다. 자동 실행이 아니라 제안만 합니다.

### 7.2 결과 쪽

결과 대시보드의 탭은 모두 데이터가 있을 때만 렌더되는 구조입니다(`sbomFile && <TabsTrigger>` 같은 조건부 렌더). 이 구조를 그대로 따릅니다.

- **모델·데이터셋 탭**. modelCard·데이터셋 컴포넌트가 SBOM에 있을 때만 탭을 추가합니다. 내용은 새로 만들지 않고 `ComponentsTable`을 `component.type`(machine-learning-model·data)으로 필터해 재사용합니다. 개방성 4축은 행마다 `Badge` 네 개(weight·architecture·data·training 공개 여부)로 표시합니다.
- **G7 적합성**. `result.conformance`가 이미 흐르고 `KpiCards`가 conformance 카드를 받습니다(ANALYZE 모드용으로 존재). 7클러스터 커버리지는 `_conformance.*` 아티팩트를 체크리스트로 보여주는 패널 하나면 됩니다. 기존 `FileViewer`로 HTML 리포트를 띄우는 경로도 이미 있습니다.
- **라이선스**. `LicenseSummary`가 라이선스별로 컴포넌트를 묶어 보여줍니다. RAIL·Llama 같은 비표준·행동제한 라이선스에 경고 배지만 더합니다. 판단은 사람에게 넘기므로 배지는 "검토 필요" 표시에 그칩니다.

### 7.3 손대지 않는 곳

- 아티팩트 다운로드 표(`ResultsList`)는 새 `_conformance`·ML-BOM 파일을 자동으로 잡으므로 수정이 필요 없습니다.
- 문구는 `docs/locales/{ko,en}/common.json`(또는 프런트엔드 로케일)에 키 몇 개만 추가합니다. 기존 react-i18next 구조를 그대로 씁니다.

## 8. 도구로 해결되지 않는 영역

세 자료가 공통으로 강조하는 한계입니다. BomLens가 자동화할 수 없으니 문서와 UI에서 과장하지 않아야 합니다.

- **비표준 라이선스 해석**. RAIL이나 Llama 커뮤니티 라이선스의 행동 사용 제한이 특정 용도에 적용되는지는 법무·정책 판단입니다. 도구는 조항의 존재를 표시할 뿐, 준수 여부를 보장하지 못합니다.
- **라이선스 드리프트**. 학술 연구에 따르면 모델이 파생·전이될 때 제한 조항의 상당 부분이 손실되고 ML 고유 의무는 극히 일부만 보존됩니다. 모델 트리를 따라 의무를 추적하려면 사람의 검토가 필요합니다.
- **데이터셋 출처 검증**. 수집 방법(크롤링·상업계약·합성)과 PII·저작권 민감도는 메타데이터를 채울 수는 있어도 그 진위를 도구가 검증하기 어렵습니다.

OpenChain 가이드가 "생성은 도구로, 해석은 사람으로"라고 정리한 부분이 이것입니다. BomLens의 역할은 가시성을 만드는 데까지이며, 보증은 조직의 정책과 거버넌스가 맡습니다.

## 9. 권고 요약과 다음 단계

- 포맷은 AI 경로만 CycloneDX 1.7 ML-BOM으로 내보내고 소프트웨어 SBOM은 1.6을 유지합니다. SPDX 3.0 AI Profile은 수요 확인 후 내보내기 확장으로 후순위 대응합니다.
- 우선 역량은 적합성 검사, 라이선스 검토, AIBOM 생성 순으로 착수하기를 권고합니다. 적합성 검사가 생성의 출력 명세를 먼저 세워 줍니다.
- 생성 엔진은 **OWASP AIBOM Generator**로 확정·구현했습니다. 사전 검증(부록 B)에서 HuggingFace 모델을 실제로 읽어 모델 카드·라이선스·데이터셋을 뽑고 CycloneDX 1.6·1.7을 모두 출력함을 확인했고, FIRMWARE 모드를 본떠 `--model owner/name`(MODE=AIBOM, opt-in `bomlens-aibom` 이미지)으로 파이프라인에 붙였습니다(`docker/lib/scan-aibom.sh`, 공통 후처리 재사용). cdxgen `aibom`은 1.7을 내지만 현재 버전이 모델을 못 읽어 제외했습니다. 커스텀 추출기는 대비책으로 둡니다.
- 자동화 한계(비표준 라이선스 해석, 라이선스 드리프트, 데이터셋 출처 검증)는 문서와 리포트에서 명확히 선을 그어, 도구가 보증을 준다는 인상을 주지 않습니다.

확정된 것은 포맷(AI 경로 1.7)과 생성 엔진(OWASP AIBOM Generator)입니다. OWASP 도구가 1.7을 직접 내므로 이전의 1.6 대 1.7 긴장도 풀렸습니다. 남은 미결정은 첫 구현 역량의 범위입니다. 생성은 출력 회귀 스냅샷으로 specVersion·필드 변화를 지켜봅니다.

> 외부 등록·노출 전략은 [외부 등록 채널](seo-external-listings.md)을, AI SBOM 기능을 더했을 때의 CycloneDX Tool Center 역량 표기 갱신은 같은 문서를 참고하세요.

---

## 부록 A. 생성 엔진 사전 검증 1차 — cdxgen (2026-06-23)

본격 구현 전에 cdxgen `aibom`의 실제 동작을 짧은 사전 검증으로 확인했습니다. 목적은 두 가지였습니다. 포맷 결정(1.7) 검증과 cdxgen이 HuggingFace 모델에서 modelCard를 실제로 만드는지 확인.

**실행 내용**
- cdxgen 12.2.0(로컬)과 핀 버전 12.5.0(npx)으로 `-t aibom` 실행.
- 입력 세 형태: HuggingFace 모델 URL(`huggingface.co/prajjwal1/bert-tiny`), 가중치를 제외하고 받은 HuggingFace 모델 디렉토리(`bert-base-uncased`, `config.json`+`README.md` frontmatter 포함), 최소 `Modelfile`.

**확인된 것**
- cdxgen `aibom`은 일관되게 **CycloneDX 1.7**을 출력합니다. AI 경로를 1.7로 두는 결정과 맞습니다.
- 모델 디렉토리의 `README.md` frontmatter에 라이선스(`apache-2.0`)와 데이터셋(`bookcorpus`, `wikipedia`)이, `config.json`에 아키텍처가 그대로 들어 있습니다. modelCard를 채울 원본 메타데이터는 모델 안에 있습니다.

**문제로 드러난 것**
- 세 입력 모두 `components`가 **0개**였습니다(URL·로컬 디렉토리·Modelfile, 12.2.0과 12.5.0 동일).
- cdxgen 12.2.0과 12.5.0의 `lib`에는 `huggingface`·`gguf`·`safetensors` 문자열이 **전혀 없습니다**. modelCard 출력 스키마(`machine-learning-model`)는 있으나, 모델을 읽어 그 필드를 채우는 수집 단계가 이 버전에는 없습니다.

**시사점**
- "cdxgen `aibom`을 1차 생성 엔진으로 쓴다"는 가정은 핀 버전에서 성립하지 않습니다. 다음 중 하나를 골라야 합니다. (1) 모델 ingestion이 실제로 되는 cdxgen 버전·호출을 찾아 검증, (2) OWASP AIBOM Generator를 1차 엔진으로 평가, (3) `config.json`+README frontmatter를 직접 읽어 modelCard를 만드는 경량 추출기. 원본 메타데이터가 모델 안에 있으므로 (3)의 난이도는 낮습니다.
- 이 사전 검증이 며칠 비용으로 로드맵의 핵심 가정 하나를 교정했습니다. 적합성 검사 기능을 먼저 크게 만들지 않은 판단이 맞았습니다.

---

## 부록 B. 생성 엔진 비교 검증 (2026-06-23)

부록 A로 cdxgen이 빠진 뒤, 같은 모델(`google-bert/bert-base-uncased`)에 OWASP AIBOM Generator와 직접 만든 최소 추출기를 돌려 비교했습니다.

**실행 내용**
- OWASP AIBOM Generator(`owasp-aibom-generator`, GitHub `GenAI-Security-Project/aibom-generator`): `python -m src.cli google-bert/bert-base-uncased`. HuggingFace API로 모델 카드를 가져옵니다(네트워크 필요, 기본 모드는 API 키 불필요).
- 커스텀 추출기: `config.json` + `README.md` frontmatter를 읽어 1.7 modelCard를 만드는 30줄짜리 파이썬 개념 증명(네트워크 불필요).

**비교표**

| 항목 | cdxgen `aibom` (부록 A) | OWASP AIBOM Generator | 커스텀 추출기 |
|---|---|---|---|
| 모델 읽기 | 못 함(0 components) | 됨 | 됨(로컬 디렉토리) |
| 출력 포맷 | 1.7 | 1.6과 1.7 모두(1.7 검증 통과) | 1.7 |
| modelCard | 비어 있음 | 채움(modelParameters·considerations) | 최소(아키텍처·데이터셋) |
| 라이선스 | 없음 | Apache-2.0 추출 | apache-2.0 추출 |
| 데이터셋 | 없음 | modelCard 안에 포착(bookcorpus·wikipedia) | 별도 data 컴포넌트로 분리 |
| 식별자 | 없음 | PURL(`pkg:huggingface/...@커밋`) | PURL |
| 무결성 해시 | 없음 | 없음 | 없음 |
| 개방성 4축 | 없음 | 없음 | 없음 |
| 완전성 점수 | 없음 | 있음(63.4/100, 섹션별 분해) | 없음 |
| 통합 비용 | — | 파이썬 패키지(pip)+HuggingFace 네트워크, opt-in 이미지 | 자체 코드, 의존성 없음 |

**권고**
- 1차 엔진은 **OWASP AIBOM Generator**. 모델을 실제로 읽고, 라이선스·데이터셋·모델 카드를 채우며, 1.7을 직접 출력해 포맷 결정과 맞고, 완전성 점수가 G7 적합성 검사 설계에 바로 도움이 됩니다. scancode·scanoss처럼 opt-in 파이썬 도구로 BomLens 1단계에 붙입니다.
- 공백(무결성 해시, CPE, 개방성 4축)은 2단계 후처리에서 보완합니다. 특히 개방성 4축은 어느 도구도 자동으로 못 채우므로 모델 카드·정책 기반으로 별도 처리합니다.
- 커스텀 추출기는 대비책으로 둡니다. OWASP 도구가 막히거나(네트워크·중단) 그 도구가 못 채우는 필드가 필요할 때 30줄 수준으로 보완할 수 있음을 확인했습니다.

---

### 출처

- OpenChain AI SBOM 컴플라이언스 가이드: <https://haksungjang.github.io/research/2026-openchain-ai-sbom/>, <https://openchain-project.github.io/OpenChain-KWG/guide/ai-sbom_guide/>
- G7 AI SBOM 최소요소: <https://haksungjang.github.io/research/2026-g7-sbom-for-ai/>
- cdxgen AIBOM 기능: <https://github.com/cdxgen/cdxgen>
- OWASP AIBOM Generator: <https://github.com/GenAI-Security-Project/aibom-generator>, <https://owasp-genai-aibom.org>
- CycloneDX 명세(ML-BOM, modelCard): <https://cyclonedx.org/>
