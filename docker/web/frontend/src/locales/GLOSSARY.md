# 화면 용어집

웹 UI 문구(`en/common.json`, `ko/common.json`)에서 같은 개념은 같은 이름으로 쓴다. 아래 표가 정본이다. 표의 "쓰지 않는 표현"은 `npm run i18n:check`가 검사하며(`docker/web/frontend/scripts/forbidden-terms.mjs`), 새 변형을 금지하려면 그 스크립트와 이 문서의 "확인된 변형"을 함께 고친다.

## 정본 용어

| 개념 | 한국어 | 영어 | 쓰지 않는 표현 |
|---|---|---|---|
| SBOM 형식과 최소 요소를 점검하는 기능 | 적합성 검사 | Conformance check | SBOM 규제 검사, 적합성 검증, SBOM Validation, conformance validation |
| 그 결과 문서 | 적합성 검사 보고서 | Conformance check report | 적합성 보고서, Conformance report |
| 스캔이 만든 파일 | 산출물 | Artifacts | 결과물, 아티팩트 |
| 스캔 대상으로 올리는 빌드 파일 | 빌드 산출물 | Build artifact | 아티팩트 |
| 같은 설정으로 다시 실행 | 다시 스캔 | Re-scan | 재스캔, Rescan |
| 라이선스와 취약점을 묶은 보고서 | 오픈소스 위험 보고서 | Open-source risk report | 오픈소스 위험분석 보고서, Open-source risk analysis report |
| 공급사가 낸 SBOM을 검토할 때의 보고서 | 오픈소스 위험 보고서 (부제로 공급사 SBOM 검토임을 밝힘) | Open-source risk report (subtitle: supplier SBOM under review) | 제목 자리의 Supplier SBOM risk report, 공급사 SBOM 위험 보고서 |
| 취약점 상태 `fixed` | 수정 버전 있음 | Fix available | 수정됨, Fixed (다른 작업에서 변경 중) |

## 라이선스 분류

Permissive, Weak copyleft, Strong copyleft, Network copyleft, Uncategorized, Review needed는 분류기의 고유 이름이라 한국어 화면에서도 영어로 둔다(한국어 보고서도 같다). 뜻은 화면의 툴팁(`licenses.tierHint.*`)이 현재 언어로 설명하고, 모든 설명 끝에 "법률 자문이 아닌 일반적인 안내"라는 문구(`licenses.tierHintNote`)를 붙인다.

## 쓰기 원칙

- 같은 개념에는 한 이름만 쓴다. 화면, 툴팁, 보고서 제목, 스캔 단계 이름이 모두 같아야 한다.
- 영어 화면에도 긴 줄표(em dash)를 쓰지 않는다. 쉼표, 마침표, 괄호로 바꾼다.
- 한국어는 일상에서 쓰는 말로 쓰고, 새로 만든 합성어와 영어 음차어를 피한다.
- "검증"은 서명이나 SPDX 형식처럼 실제로 대조해 확인하는 일에만 쓴다. SBOM 점검 기능의 이름으로 쓰지 않는다.
- "산출물"은 두 가지 뜻이 있다. 스캔이 만든 파일(Artifacts)과, 스캔 대상으로 올리는 빌드 파일(빌드 산출물, Build artifact)이다. 뒤쪽은 항상 "빌드"를 붙인다. 모델의 출력을 가리키는 `models.usageOutputsOnly`("산출물만 이용")는 세 번째 뜻이라 따로 다듬을 후보다.
- 영어 왼쪽 레일의 묶음 이름 "Outputs"와 새 스캔 화면의 "Outputs"는 같은 개념이며 한국어는 "산출물"이다. 영어는 파일 목록 화면에서만 "Artifacts"를 쓴다.

## 확인된 변형

`locales/*/common.json`과 컴포넌트를 검색해 실제로 쓰이던 변형이다. 표시가 "정리"인 항목은 이 변경에서 정본으로 바꿨다.

| 변형 | 위치 | 상태 |
|---|---|---|
| SBOM 규제 검사 / SBOM Validation | 레일 `nav.conformance` | 정리 |
| 적합성 검증 / conformance validation | 스캔 단계 `pipelineSteps.conformance` | 정리 |
| 적합성, Conformance (단독) | `result.conformance` | 적합성 검사로 정리 |
| 적합성 보고서 / Conformance report | 산출물 카드 제목, 검사 기준 설명 | 정리 |
| 결과물 | 산출물 목록 머리글, 개수, 빈 상태, 열기 버튼 | 정리 |
| 재스캔 | 결과 화면 버튼 `result.rescan` | 정리 |
| 오픈소스 위험분석 보고서 / 위험분석을 위해 | 산출물 카드, 결과 화면, 소스 설명 | 정리 |
| 다시 실행 / Re-run / run again (스캔을 가리킬 때) | 복사 소스 탐지, SCANOSS, 라이선스 충돌 안내 | 다시 스캔으로 정리 |
| 아티팩트 / Artifact | 새 스캔 화면 분류 `newscan.catArtifact` | 빌드 산출물 / Build artifact로 정리 |
| 이 머신 | 스캔 관리 화면 부제 | 이 컴퓨터로 정리 |
| 인벤토리, 컴플라이언스 | 레일 묶음 이름 | 구성 정보, 규정 준수로 정리 (이제 금지어) |
| 적합 / 부적합 | 판정 표시 | 정본 유지 (검사 결과 값) |
| 형식 적합성 / Format conformance | G7 화면 소제목 | 정본 유지 (검사 항목의 한 갈래) |
| 포맷 검증 / Format validation | 적합성 검사의 옛 이름(셸 보고서 제목) | 적합성 검사로 정리 |
| Supplier SBOM risk report | 공급사 검토용 보고서 제목 | 오픈소스 위험 보고서와 부제로 정리 |

보고서를 만드는 셸 스크립트(`docker/lib/generate-risk-report.sh`, `docker/lib/validate-sbom.sh`)와 `docker/lib/i18n/report-strings.ko.json`의 제목도 이 용어집을 따른다. 새 보고서 문구를 추가할 때는 같은 이름을 쓴다.
