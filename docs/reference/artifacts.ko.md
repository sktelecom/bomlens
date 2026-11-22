---
description: BomLens가 생성하는 산출물 파일 목록과 생성 조건, 파일명 규칙, SBOM 구조 요약입니다.
---

# 산출물 레퍼런스

생성된 SBOM은 CycloneDX 1.6 JSON 형식이고, `--spec-version 1.7`을 주면 1.7입니다. AI 모델과 데이터셋 SBOM은 항상 1.7입니다. 최종 CycloneDX SBOM을 변환한 SPDX 2.3 JSON 파일은 CLI 스캔에서 `--spdx`로 만들거나, UI에서는 스캔이 끝난 뒤 결과 화면에서 내보냅니다. 두 경로 모두 같은 변환을 거치므로 결과 파일은 동일합니다. 이때도 정본은 CycloneDX이며, CycloneDX에만 있는 데이터(취약점, `bomlens:*` 속성, [선언한 AI 서비스](#선언한-ai-서비스)가 더하는 `services[]`)는 SPDX 파일로 옮겨지지 않습니다. AI 모델과 데이터셋 스캔은 AI와 Dataset 프로파일을 쓴 SPDX 3.0.1 문서(`_bom.spdx3.json`, 아래 표)도 만듭니다.

파일명은 `{Project}_{Version}_bom.json`입니다(예: `MyApp_1.0.0_bom.json`).

## 산출물 파일

| 파일 | 생성 조건 | 설명 |
|------|----------|------|
| `{Project}_{Version}_bom.json` | 항상 | SBOM (CycloneDX 1.6, `--spec-version 1.7`이면 1.7) |
| `{Project}_{Version}_bom.refused.json` | 선언 파일(`--components`, 또는 스캔 대상 루트의 `sbom-declared.cdx.json`)이 거부된 소스 스캔 또는 Yocto 빌드 디렉터리 스캔 | 스캔이 멈춘 시점까지 만든 SBOM으로, 선언 구성요소가 빠져 있다. `_bom.json`을 쓰지 않고 이 파일이 그 자리를 대신하므로, `_bom.json`을 가져가는 단계가 불완전한 SBOM을 쓰지 않는다. 스캔은 사유를 출력하고 1로 종료한다. 정규화, 서명, 업로드를 하지 않고 보고서도 만들지 않는다. 웹 UI는 실패한 스캔 화면에서 이 파일을 보거나 내려받게 한다. 같은 프로젝트와 버전을 다음에 스캔하면 지워진다. [무엇을 거부하고, 왜 거부하나?](../guides/declared-components.ko.md#무엇을-거부하고-왜-거부하나) 참고 |
| `{Project}_{Version}_bom.spdx.json` | `--spdx` / `--all`, 또는 UI의 SPDX 2.3으로 내보내기 | SBOM (SPDX 2.3, CycloneDX 결과를 변환) |
| `{Project}_{Version}_bom.spdx3.json` | AI 모델과 데이터셋 스캔(`--model`, `--model-file`, 데이터셋), `--no-spdx3`를 주지 않은 경우 | AI SBOM을 AI와 Dataset 프로파일을 쓴 SPDX 3.0.1 문서(JSON-LD)로 담은 파일. 값은 CycloneDX 결과, 그 결과에 대한 고정 규칙, 모델 공개자의 선언(`--ai-declare`)에서만 가져오며 추정하지 않는다. SPDX에 "알 수 없음" 값이 없는 필수 필드(모델과 데이터의 공급 주체와 제작 주체, 출시일과 생성일, 내려받기 주소, 문서 작성자)는 선언하기 전까지 비어 있고, 그동안 문서에 초안이라고 표시한다. 기반 모델은 id와 라이선스로만 식별한다. 배포 가중치 범위는 CycloneDX 속성 확장의 `bomlens:weights:scope`(`full`, `adapter`, `quantized`, `merged`)로 담는다. `--analyze` 입력으로는 쓸 수 없다 |
| `{Project}_{Version}_spdx3-check.json` / `.md` | SPDX 3.0.1 문서와 함께 | 요소마다 각 필드가 스캔에서 왔는지, 선언에서 왔는지, 비어 있는지와, 채워지지 않은 필수 필드, 모델 공개자가 판단해야 할 항목(개인정보, 안전 위험, 자율성)을 정리한 검사 결과. `service.state`는 선언한 서비스와 모델 값이 CycloneDX SBOM에 들어 있는지를 알린다. `none`(선언도 없고 SBOM에도 없음), `applied`(SBOM이 선언과 같음), `pendingScan`(둘이 다르며 다시 스캔하면 반영됨) 중 하나다. 법적 자문이 아닌 안내 |
| `{Project}_{Version}_ai-declaration.template.json` | SPDX 3.0.1 문서와 함께 | 이 스캔의 빈 선언 양식. 모델과 데이터셋, 스캔이 찾은 기반 모델마다 사람이 채울 필드가 들어 있다. 채워서 `--ai-declare`로 다시 넘긴다 |
| `{Project}_{Version}_ai-declaration.json` | `--ai-declare <file>`(받아들인 파일), 또는 웹 UI에서 저장한 선언 | 모델 공개자가 선언한 내용. `_vex.json`처럼 같은 프로젝트와 버전을 다시 스캔해도 지워지지 않고, 다시 스캔하면 다시 적용된다. 새 스캔에 없는 데이터셋이나 기반 모델을 적은 파일은 거부하며, 그 경우 문서는 초안으로 남는다. 데이터셋 항목에는 `sources[]`를 적을 수 있다. 허브 데이터셋은 `{"ref": "huggingface:<id>", "relation": "extended"}`로 적으며 다음 스캔에서 허브에서 읽어 그 데이터셋과 함께 판정한다. 문장으로만 아는 원천은 `{"name": "...", "license": "<허브 라이선스 태그나 SPDX ID>", "relation": "other"}`로 적으며 SPDX 3.0.1 문서에만 기록되고 확인되지 않은 것으로 표시된다. SPDX ID가 아닌 라이선스는 문장으로만 남는다. 허브에 없는 데이터에는 문장으로 적는 원천만 넣을 수 있다. `model.license`(허브 라이선스 태그나 SPDX ID)는 모델 자체의 라이선스다. 스캔이 라이선스를 읽지 못했거나 `other`만 읽었을 때 SPDX 문서에 들어가고(SPDX 라이선스 하나에 대응하는 허브 태그나 `LicenseRef-`일 때만 SPDX 식으로 기록), 선언만으로 만든 모델은 SBOM에도 이 라이선스가 들어가 이것으로 판정한다. 선언에는 모델을 실행하는 서비스(`service`)와 모델의 입력과 출력 종류, 규제 제출용 값도 적을 수 있다. [선언한 AI 서비스](#선언한-ai-서비스)를 참고한다 |
| `{Project}_{Version}_component-versions.template.csv` | 버전 없는 컴포넌트를 찾은 펌웨어, 루트 파일시스템, 바이너리 스캔 | 그 컴포넌트의 이름을 `--component-versions` 형식(`name,version,reason` 머리글의 CSV)으로 적고 버전은 비워 둔 파일. 세 가지 사유를 설명하는 주석 줄이 함께 들어 있고, 이미 사유가 붙은 컴포넌트는 넣지 않는다. 버전을, 버전이 없으면 사유를 채워 `--component-versions`로 다시 넘긴다 |
| `{Project}_{Version}_NOTICE.txt` / `.html` | `--notice` / `--all` / 오픈소스 위험 보고서 기본 | 오픈소스 고지문 |
| `{Project}_{Version}_NOTICE.pdf` | 위와 동일한 조건, 이미지에 PDF 렌더러가 포함된 경우(`--build-arg SBOM_PDF=true`) | 고지문을 PDF로 렌더링한 파일. 렌더러가 없으면 로그만 남기고 건너뜀 |
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / 오픈소스 위험 보고서 기본 | Trivy 보안보고서 |
| `{Project}_{Version}_risk-report.md` / `.html` | 기본(전 모드) — `--no-report`로 생략 | 오픈소스 위험 보고서 |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | SBOM을 생성하는 모든 스캔에서 만들어지며 `--no-report`를 줘도 생략되지 않는다(`--no-report`는 오픈소스 위험 보고서만 건너뛴다). `--analyze`도 만든다(그것이 검증 대상이므로) | 적합성 검사 보고서. 모든 SBOM에 규제 크로스워크 집계가 함께 담긴다(EU 사이버복원력법은 BSI TR-03183-2로, 2026년판 미국 SBOM 최소 요소. 참고용이며 준수 판정 아님). AI SBOM이면 G7 검사와 함께, 아직 비어 있는 권고 요소마다 이를 충족하는 CycloneDX 조각을 담는다. 다른 도구가 만든 AI BOM에서 그 도구의 속성으로 읽은 G7 요소는 상세에 "also read from ..."으로, 그리고 `via` 필드에 출처를 밝힌다. 스캔 중 best-effort 후처리 단계가 실패하면, 적합성 검사 뒤에 도는 단계(NOTICE, 보안 스캔, 위험 보고서)를 포함해 그 단계 이름을 기록하므로, 통과 판정이 모든 단계가 문제없이 돌았다는 증명은 아니다. 통과/실패 판정이나 개별 검사 항목의 상태에는 영향을 주지 않는다. 예시는 [적합성 검사 보고서](../samples/aether-7b-5attn_conformance.ko.html)를 참고한다 |
| `{Project}_{Version}_ai-profile.json` / `.md` | AI SBOM (`--model`, 또는 모델 컴포넌트가 있는 SBOM에 `--analyze`) | AI 준수 개요: G7 요약, 메울 수 있는 공백과 참고 링크, 라이선스 표시 컴포넌트, 규제 크로스워크, 모델 위험 판정(`riskAssessment`: 모델별 ok/conditional/caution/review 판정과 조건, 근거, 사용 형태. 법적 자문이 아닌 안내). 같은 요약이 적합성 검사 보고서 HTML 맨 위에 나오므로 별도 HTML은 만들지 않는다 |
| `{Project}_{Version}_scancode.json` | `--deep-license` | scancode 원본 결과 |
| `{Project}_{Version}_files.json` | 소스를 갖는 스캔(펌웨어 스캔은 항상, 다른 모드는 `--deep-license`가 아직 `_scancode.json`을 만들지 않은 경우) | 소스 트리 뷰를 뒷받침하는 ScanCode 형식 파일 트리 인벤토리(구조만, 라이선스 없음) |
| `{Project}_{Version}_source.json` | 소스를 갖는 스캔 | 스캔한 트리의 파일 내용 스냅샷, 파일 뷰어를 뒷받침(스캔한 트리 자체는 컨테이너 종료와 함께 사라짐). 파일 내용의 자격 증명(레지스트리 토큰, URL과 설정 파일의 비밀번호 등)은 가려서 저장하며, 값을 가린 파일에는 `"masked": true`가 붙고 `totals.maskedFiles`에 그 수가 들어감 |
| `{Project}_{Version}_input.json` | `--analyze` | CycloneDX 변환이 덮어쓰기 전, 공급사 SBOM 원본의 포맷·스펙 버전·도구·작성 정보를 보존 |
| `{Project}_{Version}_yocto_vex.json` | Yocto 빌드(빌드 디렉터리를 직접 지정하거나 그 위에 `--analyze`) | 빌드가 이미 패치했거나 무관하다고 판정한 CVE 건수 — CycloneDX 결과나 보안보고서에는 미해결 항목만 남아 있어 이 수치를 알 수 없다 |
| `{Project}_{Version}_vex.json` | 웹 UI 전용, 취약점 화면에서 CVE에 판단(영향 있음/영향 없음/이미 고침/조사 중, 근거 메모는 선택)을 저장할 때 생긴다 | 이 스캔에 저장된 판단을 컴포넌트와 CVE 기준으로 담는다. CLI는 만들지 않으며, 해당 스캔에 첫 판단을 저장하기 전에는 없다. 다른 파일과 달리 스캔이 다시 만들지 않고, 같은 프로젝트와 버전을 재스캔해도 지워지지 않는다. 이전 스캔에 남긴 판단은 재스캔 뒤에도 그대로 남는다 |
| `{Project}_{Version}_vex.cdx.json` | 웹 UI 전용, 취약점 화면에서 **VEX 내보내기**를 누를 때 만들어진다(저장된 판단이 하나 이상 필요) | `_vex.json`의 판단을 다른 도구가 읽을 수 있는 독립된 CycloneDX VEX 문서로 담는다. 스캔의 SBOM이 1.7이면 1.7, 그 밖에는 1.6으로 쓴다. 네 가지 상태는 CycloneDX `analysis.state` 값으로 바뀌어 기록되고(영향 있음은 `exploitable`, 영향 없음은 `not_affected`, 이미 고침은 `resolved`, 조사 중은 `in_triage`), 메모는 `analysis.detail`에 들어간다. 화면이 자유 서술을 받는 반면 CycloneDX는 정해진 목록만 허용하므로 `justification`은 쓰지 않는다. 각 항목은 문서 안에 들어 있는 해당 컴포넌트의 사본(이름, 버전, PURL)을 가리키므로 파일 하나로 완결된다. 컴포넌트가 SBOM에 없는 판단은 제외하고 화면이 그 건수를 알려 주며, 펌웨어 발견 항목은 이름과 버전이 바이너리에서 오므로 대표적인 경우다. 내보낼 때마다 새로 만들고, 같은 프로젝트와 버전을 재스캔하면 지워지므로 그 뒤에는 다시 내보낸다 |
| `{Project}_{Version}_vex_imported.json` | CLI의 `--vex <file>`, 또는 웹 UI 취약점 화면의 **VEX 가져오기**에 CycloneDX VEX 문서를 줄 때 생긴다 | 공급사가 보낸 VEX 문서 중 이 스캔 SBOM의 컴포넌트에 해당하는 진술과, 그 문서가 설명하는 제품이다. 직접 남긴 판단(`_vex.json`)과는 따로 보관한다. 받은 진술이 내 판단을 덮어쓰지 않으며 화면도 둘을 다른 이름으로 표시한다. CycloneDX `analysis.state`는 네 가지 상태로 옮긴다(`exploitable`은 영향 있음, `not_affected`와 `false_positive`는 영향 없음, `resolved`와 `resolved_with_pedigree`는 이미 고침, `in_triage`는 조사 중). 그 밖의 상태는 무시한다. 문서의 제품이나 버전이 스캔한 SBOM의 루트와 다르면 거부하고 아무것도 저장하지 않는다. 가져오기에 성공하면 이 파일을 교체하고, 거부되거나 적용할 진술이 없는 가져오기는 이전 파일을 그대로 둔다. 제품 자체를 가리키는 진술은 컴포넌트 없이 한 번만 저장하며, 그 CVE의 발견 항목 중 자기 진술이 없는 것 모두에 적용한다. `_vex.json`처럼 같은 프로젝트와 버전을 재스캔해도 지워지지 않는다 |
| `{Project}_{Version}_reachability.cdx.json` | Go 소스나 Go 실행 파일 스캔에 `--reachability`를 주고, govulncheck가 Go 취약점 데이터베이스를 읽었을 때 생긴다 | SBOM의 컴포넌트(같은 모듈과 버전)에 해당하는 Go 보안 권고마다 govulncheck가 내린 판정을 담은 독립 CycloneDX 1.6 VEX 문서다. 영향받는 코드에 도달하지 않으면 `analysis.state`는 `not_affected`이다. 모듈은 필요하지만 영향받는 패키지가 빌드에 없으면 `justification`은 `code_not_present`, 패키지는 있지만 영향받는 함수를 호출하지 않거나 실행 파일에 링크되지 않았으면 `code_not_reachable`이다. 도달하면 `exploitable`이다. `analysis.detail`에 어느 경우인지와 호출 경로나 심볼을 적는다. `id`는 권고에 CVE가 있으면 그 CVE이고, Go 식별자와 다른 식별자는 `references`에 있다. 소스 스캔에서는 `metadata.properties`에 판정 범위(`bomlens:reachability:goos`, `goarch`, `build-tags`, `modules`)를 남긴다. 보안 보고서가 이 문서를 읽어, 해당 발견 항목마다 `_security.json`에 `bomlens:reachability`(`state`, `justification`, `detail`, `level`, `mode`)를 붙이고 문서에 `Reachability` 요약을 둔다 |
| `{Project}_{Version}_vendored.cdx.json` | 소스 스캔에서 `--identify-vendored`, opt-in SCANOSS 이미지 필요 | 소스 트리 안에서 식별한 번들 오픈소스 컴포넌트(SCANOSS) |
| `{Project}_{Version}_security_trivy.json` | 보안보고서를 생성할 때, 다른 엔진(grype, cve-bin-tool, Yocto)이 결과를 더한 경우 | `_security.json`으로 병합하기 전에 따로 남긴 Trivy 자체 결과 |
| `{Project}_{Version}_cdxgen.log` | CLI 소스 스캔에서 의존성 준비 단계가 실패한 경우(SBOM의 `bomlens:pipeline-step-failed`에 기록됨) | 원인을 찾을 수 있도록 남긴 1단계 로그(준비 단계와 cdxgen 출력). 진단용 파일이므로 배포하지 않습니다. URL에 든 자격 증명(`scheme://user:pass@`는 `scheme://***@`로 바뀜)과 Authorization, 토큰, 비밀번호, 시크릿, API 키 값은 가리지만 내부 호스트 이름은 그대로 남습니다. 같은 프로젝트와 버전을 다시 스캔하기 전에 지웁니다 |
| `bomlens-events.jsonl` | `BOMLENS_EVENTS=file` | 진행 이벤트, 한 줄에 JSON 객체 하나. [엔진 계약](engine-contract.ko.md#진행-이벤트) 참고 |
| `bomlens-result.json` | 항상 | 실행 결과 매니페스트. 실행이 어떻게 끝났는지, 단계별 결과, 출력 파일별 역할을 담습니다. [엔진 계약](engine-contract.ko.md) 참고 |
| `{Project}_{Version}_security_epss.json` | 보안보고서를 생성할 때마다 | 취약점별 EPSS 점수와 KEV 여부(오프라인 생성 시 null/false), 보안보고서 우선순위 산정에 사용 |
| `{Project}_{Version}_completeness.json` | SBOM 스캔마다 | 결과가 얼마나 완전한지(`complete`, `partial`, `unreliable`)와 완전하지 않은 이유. 개요 화면의 안내와 보고서가 이 파일을 읽습니다. 요청한 보안 스캔이 실행되지 않았거나 실패하면(Trivy 오류, 비어 있는 trivy-db 마운트, Trivy 없음) 결과는 `partial`이 되고 사유 `vulnerability-check-failed`와 SBOM 속성 `bomlens:vulnerability-check-failed`가 붙습니다. Trivy 데이터베이스가 오래되기만 한 경우는 해당하지 않고, 보안 검사를 끈 스캔에는 붙지 않습니다 |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign 서명 (`--spdx`와 함께 쓰면 `_bom.spdx.json.sig`도 생성). AI 스캔에는 `_bom.spdx3.json.sig`도 추가되며, 초안도 서명한다. 서명은 파일의 출처를 보증할 뿐 완성 여부를 뜻하지 않는다 |
| `{new}_model-diff.json` | `--diff <old.json> <new.json>` | 이미 생성한 SBOM 두 개를 비교한 AI 모델 변동 보고서. 매칭된 모델의 판정·라이선스·해시 변화와, 한쪽 파일에만 있는 컴포넌트를 담는다. 새 쪽 입력 파일 이름을 따르며(`<new>_bom.json` → `<new>_model-diff.json`), `{Project}_{Version}`이 아니다 — `--diff`는 프로젝트나 버전을 따로 받지 않는다 |

`{P}`=프로젝트 이름, `{V}`=버전 (특수문자는 `_`로 정규화).

위 표의 생성 조건은 CLI 옵션 기준입니다. 웹 UI와 데스크톱 앱에서는 새 스캔 화면의 생성 옵션(고지문, 보안 보고서)이 같은 역할을 하고, 만들어진 파일은 결과 화면의 산출물 섹션에 모두 표시되어 형식별로 또는 ZIP 하나로 내려받을 수 있습니다. SPDX는 스캔 옵션이 아닙니다. 산출물 섹션의 SBOM 행에 있는 **SPDX 2.3으로 내보내기** 버튼으로 필요할 때 완성된 SBOM을 변환하며, 변환된 파일은 산출물 목록과 ZIP 묶음에 함께 들어갑니다. UI에는 서명 기능이 없어 이렇게 내보낸 SPDX는 서명되지 않으므로, 서명이 필요하면 CLI에서 `--spdx --sign`을 쓰세요. [웹 UI와 데스크톱 앱](ui.ko.md)을 참고하세요.

## 선언한 AI 서비스

AI 선언(`--ai-declare`, 또는 웹 UI에서 저장한 선언)에는 최상위 `service` 객체로 모델을 실행하는 서비스를 적을 수 있고, 스캔으로 읽을 수 없는 모델 값 몇 가지도 적을 수 있습니다. `service`는 문서가 데이터셋이 아니라 모델을 기술할 때만 받으며, 값이 하나도 없는 `service`는 선언하지 않은 것으로 봅니다. 이 값들이 무엇을 위한 것인지는 [AI 모델 가이드](../guides/ai-model.ko.md#모델을-실행하는-서비스)에서 설명합니다.

`service` 객체는 다음과 같은 모양입니다.

```json
"service": {
  "name": "Acme Support Assistant",
  "packageVersion": "2.3.0",
  "downloadLocation": "https://support.acme.example/assistant",
  "suppliedBy": {"type": "Organization", "name": "Acme Corp"},
  "releaseTime": "2025-06-01T00:00:00Z",
  "informationAboutApplication": "Answers customer support questions in the web chat.",
  "domain": ["customer support"],
  "autonomyType": "no",
  "inputModality": ["text"],
  "outputModality": ["text"],
  "dataFlows": [
    {"flow": "inbound", "classification": "personal data",
     "description": "Customer questions typed in the chat window.",
     "source": ["https://support.acme.example/chat"]}
  ],
  "standardCompliance": ["ISO/IEC 42001:2023"],
  "disclosureUrl": "https://support.acme.example/ai-disclosure"
}
```

| 키 | 값 |
|----|----|
| `name` | 서비스 이름. 필수 |
| `packageVersion` | 서비스 버전. 필수 |
| `downloadLocation` | 서비스를 제공하는 주소(URI). 필수 |
| `suppliedBy` | 서비스를 제공하는 조직, `{"type": "Organization", "name": "..."}`. 필수 |
| `releaseTime` | 출시일, `YYYY-MM-DDThh:mm:ssZ`. 필수 |
| `informationAboutApplication` | 서비스의 용도를 적은 글 |
| `domain[]` | 서비스가 쓰이는 분야를 적은 글 |
| `autonomyType` | AI의 결정에 사람이 관여하는지. `yes`(사람이 관여하지 않는 완전 자동), `no`(사람이 관여함), `noAssertion`(모름) |
| `inputModality[]`, `outputModality[]` | 입력과 출력의 종류. `text`, `image`, `audio`, `video`, `timeseries`, `structured`, `code`, `other` |
| `dataFlows[]` | 들어오고 나가는 데이터. 항목마다 `{flow, classification, name, description, source[], destination[]}`이다. `flow`는 `inbound`, `outbound`, `bi-directional`, `unknown` 중 하나다. `classification`은 필수(200자 이내)이며 개인정보처럼 어떤 데이터인지 적는다. `name`과 `description`은 선택이며, 설명에는 서비스가 그 데이터를 어떻게 쓰는지 적는다. `source[]`와 `destination[]`은 주소(URI)다 |
| `standardCompliance[]` | 서비스가 따르는 표준의 이름 |
| `disclosureUrl` | 서비스의 AI 사용을 설명하는 공개 페이지(URI) |
| `externalModels[]` | 서비스가 API로 호출하는 AI 모델. 항목마다 `{key, name, suppliedBy, packageVersion, endpoint}`이다. `key`(영문 소문자, 숫자, `.`, `_`, `-`로 64자 이내, 목록 안에서 중복 불가)와 `name`은 필수이고, `endpoint`는 URI다 |

필수 키는 SPDX가 서비스에 요구하는 항목이며, 모두 적을 때까지 문서는 초안으로 남습니다. 선언의 `model`에는 다음 다섯 키를 더 적을 수 있습니다.

| 키 | 값 |
|----|----|
| `inputModality[]`, `outputModality[]` | 모델의 입력과 출력 종류. 값은 서비스와 같다 |
| `trainingComputeFlops` | 모델 학습에 쓴 연산량(부동소수점 연산 횟수). `"3.2e24"`나 `"1500000"`처럼 문자열로 적은 양의 10진수 |
| `trainingComputeBasis` | 그 수치를 산정한 방법을 적은 글 |
| `adversarialTesting` | 적대적 시험을 했는지. `yes`, `no`, `noAssertion` |

SPDX 3.0.1 문서에서 서비스는 `software_primaryPurpose`가 `application`인 `ai_AIPackage`이며, 범위(scope)가 `runtime`인 `dependsOn` 관계로 모델과 이어집니다. 외부 모델은 각각 용도가 `model`인 `software_Package`입니다. 데이터 흐름, 입력과 출력 종류, 모델의 규제 값은 CycloneDX 속성 확장으로 들어갑니다. `bomlens:service:dataFlow`(흐름마다 하나, serviceData를 압축한 JSON 문자열), `bomlens:service:input`과 `:output`, `bomlens:model:input`과 `:output`, `bomlens:regulatory:*`입니다.

스캔은 같은 내용을 CycloneDX SBOM에도 기록합니다. 선언한 데이터셋 원천을 읽은 다음, 위험 판정과 G7 검사보다 먼저 도는 단계입니다.

| 위치 | 내용 |
|------|------|
| `services[]`, bom-ref `service:declared/<이름>` | 서비스. `name`, `version`, `provider.name`, `endpoints[0]`(서비스 주소), `description`(용도), `data[]`(serviceData 형식의 데이터 흐름), 유형이 `documentation`인 `externalReferences` 항목(공개 페이지), 그리고 `bomlens:service:domain`, `:autonomyType`, `:input`, `:output`, `:releaseTime` 속성 |
| `services[]`, bom-ref `service:declared-external/<key>` | 외부 모델마다 하나. `name`, `version`, `provider.name`, `endpoints`, `bomlens:service:declarationKey` |
| `dependencies[]` | 서비스가 모델의 bom-ref와 각 외부 모델에 의존 |
| `declarations.claims[]` | 표준마다 하나. 대상(target)은 서비스, 서술(predicate)은 표준 이름, 근거(reasoning)는 "publisher's declaration, not verified by BomLens" |
| 모델 컴포넌트 | `bomlens:regulatory:trainingComputeFlops`, `:trainingComputeBasis`, `:adversarialTesting` 속성과, `modelCard.modelParameters.inputs[]`와 `outputs[]`에 적은 입력과 출력 종류(`{"format": "text"}`) |

이렇게 기록한 서비스에는 모두 `bomlens:origin=declared-input`과 `bomlens:service:kind`(`application` 또는 `external-model`)가 붙고, 서비스 본체에는 `bomlens:service:declarationDigest`도 붙습니다. 모델 컴포넌트에는 선언에서 채운 위치마다 `bomlens:declared` 속성이 붙습니다. 값은 속성 이름이나 `modelCard` 경로이며, 이 단계가 `modelCard`나 `modelCard.modelParameters`를 새로 만들었다면 그 경로도 적습니다. 스캔이 이미 입력이나 출력을 기록했다면 그 값을 그대로 두고 `bomlens:declared:observedKept` 속성에 그 위치를 적습니다. `bomlens:model:declarationDigest`는 모델 값이 어느 선언에서 왔는지 기록합니다. 선언한 형식을 담으려고 새로 만든 `modelCard.modelParameters`는 G7 검사에서 모델 카드로 세지 않습니다. 이 단계는 같은 SBOM에 여러 번 돌려도 됩니다. 이전 실행이 쓴 내용을 먼저 지우므로, 서비스가 없는 선언을 적용하면 예전 서비스가 지워집니다. SPDX 변환기가 거부한 선언은 아예 적용하지 않습니다.

G7 시스템 속성 요소는 선언한 서비스를 읽고, 이렇게 충족된 요소는 "있음 (발행자 선언, BomLens가 확인하지 않음)"으로 나옵니다. SPDX 2.3 내보내기와 `--diff`는 서비스를 다루지 않습니다. BomLens v1.13 이하는 `service`나 새 모델 키가 있는 선언을 "unknown key(s)" 오류로 거부합니다.

## 소스 스캔의 AI 사용 기록

소스 스캔은 스캔한 코드가 쓰는 AI도 기록합니다. `--model`과는 별개의 기능입니다. 모델 카드를 읽지 않고, 코드가 호출하는 대상과 프로젝트가 AI 도구를 쓰도록 설정된 내용을 목록으로 남깁니다. 기본으로 실행됩니다.

| 항목 | 기록 위치 | 예 |
| --- | --- | --- |
| 코드가 참조하는 모델 | `components[]`, 유형 `machine-learning-model` | `pkg:generic/openai/gpt-4o`인 `gpt-4o`, `pkg:huggingface/...`인 `meta-llama/Llama-3.1-8B-Instruct` |
| 코드가 호출하는 AI 서비스 | `services[]`, 호출에 쓰는 모델은 `dependencies[]` | OpenAI API |
| 설정 파일에 있는 MCP 서버 | `services[]` | `.vscode/mcp.json`이나 `.cursor/mcp.json`의 서버 |
| MCP 설정 파일 | `components[]`, 유형 `file` | `.vscode/mcp.json` |
| 에이전트 지침 파일 | `components[]`, 유형 `file`, SHA-256 포함 | `AGENTS.md`, GitHub Copilot `copilot-instructions.md`, `.cursor/rules/*.mdc` |

각 항목에는 `bomlens:ai:usage`(`model`, `ai-service`, `mcp-server`, `mcp-config`, `instruction-file`)와 `bomlens:ai:scope`가 붙습니다. `bomlens:ai:scope`는 코드가 호출하는 것이면 `runtime`, 편집기와 에이전트 설정이면 `development`입니다.

검토해야 할 MCP 서버에는 `bomlens:ai:reviewReason`이 하나 이상 붙습니다.

- `broad-filesystem-access`: 파일 시스템 루트나 홈 폴더를 넘겨받습니다.
- `unpinned-package`: 버전 없이 `npx`나 `uvx`로 실행되어, 새 릴리스가 검토 없이 실행됩니다.
- `unencrypted-transport`: 다른 호스트에 평문 `http`로 접속합니다.

MCP 서버에 넘기는 환경 변수 값과 헤더(토큰 등), 프롬프트 문구는 복사하지 않습니다. 접속 주소에서는 사용자 정보, 쿼리, 프래그먼트를 지웁니다.

이 항목들은 목록으로만 보여 주고 측정하지 않습니다. 적합성 검사와 NOTICE에서 빠지고, 모델 위험 판정도 허브에서 조회한 모델(아래)이 아니면 빠지며, 코드가 호출만 하는 모델에는 G7 검사를 적용하지 않습니다. 이 스캔에는 그 모델의 카드가 없기 때문입니다. 모델 자체를 점검하려면 `--model`로 스캔합니다.

탐지는 cdxgen의 `ai`, `mcp` 분석을 쓰며, 이 분석은 텍스트를 맞춰 보는 방식입니다. BomLens는 모델 식별자 형태이고 시험 코드나 문서가 아닌 코드에 나온 모델만 남기고, AI 서비스는 그런 모델이 연결된 경우에만 남깁니다. 그래도 프로젝트가 자료 구조에 나열한 모델은 놓칠 수 있고, 모델 식별자처럼 생긴 문자열이 기록될 수 있습니다. 이 단계를 끄려면 `BOMLENS_NO_AI_USAGE=1`을 설정합니다.

### Hugging Face에서 모델 조회

코드가 참조하는 모델은 이름과 purl만 목록에 올라옵니다. `--resolve-models`(또는 새 스캔 화면의 옵션)를 켜면 스캔이 각 `pkg:huggingface/...` 모델을 Hugging Face 허브에 조회해 그 항목에 요약을 덧붙입니다.

- 모델 카드가 밝힌 라이선스. 적힌 그대로(`llama3.1`)이며 SPDX 식별자로 추측하지 않고, 그 라이선스에 대한 모델 위험 판정도 함께 보여 줍니다. 이 판정은 기반 모델의 라이선스도 읽습니다.
- 가중치 파일 형식, 그중 pickle 파일의 수(불러올 때 코드를 실행할 수 있음), 허브가 해시를 가진 파일마다의 SHA-256. 이 값들은 기록만 하고 판정에는 읽지 않습니다.
- 저장소의 접근 제한(gated) 여부(허브는 토큰 없이도 접근 제한 저장소를 설명함), 허브의 현재 리비전과 그 시각(코드가 실제로 불러오는 리비전과 같다고 볼 수는 없음).
- 카드가 밝힌 기반 모델 계보와 각 기반 모델의 라이선스.

허브가 오류로 답한 모델은 HTTP 상태와 함께 `unreadable`로 표시합니다. 비공개 저장소이거나 없는 저장소이며, 허브는 둘 다 같은 방식(401)으로 답합니다. 읽을 수 있는 비공개 모델이면 `HF_TOKEN`을 설정합니다. 허브가 답하지 않았거나 429나 5xx로 답했거나 시간이 모자란 모델은 `unreachable` 또는 `not-attempted`로 표시하고, 이 단계를 실패로 기록합니다(SBOM은 그대로 기록됩니다). 추측해서 채우는 값은 없습니다. 조회하는 모델은 `MODEL_RESOLVE_MAX`(20)개까지이고, 기반 모델 조회를 포함한 전체 조회 시간은 `MODEL_RESOLVE_BUDGET`(240초)까지입니다. 나머지는 `not-attempted`로 표시합니다. `gpt-4o`처럼 허브 페이지가 없는 호스팅 모델은 그대로 둡니다.

이 요약은 모델 자체의 SBOM이 아닙니다. 모델 카드와 `--model`이 실행하는 검사가 필요하기 때문입니다. 전체 SBOM을 만들어 소스 SBOM에 연결하려면 모델을 스캔한 뒤 그 파일을 넘깁니다.

```bash
./scripts/scan-sbom.sh --project my-llm --version 1.0 --model "meta-llama/Llama-3.1-8B-Instruct"
./scripts/scan-sbom.sh --project my-app --version 1.0 --target ./my-app \
  --model-sbom my-llm_1.0/my-llm_1.0_bom.json
```

그러면 모델이 CycloneDX BOM-Link(`externalReferences` 유형 `bom`, `urn:cdx:<일련번호>/<버전>#<bom-ref>`)로 그 파일과 연결되어, 소스 SBOM을 읽는 쪽이 전체 SBOM을 찾을 수 있습니다. 링크는 문서를 일련번호로 가리키므로, 소스 SBOM을 전달할 때 모델 SBOM도 함께 전달합니다. 일련번호가 없는 파일이나 코드가 참조하지 않는 모델의 파일은 알리고 제외합니다. 요약의 라이선스와 가중치 파일은 스캔 시점에 허브에서 읽은 값이므로, 완전한 정보는 연결된 SBOM을 기준으로 봅니다.

## SBOM 구조

```
bomFormat          "CycloneDX"
specVersion        "1.6" (--spec-version 1.7이면 "1.7")
metadata
  ├── timestamp    생성 시각 (ISO 8601)
  └── component    프로젝트 정보 (name, version, type)
components[]
  ├── type         "library" | "framework" | "application"
  ├── name         컴포넌트 이름
  ├── version      버전
  ├── purl         Package URL (고유 식별자)
  ├── supplier     컴포넌트 공급자 (패키지 메타데이터에 있을 때)
  └── licenses[]   라이선스 정보 (SPDX ID)
compositions[]     의존성 그래프 완전성 (아래 참고)
```

언어별 PURL 형식은 [지원 생태계](ecosystems.ko.md)를 참고하세요.

컴포넌트의 `supplier.name`은 패키지 메타데이터에 이미 적힌 값으로만 채웁니다. 생성 도구가 읽은 `publisher`(Maven POM의 `<organization>`, npm 게시자), `authors`(PyPI, RubyGems, Composer), 예전 형식의 `author` 필드 순서로 처음 있는 값을 씁니다. 값 안의 꺾쇠괄호 부분은 지우고, 괄호나 대괄호는 안에 이메일 주소나 URL만 있을 때 지웁니다. 그래서 npm 형식 `Name <email> (url)`의 이메일 주소와 URL이 빠지고, `Example (Holdings), Inc.`처럼 다른 내용이 든 괄호는 그대로 남습니다. 괄호 밖에 있는 이메일 주소와 URL(`http://`, `https://`, `ftp://`, `www.`)도 지우며, 그 앞에 닫히지 않은 괄호가 있으면 함께 지웁니다. 그래서 `Alice <a@x.org>, Bob <b@y.org>`는 `Alice, Bob`, `Jane Doe jane@example.org`는 `Jane Doe`, `Bob <b@x.org>; Carol <c@y.org>`는 `Bob; Carol`이 됩니다. 이메일 주소나 URL만 있는 값은 쓰지 않으며, 작성자가 여럿이면 쉼표로 잇습니다. 어느 필드에서 왔는지는 `bomlens:supplierSource` 속성(`publisher`, `authors`, `author`)에 남습니다. 세 필드가 모두 없는 컴포넌트에는 공급자를 넣지 않고, 이미 공급자가 있는 컴포넌트는 그대로 둡니다. 하위 컴포넌트(`components[].components`)에도 같은 규칙을 적용합니다. 배포판과 펌웨어 패키지(`pkg:deb`, `pkg:rpm`, `pkg:apk`, `pkg:alpm`, `pkg:opkg`, `pkg:generic`)와 `operating-system` 컴포넌트에는 공급자를 넣지 않습니다. 생성 도구가 이 패키지에서 읽는 게시자는 패키지 관리자이고 대개 개인 한 명이며, 배포판 이름을 추정해 대신 넣지도 않습니다. `--analyze`로 받은 공급사 SBOM과 `--merge` 결과는 작성된 그대로 둡니다.

소스 스캔은 프로젝트가 버전을 고정했는지도 `metadata.component.properties`에 기록합니다. `bomlens:source:versionPinning` 값이 `pinned`이면 lock 파일이 있거나 `requirements.txt`의 모든 줄에 정확한 버전이 있는 것이고, `unpinned`이면 `requirements.txt`, `package.json`, `pyproject.toml`, `setup.py`, `setup.cfg` 옆에 lock 파일이 없고 모든 버전이 고정되어 있지 않은 것입니다. `unpinned`일 때 SBOM의 버전은 스캔한 날 새로 설치하면 받게 될 버전이어서, 실제로 실행한 버전과 다를 수 있습니다. 웹 UI가 안내를 보이고, 위험 보고서는 취약점 집계 아래에 같은 내용을 적습니다. 버전을 설치된 상태에서 읽었으면 두 곳 모두 이 안내를 하지 않습니다. 설치된 Python 환경(`bomlens:python-environment`)이나, 스캔 루트에서 npm 또는 pnpm이 설치할 때 써 둔 lock 파일(`bomlens:node-lock-source`)을 읽은 경우입니다. 오프라인 npm install이 npm 캐시로 의존성을 모두 해석했으면(`bomlens:prep-step-applied`의 `npm-offline-cache`) 웹 UI 안내는 그 캐시에서 버전을 정했다고 알립니다. 스캔이 판단하지 못했으면 이 속성은 없습니다.

사용자의 Maven 로컬 저장소를 읽은 Maven 소스 스캔은 `metadata.properties`에 속성 두 개를 기록합니다. `bomlens:maven-user-repository`는 `read-only`입니다. `bomlens:maven-offline`은 Maven이 내려받을 저장소가 응답하지 않아 BomLens가 `-o`를 더했으면 `probe`, 사용자의 설정이 이미 Maven을 오프라인으로 실행하게 했으면(`<offline>true</offline>` 또는 `-o`) `settings`, 그 밖에는 `false`입니다. 저장소를 붙이지 않았거나 비어 있었으면, 트리에 `pom.xml`이 없으면, `BOMLENS_MAVEN_USER_REPOSITORY=false`로 두었으면 두 속성 모두 없습니다([Java (Maven)](ecosystems.ko.md#java-maven)).

사용자의 Gradle 캐시를 읽은 Gradle 소스 스캔은 `metadata.properties`에 `bomlens:gradle-user-cache`를 기록합니다. 빌드가 쓰는 저장소가 응답해 Gradle이 평소대로 실행했으면 `online`, 하나도 응답하지 않아 Gradle이 `--offline`으로 캐시에서만 해석했으면 `offline`입니다. 캐시를 붙이지 않았거나, Gradle 빌드가 아니거나, `BOMLENS_GRADLE_USER_CACHE=false`로 두었으면 이 속성은 없습니다([Java (Gradle)](ecosystems.ko.md#java-gradle)).

패키지 저장소가 응답하지 않거나 `pip install`이 실패해 프로젝트에 설치된 가상 환경을 읽은 Python 소스 스캔은 `metadata.properties`에 `bomlens:python-environment`(스캔 루트 기준 환경 폴더, 예: `.venv`)와 `bomlens:python-environment-reason`(`index-unreachable` 또는 `pip-install-failed`)을 기록합니다. `bomlens:python-environment-unsure`는 확정하지 못한 것이 있을 때만 붙고 그 내용을 적습니다(판정하지 못한 환경 마커, 선언했지만 설치되지 않은 패키지, 선언한 고정 버전과 다른 설치 버전 등). 이때 결과는 `installed-environment-unsure` 사유의 부분 결과이고 `compositions[0].aggregate`는 `incomplete`입니다. 환경을 읽지 않았거나 `BOMLENS_PYTHON_VENV=false`로 두었으면 세 속성 모두 없습니다([Python](ecosystems.ko.md#python)). 환경 폴더 자체는 읽었든 아니든 스캔의 탐색에서 빠지고, 그 패턴(`.venv/**`)은 `BOMLENS_INCLUDE_NON_SHIPPED=1`일 때도 `bomlens:excluded-paths`에 들어갑니다.

커밋한 lock 파일 대신 npm이나 pnpm이 설치할 때 써 둔 lock 파일을 읽은 Node.js 소스 스캔은 `metadata.properties`에 `bomlens:node-lock-source`를 기록합니다. 읽은 파일마다 하나씩 남고, 값은 스캔 루트 기준 상대 경로입니다(예: `node_modules/.package-lock.json`, `web/node_modules/.pnpm/lock.yaml`). 이때 `bomlens:prep-step-applied`에는 `npm-installed-lock` 또는 `pnpm-installed-lock`이 들어갑니다. 모든 폴더에 자체 lock 파일이 있었거나, lock을 읽지 않았거나, `BOMLENS_NODE_INSTALLED_LOCK=false`로 두었으면 이 속성은 없습니다([Node.js](ecosystems.ko.md#nodejs)).

의존성 분석이 SBOM을 만들었지만 그동안 패키지 저장소가 일부 다운로드의 로그인을 거부했으면(HTTP 401 또는 403) 소스 스캔은 `metadata.properties`에 `bomlens:registry-refused`를 `registry-auth` 값으로 기록합니다. 일부 의존성이 빠졌을 수 있다는 뜻이므로 `compositions[0].aggregate`는 `incomplete`입니다. 결과 완전성 등급은 이 속성 때문에 바뀌지 않습니다. 로그에서 찾은 거부가 빠진 의존성으로 이어졌는지는 스캔이 확인할 수 없기 때문입니다. 웹 UI는 개요에 안내를 보입니다([사내 네트워크에서 스캔하기](../guides/company-network.ko.md)). 의존성 분석이 아예 실패한 경우는 이 속성 대신 `bomlens:sbom-tool-degraded`의 `registry-auth`로 기록됩니다.

## 의존성 그래프 완전성

생성된 SBOM은 의존성 그래프가 얼마나 완전한지 나타내는 `compositions[0].aggregate` 항목을 담습니다.

| 값 | 의미 |
|----|------|
| `complete` | 그래프가 완전히 해석됐다는 적극적인 근거를 찾았습니다. 생태계의 lock/resolve 단계가 성공했거나 lock 파일이 이미 커밋돼 있었고, 의존 엣지가 하나 이상 있는 경우입니다. |
| `incomplete` | 스캔에 알려진 실패가 있었습니다. cdxgen 대신 syft 폴백이 돌았거나, 펌웨어 패키지 목록화 단계가 실패했거나, `poetry.lock`이 없는 Poetry 프로젝트를 일부만 변환했거나 그 의존성을 풀지 못했거나, 설치된 Python 환경을 읽었는데 확정하지 못한 것이 있거나(`bomlens:python-environment-unsure`), 패키지 저장소가 일부 다운로드를 거부한(`bomlens:registry-refused`) 경우입니다. |
| `unknown` | 그래프가 완전하다고 확인해 주는 근거가 SBOM에 없습니다. 어느 쪽으로도 적극적인 근거가 없을 때의 기본값이며, 예를 들면 image/rootfs/firmware/binary 스캔(syft 혼자서는 패키지 사이 의존 관계를 못 봄), AI 모델·데이터셋·병합 SBOM, Maven 소스 스캔(해석이 됐는지 저하됐는지 가릴 신뢰할 수 있는 신호가 없음)이 여기 해당합니다. `unknown`은 결함이 아닙니다. 도구가 판단할 근거를 찾지 못했다는 뜻일 뿐, 뭔가 잘못됐다는 뜻이 아닙니다. |

분석 대상 공급사 SBOM이 자체 `compositions` 선언을 이미 가지고 있다면 절대 덮어쓰지 않습니다.

적합성 검사 보고서의 전이 의존성 검사는 이 값을 detail 문구에 덧붙입니다(예: "12 edge(s), declared complete"). 통과/실패 판정에는 영향을 주지 않습니다.

전처리 단계가 돌았거나 이미 커밋된 lock 파일로 충족된 경우, 성공·실패와 무관하게 `bomlens:prep-step-applied` 속성에 기록됩니다. `bomlens:pipeline-step-failed`는 실패만 기록합니다. 위 `aggregate` 값은 둘을 함께 봐서 정해집니다. `bomlens:pipeline-step-failed`의 `license-fetch`는 패키지 저장소가 응답하지 않아 이번 스캔에서 저장소 라이선스 조회를 껐다는 뜻이며, SBOM에는 lock 파일과 패키지 매니페스트에 든 라이선스만 들어 있습니다. 빠지는 의존성은 없고 완전성 판정도 바뀌지 않습니다. CLI는 이를 `[INFO]` 한 줄로 알리고, 웹 UI는 불완전한 데이터가 아니라 안내 메모로 보여 줍니다. `cocoapods-licenses`는 CocoaPods trunk가 응답하지 않아(또는 조회 시간이 다 되어) 일부 pod가 라이선스 없이 남았다는 뜻입니다. 완전성 판정은 바뀌지 않으며, 마지막 요약의 실패한 단계 목록에 나옵니다.

실패한 단계에는 빌드 도구가 보고한 내용이 `bomlens:pipeline-step-cause`(`<단계>: <문장>`, 예를 들어 Gradle의 `What went wrong` 내용 첫 줄)로 붙고, 해결 방법이 따로 있는 원인은 `bomlens:resolution-hint`로 붙을 수 있습니다. 원인 코드는 `maven-parent-outside-scan`(부모 POM이 있는 폴더 없이 스캔한 Maven 모듈), `android-useandroidx-missing`(`android.useAndroidX=true`가 없는 안드로이드 빌드), `android-release-classpath-unresolved`(안드로이드 빌드가 release 런타임 클래스패스를 읽기 전에 실패해 다른 구성의 빌드 도구를 제외함)입니다. 완전성 결과는 그 원인을 인용하고 일반 안내 대신 해당 원인의 해결 방법을 보여 주며, `android-release-classpath-unresolved`가 있으면 등급이 unreliable이 됩니다. 이 코드의 해결 방법(Gradle 오류를 해결한 뒤 다시 스캔)은 구체적인 해결 방법을 가진 다른 원인이 없을 때만 나옵니다. 그래서 `android-useandroidx-missing`과 함께 붙으면 해결 방법에는 그 속성만 나오고, 두 원인의 설명은 모두 남습니다.

## 적합성 검사 보고서

행 목록과 검사 기준별 판정은 [적합성 검사 보고서 읽기](../guides/supplier-sbom.ko.md#적합성-검사-보고서-읽기)에 요약되어 있습니다. 이 절에는 그 판정의 세부 규칙을 적습니다.

- 네임스페이스. OS 패키지뿐 아니라 purl-spec이 네임스페이스를 필수로 규정한 모든 타입을 봅니다. groupId가 빠진 `pkg:maven` 식별자나 배포판을 `?distro=` 한정자로만 적은 `pkg:rpm` 식별자는 형식은 맞지만 어떤 패키지에도 연결되지 않습니다. `pkg:golang`과 `pkg:huggingface`는 권고 행으로 따로 보고합니다. Go 모듈 경로는 호스트 이름 하나일 수 있고, 조직 없이 공개된 모델에는 소유자 구간이 없기 때문입니다.
- 최상위 컴포넌트 이름. 일부 생성 도구는 제품명 대신 고정값(`.`, `..`, `/`, `/scan`)을 적고, 그러면 서로 다른 제품의 SBOM이 충돌합니다. 다른 제출물과 이름이 겹치는지는 접수 시스템이 판단할 일이라 이 검사로는 알 수 없습니다.
- PURL 타입. 타입 목록은 `docker/lib/purl-types.json`에 있습니다. 표시용 이름에서 식별자를 되돌려 만드는 생성 도구는 규격에 없는 타입을 만들어 내기도 합니다(`pkg:applications/java@11.0.25`). `skt-submission`은 SourceForge나 GNU 사이트에 공개된 프로젝트의 릴리스를 가리키는 `pkg:sourceforge`와 `pkg:gnu`도 받아들입니다.
- OS 패키지 네임스페이스 값. `rpm`, `deb`, `apk` 식별자의 네임스페이스에는 패키지 저장소가 배포판에 쓰는 식별자(`rhel`, `debian`, `ubuntu`, `alpine`)가 와야 하며, `pkg:rpm/examplevendor/glibc@…`처럼 회사 이름을 쓰면 그런 식별자가 아닙니다. `docker/lib/os-distros.json`에 없는 값은 해당 식별자 수와 함께 알려 줍니다. SBOM의 operating-system 구성요소 이름이나 같은 식별자의 `distro=` 한정자에 적힌 배포판 id와 같은 네임스페이스도 받아들이며, 스스로 배포판을 선언한 자체 배포판이 여기에 해당합니다. 네임스페이스가 아예 없는 경우는 네임스페이스 행에서 셉니다.
- 버전 값. 공백이 있는 값, `키: 값` 형태(매니페스트 줄이 버전으로 읽힌 `Specification-Vendor: The Apache Software Foundation` 등), 제어 문자가 있는 값, 128자를 넘는 값을 최대 50개까지 `name@version` 형태로 알려 줍니다.
- 수정 제안. 네임스페이스 행이나 버전 행에 걸린 구성요소에는 "수정 제안" 절(JSON의 `suggestions`)이 후보를 보여 줍니다. 후보는 규칙 하나가 답을 하나로 정할 때만 냅니다. `distro=` 한정자나 하나뿐인 operating-system 구성요소가 가리키는 배포판, Maven `group` 필드, 앞뒤 공백만 있는 버전이 그 규칙입니다. 배포판은 패키지 유형에 맞아야 하고(`apk`에는 `alpine`, `deb`에는 `debian`), 인식되지 않는 `distro=` 한정자는 후보도 대체 규칙도 없이 처리합니다. `group` 필드는 신뢰도 중간의 참고 값이며, purl 이름에 콜론이 있거나 이름이 group으로 시작하면 쓰지 않습니다. 후보마다 근거와 신뢰도를 적고, 답이 모호하면 후보 대신 기반 배포판처럼 무엇이 필요한지 적습니다. 제안은 파일 내용만으로 만들며 네트워크 조회를 하지 않고, 제출된 파일은 바꾸지 않습니다. 공급사가 SBOM을 직접 고쳐 다시 제출해야 합니다. `.md`와 `.html` 보고서에는 앞의 50개만 보여 줍니다.
- 버전 보충 필요와 upstream purl 없음(`skt-submission`에서만). "버전 보충 필요"는 버전도 사유도 없는 컴포넌트가 있을 때만 실패합니다. 공급사가 버전 대신 사유(`own-code`, `not-open-source`, `version-unknown`)를 적은 컴포넌트는 "공급사 소명" 절(JSON에서는 `explained`)에 나오며, 이 목록이 비어 있지 않아도 행은 통과할 수 있습니다. `--analyze`에서는 SBOM의 `bomlens:versionReason` 속성에서 사유를 읽습니다. "upstream purl 없음"은 버전은 있지만 소스 저장소를 가리키는 purl이 없는 컴포넌트 목록입니다. 경고이고 공급사가 고칠 항목이 아니며, 해당 컴포넌트는 SK텔레콤이 따로 확인합니다. `--analyze`에서는 앞 행이 공급사에 고친 SBOM을 요청하라고, 뒤 행이 최신 BomLens로 다시 스캔해 달라고 요청하라고 안내합니다. 펌웨어, 루트 파일시스템, 바이너리를 스캔한 공급사는 `{Project}_{Version}_component-versions.template.csv`에 버전이나 사유를 적고 `--component-versions`로 다시 스캔합니다([펌웨어 가이드](../guides/firmware.ko.md#스캔이-읽지-못한-버전-채우기)). BomLens가 직접 실행한 스캔이면 제출할 파일이 `{Project}_{Version}_bom.json` 하나라는 점도 요약에 적습니다.
- `skt-submission`에서 펌웨어, 루트 파일시스템, 바이너리, Yocto 빌드 스캔. 찾은 파일에서 값을 가져오므로 네임스페이스 값 행과 버전 행이 실패 대신 경고입니다. 일반 행도 위 두 행이 이미 다루는 컴포넌트 때문에 실패하지 않고, 경고로 바뀐 이유를 상세 내용에 적습니다. name/version 포함률은 버전이 없는 컴포넌트에 모두 사유가 있으면, PURL 포함률은 purl이 없는 컴포넌트가 모두 소명되었거나 버전이 있으면, "추적 가능한 PURL (pkg:generic 없음)"은 `pkg:generic` 컴포넌트가 모두 버전이나 사유를 가지면 경고입니다. 추이적 의존성 행도 경고입니다. 이런 스캔은 의존성 그래프가 아니라 찾은 패키지를 기록하기 때문입니다. 버전도 사유도 없는 컴포넌트가 하나라도 있거나 SBOM에 패키지가 하나도 없으면 완화하지 않습니다. 이런 스캔은 `metadata.properties`에 `bomlens:scanMode`(`FIRMWARE`, `ROOTFS`, `BINARY`, `YOCTO`)를 기록하고, `--analyze`도 이 값이 있는 SBOM을 같은 방식으로 판정하며 그 사실을 요약에 적습니다. 소스 스캔과 `--analyze`로 점검하는 다른 SBOM은 이 행들을 측정한 그대로 판정합니다. 기본 기준은 달라지지 않습니다.
- 자체개발 구성요소. 자체 빌드 산출물은 패키지 저장소에 없으므로 purl이 없습니다. 선언 파일(`--components`, 또는 스캔 루트의 `sbom-declared.cdx.json`)에 `bomlens:origin`을 `first-party`로 적고 공급자와 `bomlens:artifact`의 빌드 산출물(여기서 SHA-512를 얻음)을 함께 적은 구성요소는 PURL 포함률, "추적 가능한 PURL (pkg:generic 없음)", "upstream purl 없음" 행에서 빠지고, 권고 행 "purl 대신 공급자와 SHA-512로 식별한 자체개발 구성요소"에 이름이 나옵니다. 이 예외는 선언 파일을 읽은 그 스캔에서만 적용됩니다. `--analyze`로 점검하는 SBOM의 `first-party` 구성요소와 선언 파일의 `third-party` 구성요소에는 여전히 purl이 필요합니다.
- 패키지와 파일 구성요소. name/version과 PURL 포함률은 패키지 구성요소만 셉니다. 바이너리와 펌웨어 SBOM은 전달된 파일도 싣는데, 파일에는 패키지 버전도 PURL 타입도 없으므로 파일 구성요소 식별자 행이 해시가 있는 파일의 비율을 잽니다. 패키지 없이 파일만 실린 SBOM은 실패입니다. 취약점 매칭이 패키지 식별자를 키로 삼기 때문입니다.
- 권장 행. 라이선스와 hash 포함률 외에 SHA-512 체크섬 포함률, 컴포넌트 작성 주체, 컴포넌트 파일명, 소스·배포 URI, 전달 파일 속성(스캔으로 확인할 수 없으면 검토 필요), 파일 구성요소 식별자 포함률이 있습니다. 2026년 최소 요소 중에는 필드가 비어 있는 이유를 밝히라는 항목이 있습니다. BomLens가 생성한 SBOM은 문서 전체에 대해 그 이유를 적고, 받은 SBOM이 아무 말도 하지 않으면 이 항목을 공백으로 보고합니다.
- `--resolve-purl`을 붙이면 권고 행이 하나 더 붙으며, 적합성 검사에서 네트워크를 쓰는 유일한 부분입니다. 식별자가 실제 있는 패키지를 가리키는지 각 패키지 저장소에 조회해, 형식은 맞지만 저장소에 없는 식별자를 잡습니다. `pkg:maven/org.drools/org.drools.drools-core-dynamic@…`(artifactId 안에 groupId가 한 번 더 들어감)이나 `pkg:maven/The%2BApache%2BSoftware%2BFoundation/poi@…`(groupId 자리에 회사 표시 이름)가 그 예입니다. 사내 저장소에만 올린 패키지도 같은 결과가 나오므로 판정을 바꾸지 않으며, 사내 네임스페이스는 `PURL_RESOLVE_IGNORE`로 제외합니다. 버전이 아니라 좌표만 확인합니다. 벤더가 다시 빌드한 버전은 정상이면서도 공개 저장소에 없기 때문입니다.
- 검사하지 않는 것. 서버 납품에 OS 패키지가 들어 있는지, OS 패키지 purl이 실제 설치된 배포판을 가리키는지(RHEL 서버에 `pkg:deb/debian/...`이 붙어 있어도 통과합니다), 파일 기본 점검(확장자, 크기, JSON 문법)은 보지 않습니다. 이런 항목은 [점검표](https://sktelecom.github.io/guide/supply-chain/for-suppliers/checklist/)로 확인하세요.
- 규제 참고 정보. 규제 기준선과 대응되는 행에는 그 아래에 참고 규정이 붙고, 크로스워크 절이 프레임워크별 충족 현황을 집계합니다. 대상은 BSI TR-03183-2(EU 사이버복원력법을 위한 독일 기술지침)와 미국 SBOM 최소 요소(2026년판)입니다. 크로스워크는 참고 자료이며 준수 판정을 하지 않습니다. 동작 방식은 아래 [규제 크로스워크](#규제-크로스워크)에서 설명합니다. HTML 보고서 상단 카드에는 판정과 누락 항목이 표시됩니다.

### 규제 크로스워크

AI 여부와 관계없이 분석하는 모든 SBOM에는 두 가지 프레임워크가 매핑됩니다.

- EU 사이버복원력법(CRA): CRA 준수를 위해 작성된 독일 기술지침이자 공개된 것 중 가장 상세한 SBOM 필드 명세인 BSI TR-03183-2를 통해 연결합니다(CRA 본문은 데이터 필드를 지정하지 않습니다). TR-03183-2는 국가 지침이며, 구속력 있는 문구를 담을 유럽 조화 표준은 아직 초안 단계입니다.
- 미국 SBOM 최소 요소: 2026년판 최소 요소의 데이터 필드 17개와 운영 원칙 6개. CISA와 NSA, FBI가 15개 해외 기관과 함께 발표했고 2021년 NTIA 문서를 대체합니다. 이후 연방 차원의 SBOM 수집 의무는 기관별 위험 기반 판단으로 축소되었지만, 개별 기관이 요구하는 실무 기준으로는 여전히 유효합니다.

위 크로스워크는 SBOM 데이터 필드만 다룹니다. 이 필드가 속한 CRA 준비 절차 전체(거버넌스, 취약점 대응, 기술문서, 보안 업데이트)는 커뮤니티가 관리하는 [OpenChain CRA Compliance Requirements & Checklist](https://github.com/OpenChain-Project/CRA-Compliance)를 참고하세요.

AI SBOM에는 EU 인공지능법(AI Act)과 한국 AI 기본법도 G7 요소에 매핑됩니다. 대응하는 조항은 [AI 모델 SBOM 가이드](../guides/ai-model.ko.md#규제-크로스워크)에 있습니다.

매핑은 검사 id를 키로 삼아 `docker/lib/regulation-crosswalk.json`에 있습니다. AI 검사는 G7 요소 id, 기본 형식 검사는 일반 CycloneDX 검사 id를 씁니다. 의도적으로 보수적으로 잡아, 근거가 분명한 검사만 매핑합니다. 현재 검사 id 74개가 네 프레임워크에 걸쳐 84건으로 연결되어 있습니다. 검사 하나가 여러 프레임워크에 연결될 수 있어 두 수치가 다릅니다. 검사 이름이 바뀌어도 크로스워크가 조용히 어긋나지 않도록, 매핑된 모든 id를 레지스트리와 대조하는 테스트를 둡니다.

### 다른 도구가 만든 AI BOM

`--analyze`는 다른 도구가 만든 AI BOM도 읽어 같은 G7 점검과 위험 판정을 돌립니다. k8s-aibom의 CycloneDX 출력, AIsbom, Cisco AI BOM, AIBoMGen CLI 네 가지 도구의 시료로 확인했습니다. 어느 도구도 G7 항목 대부분을 채우지 않으므로 보고서에는 없음으로 나오는 항목이 많습니다. 이는 파일에 든 내용이 그렇다는 뜻이며 읽기가 잘못된 것이 아닙니다.

일부 값은 G7 점검이 예전에 보지 않던 자리에 들어 있어서, 이제 그 자리에서도 읽습니다. 이렇게 채워진 항목의 상세 줄에는 `also read from`과 출처가 붙고, 결과의 `via`에도 담깁니다.

| 항목 | 읽는 곳 | 도구 |
|---|---|---|
| 모델 식별자 | `aisbom:hf:repo_id` | AIsbom |
| 모델 라이선스 | `aisbom:hf:license` | AIsbom |
| 모델 버전 | `aisbom:hf:revision`, `k8s-aibom:model:revision` | AIsbom, k8s-aibom |
| SBOM 생성 맥락 | `metadata.lifecycles`(CycloneDX 표준 필드) | k8s-aibom, AIBoMGen CLI |

AIsbom은 라이선스 판정이 저절로 바뀌지 않게 하려고 허브의 라이선스를 `licenses[]`에 넣지 않습니다. BomLens는 이 값을 있는 것으로 세고, `licenses[]`가 비어 있을 때만 위험 판정에 넘깁니다. 둘 다 있으면 `licenses[]`를 씁니다. 이 값은 허브 페이지가 밝힌 내용이며 BomLens가 검증하지는 않습니다.

그 밖에 이 도구들이 적은 내용은 대응하는 G7 항목이 없습니다. Cisco AI BOM은 에이전트와 MCP 서버를 `application` 구성요소로, k8s-aibom은 모델을 실행하는 워크로드를 기록합니다. 이 내용은 파일과 구성요소 목록에 그대로 남습니다.
