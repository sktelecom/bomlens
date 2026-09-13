---
description: BomLens가 생성하는 산출물 파일 목록과 생성 조건, 파일명 규칙, SBOM 구조 요약입니다.
---

# 산출물 레퍼런스

생성된 SBOM은 CycloneDX 1.6 JSON 형식입니다. 최종 CycloneDX SBOM을 변환한 SPDX 2.3 JSON 파일은 CLI 스캔에서 `--spdx`로 만들거나, UI에서는 스캔이 끝난 뒤 결과 화면에서 내보냅니다. 두 경로 모두 같은 변환을 거치므로 결과 파일은 동일합니다. 이때도 정본은 CycloneDX이며, CycloneDX에만 있는 데이터(취약점, `bomlens:*` 속성)는 SPDX 파일로 옮겨지지 않습니다.

파일명은 `{Project}_{Version}_bom.json`입니다(예: `MyApp_1.0.0_bom.json`).

## 산출물 파일

| 파일 | 생성 조건 | 설명 |
|------|----------|------|
| `{Project}_{Version}_bom.json` | 항상 | SBOM (CycloneDX 1.6) |
| `{Project}_{Version}_bom.spdx.json` | `--spdx` / `--all`, 또는 UI의 SPDX 2.3으로 내보내기 | SBOM (SPDX 2.3, CycloneDX 결과를 변환) |
| `{Project}_{Version}_NOTICE.txt` / `.html` | `--notice` / `--all` / 위험분석보고서 기본 | 오픈소스 고지문 |
| `{Project}_{Version}_NOTICE.pdf` | 위와 동일한 조건, 이미지에 PDF 렌더러가 포함된 경우(`--build-arg SBOM_PDF=true`) | 고지문을 PDF로 렌더링한 파일. 렌더러가 없으면 로그만 남기고 건너뜀 |
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / 위험분석보고서 기본 | Trivy 보안보고서 |
| `{Project}_{Version}_risk-report.md` / `.html` | 기본(전 모드) — `--no-report`로 생략 | 오픈소스위험분석보고서 |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | 기본(모든 모드) — `--no-report`로 생략, `--analyze`는 이 값과 무관하게 항상 생성(그것이 검증 대상이므로) | 포맷 적합성 보고서. 모든 SBOM에 규제 크로스워크 집계가 함께 담긴다(EU 사이버복원력법은 BSI TR-03183-2로, 2026년판 미국 SBOM 최소 요소 — 참고용이며 준수 판정 아님). AI SBOM이면 G7 검사와 함께, 아직 비어 있는 권고 요소마다 이를 충족하는 CycloneDX 조각을 담는다. 예시는 [적합성 보고서](../samples/aether-7b-5attn_conformance.ko.html)를 참고한다 |
| `{Project}_{Version}_ai-profile.json` / `.md` | AI SBOM (`--model`, 또는 모델 컴포넌트가 있는 SBOM에 `--analyze`) | AI 준수 개요: G7 요약, 메울 수 있는 공백과 참고 링크, 라이선스 표시 컴포넌트, 규제 크로스워크, 모델 위험 판정(`riskAssessment`: 모델별 ok/conditional/caution/review 판정과 조건, 근거, 사용 형태. 법적 자문이 아닌 안내). 같은 요약이 적합성 보고서 HTML 맨 위에 나오므로 별도 HTML은 만들지 않는다 |
| `{Project}_{Version}_scancode.json` | `--deep-license` | scancode 원본 결과 |
| `{Project}_{Version}_files.json` | 소스를 갖는 스캔(펌웨어 스캔은 항상, 다른 모드는 `--deep-license`가 아직 `_scancode.json`을 만들지 않은 경우) | 소스 트리 뷰를 뒷받침하는 ScanCode 형식 파일 트리 인벤토리(구조만, 라이선스 없음) |
| `{Project}_{Version}_source.json` | 소스를 갖는 스캔 | 스캔한 트리의 파일 내용 스냅샷, 파일 뷰어를 뒷받침(스캔한 트리 자체는 컨테이너 종료와 함께 사라짐) |
| `{Project}_{Version}_input.json` | `--analyze` | CycloneDX 변환이 덮어쓰기 전, 공급사 SBOM 원본의 포맷·스펙 버전·도구·작성 정보를 보존 |
| `{Project}_{Version}_yocto_vex.json` | Yocto 빌드(빌드 디렉터리를 직접 지정하거나 그 위에 `--analyze`) | 빌드가 이미 패치했거나 무관하다고 판정한 CVE 건수 — CycloneDX 결과나 보안보고서에는 미해결 항목만 남아 있어 이 수치를 알 수 없다 |
| `{Project}_{Version}_vendored.cdx.json` | 소스 스캔에서 `--identify-vendored`, opt-in SCANOSS 이미지 필요 | 소스 트리 안에서 식별한 번들 오픈소스 컴포넌트(SCANOSS) |
| `{Project}_{Version}_security_epss.json` | 보안보고서를 생성할 때마다 | 취약점별 EPSS 점수와 KEV 여부(오프라인 생성 시 null/false), 보안보고서 우선순위 산정에 사용 |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign 서명 (`--spdx`와 함께 쓰면 `_bom.spdx.json.sig`도 생성) |
| `{new}_model-diff.json` | `--diff <old.json> <new.json>` | 이미 생성한 SBOM 두 개를 비교한 AI 모델 변동 보고서. 매칭된 모델의 판정·라이선스·해시 변화와, 한쪽 파일에만 있는 컴포넌트를 담는다. 새 쪽 입력 파일 이름을 따르며(`<new>_bom.json` → `<new>_model-diff.json`), `{Project}_{Version}`이 아니다 — `--diff`는 프로젝트나 버전을 따로 받지 않는다 |

`{P}`=프로젝트 이름, `{V}`=버전 (특수문자는 `_`로 정규화).

위 표의 생성 조건은 CLI 옵션 기준입니다. 웹 UI와 데스크톱 앱에서는 새 스캔 화면의 생성 옵션(고지문, 보안 보고서)이 같은 역할을 하고, 만들어진 파일은 결과 화면의 산출물 섹션에 모두 표시되어 형식별로 또는 ZIP 하나로 내려받을 수 있습니다. SPDX는 스캔 옵션이 아닙니다. 산출물 섹션의 SBOM 카드에 있는 **SPDX 2.3으로 내보내기** 버튼으로 필요할 때 완성된 SBOM을 변환하며, 변환된 파일은 산출물 목록과 ZIP 묶음에 함께 들어갑니다. UI에는 서명 기능이 없어 이렇게 내보낸 SPDX는 서명되지 않으므로, 서명이 필요하면 CLI에서 `--spdx --sign`을 쓰세요. [웹 UI와 데스크톱 앱](ui.ko.md)을 참고하세요.

## SBOM 구조

```
bomFormat          "CycloneDX"
specVersion        "1.6"
metadata
  ├── timestamp    생성 시각 (ISO 8601)
  └── component    프로젝트 정보 (name, version, type)
components[]
  ├── type         "library" | "framework" | "application"
  ├── name         컴포넌트 이름
  ├── version      버전
  ├── purl         Package URL (고유 식별자)
  └── licenses[]   라이선스 정보 (SPDX ID)
```

언어별 PURL 형식은 [지원 생태계](ecosystems.ko.md)를 참고하세요.
