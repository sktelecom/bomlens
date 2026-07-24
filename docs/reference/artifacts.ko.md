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
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / 위험분석보고서 기본 | Trivy 보안보고서 |
| `{Project}_{Version}_risk-report.md` / `.html` | 기본(전 모드) — `--no-report`로 생략 | 오픈소스위험분석보고서 |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | `--analyze` | 포맷 적합성 보고서. AI SBOM이면 G7 검사와 함께, 아직 비어 있는 권고 요소마다 이를 충족하는 CycloneDX 조각을 담는다. 예시는 [적합성 보고서](../samples/aether-7b-5attn_conformance.ko.html)를 참고한다 |
| `{Project}_{Version}_ai-profile.json` / `.md` | AI SBOM (`--model`, 또는 모델 컴포넌트가 있는 SBOM에 `--analyze`) | AI 준수 개요: G7 요약, 메울 수 있는 공백과 참고 링크, 라이선스 표시 컴포넌트, 규제 크로스워크, 모델 위험 판정(`riskAssessment`: 모델별 ok/conditional/caution/review 판정과 조건, 근거, 사용 형태. 법적 자문이 아닌 안내). 같은 요약이 적합성 보고서 HTML 맨 위에 나오므로 별도 HTML은 만들지 않는다 |
| `{Project}_{Version}_scancode.json` | `--deep-license` | scancode 원본 결과 |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign 서명 (`--spdx`와 함께 쓰면 `_bom.spdx.json.sig`도 생성) |

`{P}`=프로젝트 이름, `{V}`=버전 (특수문자는 `_`로 정규화).

위 표의 생성 조건은 CLI 옵션 기준입니다. 웹 UI와 데스크톱 앱에서는 새 스캔 화면의 생성 옵션(고지문, 보안 보고서)이 같은 역할을 하고, 만들어진 파일은 결과 화면의 산출물 섹션에 모두 표시되어 형식별로 또는 ZIP 하나로 내려받을 수 있습니다. SPDX는 스캔 옵션이 아닙니다. 산출물 섹션의 SBOM 카드에 있는 **SPDX 2.3으로 내보내기** 버튼으로 필요할 때 완성된 SBOM을 변환하며, 변환된 파일은 산출물 목록과 ZIP 묶음에 함께 들어갑니다. UI에는 서명 기능이 없어 이렇게 내보낸 SPDX는 서명되지 않으므로, 서명이 필요하면 CLI에서 `--spdx --sign`을 쓰세요. [웹 UI와 데스크톱 앱](ui.md)을 참고하세요.

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
