---
description: BomLens가 생성하는 산출물 파일 목록과 생성 조건, 파일명 규칙, SBOM 구조 요약입니다.
---

# 산출물 레퍼런스

생성된 SBOM은 CycloneDX 1.6 JSON 형식입니다. `--spdx`를 켜면 최종 CycloneDX SBOM을 변환한 SPDX 2.3 JSON 파일이 함께 생성됩니다. 이때도 정본은 CycloneDX이며, CycloneDX에만 있는 데이터(취약점, `bomlens:*` 속성)는 SPDX 파일로 옮겨지지 않습니다.

파일명은 `{Project}_{Version}_bom.json`입니다(예: `MyApp_1.0.0_bom.json`).

## 산출물 파일

| 파일 | 생성 조건 | 설명 |
|------|----------|------|
| `{Project}_{Version}_bom.json` | 항상 | SBOM (CycloneDX 1.6) |
| `{Project}_{Version}_bom.spdx.json` | `--spdx` / `--all` | SBOM (SPDX 2.3, CycloneDX 결과를 변환) |
| `{Project}_{Version}_NOTICE.txt` / `.html` | `--notice` / `--all` / 위험분석보고서 기본 | 오픈소스 고지문 |
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / 위험분석보고서 기본 | Trivy 보안보고서 |
| `{Project}_{Version}_risk-report.md` / `.html` | 기본(전 모드) — `--no-report`로 생략 | 오픈소스위험분석보고서 |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | `--analyze` | 포맷 적합성 보고서 |
| `{Project}_{Version}_ai-profile.json` / `.md` / `.html` | AI SBOM (`--model`, 또는 모델 컴포넌트가 있는 SBOM에 `--analyze`) | AI 컴플라이언스 프로파일: G7 요약, 라이선스 표시 컴포넌트, 규제 크로스워크 (참고용, 인증 아님) |
| `{Project}_{Version}_scancode.json` | `--deep-license` | scancode 원본 결과 |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign 서명 (`--spdx`와 함께 쓰면 `_bom.spdx.json.sig`도 생성) |

`{P}`=프로젝트 이름, `{V}`=버전 (특수문자는 `_`로 정규화).

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
