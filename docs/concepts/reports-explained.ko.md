---
description: BomLens가 만드는 오픈소스 고지문과 보안 보고서, 오픈소스위험분석보고서를 읽고 해석하는 방법을 다룹니다.
---

# 보고서 읽는 법

이 문서는 스캔 뒤 BomLens 보고서를 어떻게 읽고 해석하는지를 다룹니다. 생성 방법은 [보고서 생성](../guides/reports.ko.md)을 참고하세요.

## 고지문이 함께 처리하는 것

오픈소스 고지문(NOTICE)은 라이선스별로 컴포넌트를 묶습니다. 그 묶음 외에 고지문은 다음을 함께 처리합니다.

- 라이선스 이름을 SPDX 식별자로 정규화합니다. 예를 들어 "Apache License, version 2.0"은 `Apache-2.0`으로 모읍니다. 같은 라이선스의 표기가 갈려 중복되던 항목이 하나로 합쳐집니다.
- SBOM에 저작권(copyright) 값이 있으면 컴포넌트별로 표시합니다.
- 주요 오픈소스 라이선스 21종(`Apache-2.0`, `MIT`, `BSD-3-Clause`, `GPL`/`LGPL` 계열 등)의 SPDX 표준 전문을 고지문 끝에 함께 묶습니다. 전문 동봉을 요구하는 라이선스의 의무를 별도 수집 없이 충족합니다. 번들 원본은 `docker/lib/licenses/*.txt`에 있습니다.

## 우선순위 신호 (CVSS, EPSS, CISA KEV)

심각도(Severity)만으로는 무엇을 먼저 고칠지 정하기 어렵습니다. 이를 보완하기 위해 보안 보고서는 심각도 외에 세 가지 신호를 함께 보여 줍니다. Markdown과 HTML 표의 열 구성은 `Severity | KEV | CVSS | EPSS | CVE | Package | Installed | Fixed`입니다.

- **CVSS** — 취약점의 기술적 심각도 점수(0~10). V3 점수를 우선 쓰고 없으면 V2로 대체합니다.
- **EPSS** — 향후 30일 내 실제 악용 가능성(0~1)입니다. FIRST.org에서 조회하며, 점수가 높을수록 공격에 쓰일 확률이 큽니다.
- **CISA KEV** — 미국 CISA가 관리하는 "실제 악용된 취약점" 목록에 포함됐는지 여부입니다. 포함되면 HTML 보고서에 ⚠️ 배지로 표시합니다.

표는 KEV 포함 항목을 맨 위에 두고, 그다음 심각도, 마지막으로 EPSS 내림차순으로 정렬합니다. 위에서부터 처리하면 자연히 위험이 큰 것부터 대응하게 됩니다.

EPSS와 KEV는 외부 API 조회가 필요합니다. 폐쇄망에서는 `SECURITY_ENRICH=false`로 두면 두 열을 생략하고 나머지 보고서는 그대로 생성합니다.

## 결과 해석과 후속 조치

| Severity | 의미 | 권장 조치 |
|----------|------|----------|
| **Critical** | 즉시 악용 가능, 심각 | 최우선 패치 — `Fixed` 버전으로 즉시 업그레이드 |
| **High** | 위험도 높음 | 단기 내 패치 계획 수립 |
| **Medium / Low** | 영향 제한적 | 정기 점검 시 처리 |
| **Unknown** | 심각도 미평가 | 해당 CVE를 직접 확인 후 분류 |

- 보고서의 `Fixed` 열에 버전이 있으면, 그 버전 이상으로 의존성을 올리면 해결됩니다. 가장 빠른 1차 대응입니다.
- CI 게이트 예시. Critical이 1건이라도 있으면 빌드 실패:
  ```bash
  crit=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
  [ "$crit" -gt 0 ] && { echo "Critical 취약점 ${crit}건"; exit 1; }
  ```
- 오탐(실제 영향 없음) 판단, 예외 승인, 이력 관리 같은 triage는 BomLens의 범위를 넘습니다. 취약점 관리 시스템(Dependency-Track, TRUSCA 등)에 SBOM을 업로드해 처리하세요.

## 오픈소스위험분석보고서

오픈소스위험분석보고서는 취약점을 심각도별로 집계하고 권고 대응 기한(Critical 7일, High 30일)을 명시합니다. 라이선스 요약도 담고 있으며, 공급사 SBOM을 분석한 경우에는 포맷 적합성 결과가 더해집니다.

## 관련 문서

- [보고서 생성](../guides/reports.ko.md)
- [산출물 레퍼런스](../reference/artifacts.ko.md)
- [BomLens 동작 원리](architecture.ko.md)
