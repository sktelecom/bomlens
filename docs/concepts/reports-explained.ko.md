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

## 컴포넌트 지원 종료(EOL)

BomLens는 각 컴포넌트의 릴리스 주기가 상위(upstream) 지원 종료(End-of-Life, EOL)에 이르렀는지도 함께 표시합니다. 이는 취약점(CVE)과는 별개의 공급망 위험입니다. 지원 기한이 지난 런타임이나 프레임워크는 상위 보안 패치가 더 나오지 않으므로, 이후 Critical이나 High가 보고돼도 적용할 패치가 없습니다.

- 날짜는 스캐너 이미지에 번들한 endoflife.date 스냅샷에서 가져옵니다. 그래서 이 점검은 네트워크 호출 없이 오프라인으로 동작하며 폐쇄망에서도 쓸 수 있습니다. 출처와 스냅샷 날짜는 표시된 각 컴포넌트에 기록됩니다(`bomlens:eol:source`).
- 커버리지는 endoflife.date를 따릅니다. endoflife.date는 런타임, 주요 프레임워크, 운영체제, 데이터베이스를 다룹니다(spring-boot, express, django, nodejs, python, php, nginx, openssl, ubuntu, debian 등). 규모가 작은 라이브러리 다수는 대상이 아니며, 매핑이 없는 컴포넌트는 추측하지 않고 미표기(unknown)로 둡니다.
- 웹 UI에서는 개요(Overview)에 "지원 종료" 개수 타일이 나오고, 그중 취약점도 있는 컴포넌트는 위험색으로 강조됩니다. 지원 종료 컴포넌트는 자신의 CVE에 대한 상위 패치가 없으므로 실제로 대응해야 할 대상입니다. 컴포넌트 표에는 "지원 종료" 배지(가능하면 종료 날짜 포함)와 "지원 종료" 필터가 더해집니다.
- 오프라인이라 지연이 없어 기본으로 켜져 있습니다. 끄려면 `ENRICH_EOL=false`로 설정합니다. AI/ML 모델 스캔은 런타임이나 프레임워크 컴포넌트가 없어 이 단계를 건너뜁니다.

## 버전 최신성

지원되는 릴리스 주기 안에 있다고 해서 최신 버전을 쓰는 것은 아닙니다. 그래서 BomLens는 컴포넌트가 뒤처졌는지도 함께 표시합니다. 이 판정은 두 층으로 나뉩니다.

- 오프라인 층은 EOL 점검과 함께 기본으로 켜져 있습니다. 같은 endoflife.date 스냅샷에 각 릴리스 주기의 최신 패치가 담겨 있어, 설치된 버전이 자기 주기 안에서 최신 패치보다 뒤처졌는지를 오프라인으로 판정합니다. EOL 점검과 똑같이 네트워크 호출 없이 찾아내는, 안전한 주기 내 업그레이드 신호입니다. 뒤처진 컴포넌트에는 `bomlens:currency:outdated=true`가 붙고, 목표 패치는 `bomlens:currency:latestPatch`에 담깁니다. 이 판정은 EOL 단계 안에서 돌기 때문에 `ENRICH_EOL=false`로 두면 함께 꺼지고, AI/ML 모델 스캔은 건너뜁니다.
- deps.dev 층은 옵트인입니다. `STALENESS_ENRICH=true`로 켜면 각 컴포넌트를 deps.dev(구글의 공개 패키지 메타데이터)에서 조회해 절대 최신 버전(`bomlens:staleness:latest`), 설치 버전이 몇 릴리스 뒤인지(`bomlens:staleness:releasesBehind`), 최신 버전이 언제 나왔는지(`bomlens:staleness:lastReleased`)를 기록합니다. 이는 컴포넌트마다 네트워크 호출을 하므로 스캔의 오프라인 결정성을 최신성과 맞바꾸며, 폐쇄망에는 맞지 않아 기본으로 꺼져 있습니다. 최선 노력이자 시간 제한이 있어, 조회에 실패해도 스캔을 멈추지 않습니다. 지원 생태계는 npm, PyPI, Maven, Go, Cargo, NuGet, RubyGems입니다. 프로젝트가 지금도 활발히 유지보수되는지는 이번 릴리스에 포함되지 않으며, 이후 확장할 부분입니다.
- 웹 UI에서는 개요(Overview)에 최신 버전보다 뒤처진 컴포넌트 수 타일이 더해지고, 컴포넌트 표는 최신 버전이 아닌 컴포넌트를 표시하며 "Outdated" 필터를 더합니다. deps.dev 층을 켜면 그런 컴포넌트마다 몇 릴리스 뒤인지와 마지막 릴리스 날짜도 함께 보여줍니다.

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
- 오탐(실제 영향 없음) 판단, 예외 승인, 이력 관리 같은 취약점 분류 업무는 BomLens의 범위를 넘습니다. 취약점 관리 시스템(Dependency-Track, TRUSCA 등)에 SBOM을 업로드해 처리하세요.

## 오픈소스위험분석보고서

오픈소스위험분석보고서는 취약점을 심각도별로 집계하고 권고 대응 기한(Critical 7일, High 30일)을 명시합니다. 라이선스 요약도 담고 있으며, 공급사 SBOM을 분석한 경우에는 포맷 적합성 결과가 더해집니다.

## 관련 문서

- [보고서 생성](../guides/reports.ko.md)
- [산출물 레퍼런스](../reference/artifacts.ko.md)
- [BomLens 동작 원리](architecture.ko.md)
