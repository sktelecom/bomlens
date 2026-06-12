# BomLens 개선 로드맵

이 문서는 실제 스캔 결과에서 드러난 미비점을 정리하고, 오픈소스 거버넌스 포털(trustedoss-portal)을 참고 기준으로 삼아 개선 항목과 우선순위를 도출한다. 웹 UI의 스캔 엔진 문제는 이미 해결했고(아래 1항), UI 가시성과 리포트 충실도는 남은 과제다.

## 배경

`haksungjang/pilot-java-maven`(Spring Boot) 프로젝트를 웹 UI로 스캔했을 때 세 가지 미비점이 나타났다.

1. 검출된 컴포넌트를 볼 화면이 없고 개수만 보인다.
2. 보안 리포트에 취약점이 1개만 나온다.
3. 고지문(NOTICE)에 컴포넌트 목록만 나온다.

진단 결과, 세 증상의 공통 뿌리는 스캔 산출물(SBOM)이 직접 선언 의존성만 담아 빈약하다는 점이었다. 그리고 그 빈약함의 원인은 웹 UI와 CLI가 서로 다른 스캔 엔진을 쓴다는 데 있었다.

## 진단: 같은 프로젝트, 8개 대 91개

동일한 프로젝트를 두 경로로 스캔하면 결과가 크게 달랐다.

| 경로 | 엔진 | 컴포넌트 | 의존성 범위 |
|---|---|---|---|
| 웹 UI (source/git/zip) | 컨테이너 내부 syft | 8개 | 직접 의존성만 (빌드 없이 pom.xml 파싱) |
| CLI `scan-sbom.sh --git` | 호스트 cdxgen 언어 이미지 | 91개 | 추이 의존성 포함 (maven 그래프 해석) |

웹 UI로 만든 8개짜리 SBOM은 `metadata.tools`가 syft였고, CLI로 만든 91개짜리는 cdxgen이었다. syft는 maven이나 gradle을 빌드하지 않아 pom.xml에 직접 선언된 의존성만 잡는다. Spring Boot 프로젝트는 spring-boot-starter 하나만으로도 tomcat-embed, spring-core, jackson-core 등 추이 의존성 수십 개를 끌어오는데, syft 경로에서는 이들이 전부 빠졌다. 취약점이 1개만 나오고 NOTICE가 빈약했던 것도 모두 이 8개짜리 SBOM에서 파생된 결과다.

원인은 `docker/entrypoint.sh`의 SOURCE 모드에 있었다. CLI는 source 스캔을 호스트에서 cdxgen 언어 이미지로 처리하지만, 웹 UI 컨테이너 안에는 언어 도구 모음과 docker CLI가 없어 syft로 대체하고 있었다. 같은 "source"라는 이름이지만 두 경로가 다른 엔진을 쓴 것이다.

## 해결: 웹 UI도 cdxgen으로 전환 (완료)

웹 UI의 source 스캔이 CLI와 동일하게 cdxgen 언어 이미지로 추이 의존성을 해석하도록 바꿨다. 같은 프로젝트를 웹 UI git 스캔으로 다시 돌려 8개에서 91개로 늘어난 것을 확인했다.

- 언어 감지와 cdxgen 이미지 선택 로직을 `docker/lib/source-detect.sh`로 추출해 CLI(`scripts/scan-sbom.sh`)와 웹 UI(`docker/entrypoint.sh`)가 공유한다. 두 경로가 같은 이미지를 고른다.
- `docker/entrypoint.sh`의 SOURCE 모드를 다시 작성했다. 호스트 Docker 소켓과 docker CLI, 스캔 대상의 호스트 경로가 모두 있으면 cdxgen 언어 이미지를 sibling 컨테이너로 띄워 빌드하고, 하나라도 없으면 기존 syft로 폴백한다(직접 의존성만).
- `docker/web/server.py`에 `host_path_of()`를 추가했다. 컨테이너 안 경로(`/src`, `/host-output` 하위)를 호스트 경로로 변환해 sibling 컨테이너가 스캔 대상을 올바르게 마운트하게 한다.
- `docker/Dockerfile`에 docker CLI(클라이언트 전용, 핀 버전)를 추가했다. cdxgen 언어 이미지를 띄우는 데 필요하다.

폴백 설계 덕분에 Docker 소켓을 마운트하지 않은 환경에서도 기존처럼 syft로 동작한다. docker CLI를 더하면서 컨테이너가 호스트 소켓에 접근하므로 보안 표면이 늘어나는 점은 운영에서 고려한다.

남은 사실 하나는 라이선스 정보다. 91개 컴포넌트도 cdxgen이 라이선스를 채우지 못하면 `licenses`가 비어 NOTICE가 여전히 빈약할 수 있다. 이는 아래 3항에서 다룬다.

## trustedoss-portal 대비 갭 (참고 기준)

참고 포털이 제공하지만 본 도구에 없는 항목 중, 이번 범위(UI, 리포트, SBOM)에 해당하는 것이다. 포털은 PostgreSQL과 Celery, 인증을 갖춘 영속 서버이고 본 도구는 단발 스캔 도구다. 따라서 데이터 모델과 워크플로우를 그대로 옮기지 않고, 포털 화면이 보여주는 정보 항목을 본 도구의 산출물 JSON에서 끌어내 표현하는 선에서 받아들인다.

| 영역 | 포털이 제공하는 것 | 본 도구 현황 |
|---|---|---|
| 컴포넌트 | 이름, 버전, PURL, 라이선스, 취약점 수, 직접/간접, 깊이 테이블에 검색·필터·정렬 | 개수만 표시 |
| 취약점 | CVE, 심각도, CVSS, EPSS, 수정버전, 참고링크와 영향 컴포넌트 | 보안 리포트는 CVSS, EPSS, CISA KEV, 수정버전을 표로 제공. 웹 UI 대시보드는 아직 심각도 막대와 개수만 |
| 라이선스 | 라이선스와 의무사항 그리드, 카테고리(허용/조건부/금지) | NOTICE에 라이선스 ID만 |

## 남은 개선 항목과 우선순위

### 1. SBOM 완전성 — 완료

웹 UI source 스캔의 cdxgen 전환으로 추이 의존성 누락을 해결했다. 라이선스 보강은 3항과 함께 본다.

### 2. UI 가시성

- API를 확장한다. `server.py`의 `sbom_summary()`가 컴포넌트 배열(name, version, group, purl, licenses, type)과 취약점 배열(CVE, severity, pkg, installed, fixed)을 반환하게 한다. `api.ts`의 타입도 함께 넓힌다.
- 컴포넌트 테이블을 추가한다. 검색과 라이선스·타입 필터, 정렬을 지원한다.
- 취약점 테이블을 추가한다. 심각도 배지와 CVE, 패키지, 설치·수정버전 컬럼을 두고 기존 `SeverityBar.tsx`를 목록과 연결한다.
- 라이선스 요약을 둔다. 라이선스별 컴포넌트 그룹으로, NOTICE 데이터를 재사용한다.
- 대상 파일은 `docker/web/server.py`, `docker/web/frontend/src/lib/api.ts`, `docker/web/frontend/src/components/ResultDashboard.tsx`와 신규 테이블 컴포넌트다.

### 3. 리포트 충실도

- 라이선스를 채운다 — 완료. 소스 스캔 시 `FETCH_LICENSE`(기본 true)로 cdxgen이 의존성 라이선스를 조회한다. 1st-party 소스 헤더는 `--deep-license`(scancode)로 보강한다.
- NOTICE를 강화한다 — 완료. `generate-notice.sh`가 라이선스 이름을 SPDX로 정규화하고, `component.copyright`를 표시하며, 주요 라이선스 21종의 SPDX 전문을 고지문에 번들한다.
- 보안 리포트에 우선순위 신호를 넣는다 — 완료. 리포트에 CVSS, EPSS, CISA KEV 열을 더하고 KEV·심각도·EPSS 순으로 정렬한다(`SECURITY_ENRICH`로 EPSS/KEV 조회 제어).
- 위험분석보고서를 보강한다. 라이선스 개수만 담던 것을 라이선스별 컴포넌트 매핑과 의무사항 요약까지 넓힌다.
- 대상 파일은 `docker/lib/generate-notice.sh`, `docker/lib/scan-security.sh`, `docker/lib/generate-risk-report.sh`다.

## 장기 과제

정책 게이트(금지 라이선스나 Critical 취약점 차단), 다단계 triage 워크플로우, 컴포넌트 승인, VEX 입출력, 도달가능성 분석은 본 도구가 영속 저장소를 갖추지 않는 한 부분 적용만 가능하다. 별도로 검토한다.
