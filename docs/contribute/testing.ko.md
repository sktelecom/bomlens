# 테스트 가이드

BomLens의 테스트 구조와 실행 방법, 테스트 작성 방법, 디버깅 절차를 설명합니다.

## 테스트 구조

```
tests/
├── test-scan.sh          # 통합 테스트 진입점 (전체 테스트 실행)
├── helpers/
│   ├── assert.sh         # 단언(assertion) 헬퍼 함수
│   └── setup.sh          # 테스트 환경 초기화/정리
└── cases/
    ├── test-java.sh      # Java 테스트 케이스
    ├── test-nodejs.sh    # Node.js 테스트 케이스
    ├── test-python.sh    # Python 테스트 케이스
    ├── test-go.sh        # Go 테스트 케이스
    └── test-docker.sh    # Docker 이미지 분석 테스트
```

## 테스트 실행

### 전체 테스트 실행

```bash
./tests/test-scan.sh
```

성공 시 출력 예시:

```
[PASS] Java Maven 소스 코드 분석
[PASS] Java Gradle 소스 코드 분석
[PASS] Node.js npm 소스 코드 분석
[PASS] Python pip 소스 코드 분석
[PASS] Go 모듈 소스 코드 분석
[PASS] Docker 이미지 분석 (nginx:alpine)
─────────────────────────────────
총 6개 테스트 중 6개 통과 (0개 실패)
```

### 특정 언어만 테스트

```bash
./tests/cases/test-java.sh
./tests/cases/test-nodejs.sh
```

## 실행 모드

| 환경 변수 | 값 | 출력 내용 |
|-----------|-----|----------|
| (없음) | — | 테스트 결과 요약만 출력 |
| `VERBOSE` | `true` | 각 단계별 주요 진행 로그 출력 |
| `DEBUG_MODE` | `true` | Docker 실행 로그, cdxgen/syft 전체 출력 포함 |
| `LOG_FILE` | 파일 경로 | 로그를 파일에 저장 |

```bash
# Verbose 모드
VERBOSE=true ./tests/test-scan.sh

# Debug 모드 (문제 분석 시)
DEBUG_MODE=true ./tests/test-scan.sh

# 로그 파일 저장
LOG_FILE="./test-results.log" ./tests/test-scan.sh
```

Verbose 모드 출력 예시:

```
[INFO] Java Maven 테스트 시작
[INFO] Docker 이미지 준비 중...
[INFO] SBOM 생성 중...
[PASS] Java Maven 소스 코드 분석
  - 감지된 컴포넌트: 47개
  - PURL 형식: pkg:maven/...
  - 라이선스 정보: 포함
```

## 테스트 작성

새로운 언어 지원을 추가할 때 아래 형식으로 테스트 케이스를 작성합니다.

```bash
# tests/cases/test-kotlin.sh

#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/../helpers/assert.sh"
source "$(dirname "$0")/../helpers/setup.sh"

TEST_NAME="Kotlin Gradle 소스 코드 분석"
EXAMPLE_DIR="examples/kotlin"

setup_test "$TEST_NAME"

# SBOM 생성
run_scan \
  --project "KotlinExample" \
  --version "1.0.0" \
  --target "$EXAMPLE_DIR" \
  --generate-only

# 단언
assert_file_exists "KotlinExample_1.0.0_bom.json"
assert_json_field ".bomFormat" "CycloneDX"
assert_json_field ".specVersion" "1.6"
assert_components_count_gte 1
assert_purl_prefix "pkg:maven/"  # Kotlin은 Gradle/Maven 생태계 사용

teardown_test
```

그 다음, `tests/test-scan.sh`에 새 테스트를 등록합니다.

```bash
# tests/test-scan.sh 내부에 추가
source "$(dirname "$0")/cases/test-kotlin.sh"
```

전체 절차는 [패키지 매니저 추가 가이드](package-managers.ko.md#4-테스트-추가)를 참고하세요.

## 단언 함수 레퍼런스

| 함수 | 설명 |
|------|------|
| `assert_file_exists <파일>` | 파일 존재 여부 확인 |
| `assert_json_field <필드> <기댓값>` | JSON 필드 값 확인 |
| `assert_components_count_gte <수>` | 컴포넌트 수가 N개 이상인지 확인 |
| `assert_purl_prefix <접두사>` | PURL 접두사 형식 확인 |
| `assert_license_exists` | 하나 이상의 라이선스 정보 존재 확인 |
| `assert_no_empty_versions` | 빈 버전 필드 없음 확인 |

### 테스트 작성 원칙

**독립성**: 각 테스트는 다른 테스트에 의존하지 않아야 합니다. 테스트 순서가 달라져도 결과가 동일해야 합니다.

**정리**: `teardown_test`에서 생성된 파일을 반드시 삭제하여 다음 테스트에 영향을 주지 않도록 합니다.

**명확한 이름**: `TEST_NAME`은 "무엇을 검증하는가"를 명확히 표현합니다.

**최소 단언**: 필요한 항목만 단언하고, 과도한 검증은 피합니다.

## 로깅 및 디버깅

### 생성된 SBOM 직접 검사

```bash
# 컴포넌트 수 확인
jq '.components | length' NodeExample_1.0.0_bom.json

# 모든 PURL 목록
jq '[.components[].purl]' NodeExample_1.0.0_bom.json

# 라이선스 목록
jq '[.components[].licenses[]?.license.id] | unique' NodeExample_1.0.0_bom.json
```

### 특정 테스트 디버깅

```bash
DEBUG_MODE=true ./tests/cases/test-nodejs.sh
```

## CI 통합

### GitHub Actions

```yaml
- name: Run integration tests
  run: |
    VERBOSE=true ./tests/test-scan.sh

- name: Upload test logs on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: test-logs
    path: "*.log"
```

### 테스트 실패 시 대응 절차

1. `DEBUG_MODE=true` 로 재실행하여 상세 로그를 확인합니다.
2. 실패한 언어의 예제 디렉토리에서 `scan-sbom.sh`를 직접 실행합니다.
3. Docker 이미지를 최신 버전으로 업데이트합니다: `docker pull ghcr.io/sktelecom/bomlens:latest`
4. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)에 환경 정보와 로그를 첨부해 리포트해 주세요.

---

> **관련 문서**: [기여 가이드](https://github.com/sktelecom/sbom-tools/blob/main/CONTRIBUTING.md) | [아키텍처](../concepts/architecture.ko.md) | [패키지 매니저 추가](package-managers.ko.md)
