# 패키지 매니저 추가 가이드

> **관련 문서**: [기여 가이드](https://github.com/sktelecom/sbom-tools/blob/main/CONTRIBUTING.md) | [아키텍처](../architecture.md) | [테스트 가이드](testing-guide.md)

새로운 프로그래밍 언어 또는 패키지 매니저 지원을 추가하는 방법을 단계별로 설명합니다.

## 사전 확인

새로운 언어나 패키지 매니저를 추가하기 전에 다음을 먼저 확인하세요.

- **cdxgen 지원 여부**: [cdxgen 지원 언어 목록](https://github.com/CycloneDX/cdxgen#supported-project-types)을 확인합니다. cdxgen 공식 언어 이미지가 있다면 라우팅 테이블에 추가하는 것으로 충분합니다.
- **syft 지원 여부**: 바이너리나 이미지 분석이 필요한 경우 [syft 지원 형식](https://github.com/anchore/syft#supported-ecosystems)을 확인합니다.
- **커스텀 분석기 필요 여부**: 두 도구 모두 지원하지 않는 경우에만 커스텀 분석 스크립트를 검토합니다.

소스 스캔은 단일 이미지가 아니라 언어별 cdxgen 공식 이미지를 라우팅하는 2단계 구조입니다. 전체 그림은 [아키텍처](../architecture.md)를 참고하세요.

## 추가 절차

### 1. 언어 감지와 이미지 라우팅 추가

`docker/lib/source-detect.sh`가 CLI와 웹 UI 양쪽에서 쓰는 공용 감지 로직입니다. 두 함수를 수정합니다.

- `detect_lang()` — 프로젝트의 매니페스트 파일로 언어를 감지하는 규칙을 추가합니다 (예: Kotlin이면 `build.gradle.kts` 존재 확인 — Kotlin은 이미 `java` 분기에 포함됩니다).
- `img_for_lang()` — 감지된 언어에 대응하는 cdxgen 공식 이미지를 추가합니다.

```bash
# img_for_lang() 예시 — 새 언어 항목 추가
newlang) echo "ghcr.io/cyclonedx/cdxgen-debian-newlang:$CDXGEN_TAG" ;;
```

### 2. 의존성 보강이 필요하면 build-prep.sh 수정

cdxgen이 잠금 파일 없이 전이 의존성을 해석하지 못하는 생태계라면, cdxgen 실행 직전에 잠금 파일을 만들어 주는 `docker/lib/build-prep.sh`에 보강 로직을 추가합니다. Rust(`cargo generate-lockfile`)와 Go(`go mod download`)가 선례입니다. 보강은 best-effort로 작성해 스캔을 실패시키지 않아야 합니다.

### 3. 예제 프로젝트 추가

`examples/` 디렉토리에 예제 프로젝트를 추가합니다.

```
examples/kotlin/
├── README.md              # 예제 설명
├── build.gradle.kts       # 빌드 파일
├── gradle.lockfile        # 잠금 파일 (필수!)
└── src/main/kotlin/
    └── Main.kt
```

> **잠금 파일이 중요한 이유**: cdxgen은 잠금 파일에서 정확한 버전 정보를 추출합니다. 잠금 파일이 없으면 의존성이 불완전하게 탐지됩니다.

### 4. 테스트 추가

`tests/cases/test-{언어}.sh` 파일을 생성합니다. 자세한 작성법은 [테스트 가이드](testing-guide.md#테스트-작성)를 참고하세요.

```bash
#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/../helpers/assert.sh"
source "$(dirname "$0")/../helpers/setup.sh"

TEST_NAME="Kotlin Gradle 소스 코드 분석"
EXAMPLE_DIR="examples/kotlin"

setup_test "$TEST_NAME"

run_scan \
  --project "KotlinExample" \
  --version "1.0.0" \
  --target "$EXAMPLE_DIR" \
  --generate-only

assert_file_exists "KotlinExample_1.0.0_bom.json"
assert_json_field ".bomFormat" "CycloneDX"
assert_json_field ".specVersion" "1.6"
assert_components_count_gte 1
assert_purl_prefix "pkg:maven/"

teardown_test
```

그 다음, `tests/test-scan.sh`에 새 테스트를 등록합니다.

```bash
source "$(dirname "$0")/cases/test-kotlin.sh"
```

### 5. 문서 업데이트

새로운 언어를 추가하면 아래 문서를 업데이트해야 합니다.

- `README.md` — 지원 언어 목록에 추가
- [예제 가이드](../examples-guide.md) — 새 언어 섹션 추가 (다른 언어 예시 형식 참고)
- [사용 가이드](../usage-guide.md) — 트러블슈팅의 "언어 미감지" 표에 추가:

```markdown
| Kotlin | `build.gradle.kts` + `gradle.lockfile` |
```

### 6. PR 제출

[기여 가이드](https://github.com/sktelecom/sbom-tools/blob/main/CONTRIBUTING.md)에 따라 PR을 제출합니다. PR 본문에 다음을 포함하세요.

- 추가한 언어/패키지 매니저 이름
- 테스트 실행 결과 (스크린샷 또는 로그)
- 예제 SBOM 출력 샘플

## 예제: Kotlin 지원 추가

Kotlin은 Gradle 빌드 시스템을 사용하며 JVM 기반이므로, `detect_lang()`의 `java` 분기(`*.gradle.kts` 감지)와 `cdxgen-temurin-java21` 이미지를 그대로 재활용합니다.

### Gradle 잠금 파일 생성 방법

```bash
cd examples/kotlin

# build.gradle.kts에 의존성 잠금 설정 추가
cat >> build.gradle.kts << 'EOF'
dependencyLocking {
    lockAllConfigurations()
}
EOF

# 잠금 파일 생성
./gradlew dependencies --write-locks
```

### 예상 SBOM 출력 (components 일부)

```json
{
  "components": [
    {
      "type": "library",
      "name": "kotlin-stdlib",
      "version": "1.9.21",
      "purl": "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.9.21"
    }
  ]
}
```

Kotlin은 Maven 생태계를 공유하므로 PURL은 `pkg:maven/` 접두사를 사용합니다.

## 체크리스트

새로운 언어 지원 PR을 제출하기 전에 모든 항목을 확인하세요.

- [ ] `docker/lib/source-detect.sh`에 감지 규칙과 이미지 라우팅이 추가되었습니다.
- [ ] 전이 의존성 보강이 필요하면 `docker/lib/build-prep.sh`에 반영되었습니다.
- [ ] `examples/{언어}/` 예제 프로젝트가 있습니다.
- [ ] 예제 프로젝트에 잠금 파일이 포함되어 있습니다.
- [ ] `tests/cases/test-{언어}.sh` 테스트가 작성되었습니다.
- [ ] `tests/test-scan.sh`에 테스트가 등록되었습니다.
- [ ] `./tests/test-scan.sh` 전체가 통과합니다.
- [ ] `README.md` 지원 언어 목록이 업데이트되었습니다.
- [ ] 예제 가이드에 예제 섹션이 추가되었습니다.
- [ ] 사용 가이드 트러블슈팅 표가 업데이트되었습니다.
