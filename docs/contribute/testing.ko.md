---
description: BomLens 테스트 구조와 실행 방법, 테스트 작성 방법, 디버깅 절차를 설명한다.
---

# 테스트 가이드

BomLens의 테스트 구조와 실행 방법, 테스트 작성 방법, 디버깅 절차를 설명합니다.

## 테스트 구조

```
tests/
├── test-scan.sh              # 메인 통합 테스트 — 언어/입력 유형별 15개 블록이
│                              # 한 파일에 이어져 있다(Node.js, Python, Java Maven,
│                              # Ruby, PHP, Rust, Docker 이미지, 바이너리 파일,
│                              # rootfs 디렉터리, ZIP 아카이브 등)
├── test-e2e.sh                # 그 밖의 엔드투엔드 테스트(CLI, 예제, 웹 UI, AI-BOM 등)
├── test-examples-e2e.sh
├── test-web-e2e.sh
├── test-web-ui.sh
├── test-android-scope.sh      # 관심사별 독립 회귀 테스트 스크립트 —
├── test-aibom.sh              # 공용 라이브러리를 쓰지 않고 각자 자기만의
├── test-firmware-unpack.sh    # pass()/fail() 헬퍼를 정의한다
├── ...
├── lib/
│   └── snapshot-normalize.jq  # 스냅샷 테스트가 공유하는 jq 헬퍼
├── fixtures/                  # 독립 스크립트들이 쓰는 입력 픽스처
└── snapshots/                 # test-snapshot.sh가 비교하는 기대 출력 스냅샷
```

`tests/helpers/`나 `tests/cases/` 디렉터리는 없습니다. `test-scan.sh`는 파일 상단에
헬퍼 함수 몇 개(`run_scan_with_logs`, `find_bom_file`, `assert_bom_sane`,
`assert_spdx_sane`, `assert_root_has_direct_deps`, `show_failure_log`)를
직접 정의해 두고, 같은 파일 안에서 15개 테스트 블록을 차례로 실행합니다. 각 블록은
몇 줄짜리 코드로, 테스트 작업 공간에 픽스처 프로젝트를 만들고 스캔을 실행한 뒤
`jq`나 위 헬퍼 함수로 결과를 확인합니다.

`tests/` 아래의 독립 스크립트(`test-android-scope.sh`, `test-aibom.sh` 등)는 이
장치를 공유하지 않고, 각자 필요한 만큼의 작은 로컬 헬퍼를 따로 정의합니다. 새
스크립트를 쓰기 전에 기존 스크립트 하나를 먼저 읽어 보세요.

## 테스트 실행

### 전체 테스트 실행

```bash
./tests/test-scan.sh
```

성공 시 출력 예시(축약 — 실제로는 `[TEST]`/`[✓]` 쌍이 15번 출력됩니다):

```
==========================================
 SBOM Generator - Integration Test
 Version: 1.0.0
==========================================

[INFO] Checking prerequisites...
[✓] Docker check passed
[✓] Scan script check passed

[INFO] Starting tests...

[TEST] Test 1/15: Node.js project (npm)
[✓] Node.js project (2 components)
...
[TEST] Test 15/15: --timestamp run folder
[✓] --timestamp run folder created (./Stamped_1.0.0_.../)

==========================================
 Test Summary
==========================================

Total tests: 15
Passed: 15
Failed: 0
Success rate: 100.0%
```

### 전체를 돌리지 않고 케이스 하나만 확인하기

`test-scan.sh`에는 15개 블록 중 하나만 골라 실행하는 옵션이 없습니다. 특정 언어나
입력 유형 하나만 확인하려면 원하는 픽스처나 예제를 대상으로 스캔을 직접
실행하세요.

```bash
./scripts/scan-sbom.sh --project Test --version 1.0.0 --target examples/nodejs --generate-only
```

반면 독립 스크립트들은 이미 각자 따로 실행할 수 있습니다.

```bash
./tests/test-android-scope.sh
./tests/test-aibom.sh
```

## 실행 모드

| 환경 변수 | 값 | 효과 |
|-----------|-----|----------|
| (없음) | — | `[TEST]`/`[✓]`/`[✗]` 통과·실패 줄만 출력하고, 단계별 출력은 로그 파일에 저장 |
| `VERBOSE` | `true` | 스캔 출력에서 걸러낸 주요 진행 줄도 함께 출력(`INFO`/`WARN`/`ERROR`, `Analyzing`, `Downloading`, `components`, `cdxgen`, `syft`) |
| `DEBUG_MODE` | `true` | Docker·cdxgen·syft 전체 출력을 실시간으로 스트리밍하고, 종료 시 작업 공간을 정리하지 않고 보존 |

```bash
# Verbose 모드
VERBOSE=true ./tests/test-scan.sh

# Debug 모드(문제 분석 시. tests/test-workspace/도 보존됩니다)
DEBUG_MODE=true ./tests/test-scan.sh
```

`test-android-scope.sh` 등 일부 독립 스크립트도 `VERBOSE`를 지원합니다. 스크립트가
읽는 환경 변수는 각 스크립트 상단의 헤더 주석에서 확인하세요.

## 테스트 작성

언어마다 따로 만들 파일은 없습니다. 새 언어나 생태계에 대한 테스트를 추가하려면
기존 테스트를 확장합니다.

1. `tests/test-scan.sh`를 열어 기존 블록의 형식을 따라 새 블록을 추가합니다(Java
   Maven 블록인 Test 3이 참고하기 좋은 예입니다). 테스트 작업 공간에 픽스처
   프로젝트를 만들고, `run_scan_with_logs`로 스캔을 실행하고, `find_bom_file`로
   생성된 BOM을 찾은 뒤, `jq` 또는 `assert_bom_sane` / `assert_spdx_sane` /
   `assert_root_has_direct_deps`로 검증합니다. 주변 블록과 같은 방식으로 성공·실패에
   따라 `PASSED`나 `FAILED`를 늘리고, 실패 시 `show_failure_log`를 호출합니다.
2. 각 블록의 `print_test` 레이블은 "Test N/15"처럼 번호가 손으로 적혀 있습니다.
   블록을 추가한 뒤에는 레이블 번호를 다시 매기고, 스크립트 상단의 `--help` 문구와
   요약 배너의 총 개수도 함께 갱신합니다.
3. 소스 스캔 패턴에 맞지 않는 경우 — 이미지나 rootfs에 특화된 사례, 재현성 확인,
   AI-BOM 동작, 느리고 네트워크에 의존하는 회귀 테스트 등 — 라면 대신
   `tests/test-<name>.sh` 스크립트를 새로 만듭니다. `test-android-scope.sh` 같은
   기존 스크립트를 따라 로컬 `pass()`/`fail()` 헬퍼를 정의하고, 필요한 도구나
   이미지가 없으면 일찍 건너뛰게 하고, 해당 CI 워크플로(퍼 PR 경로는 `ci.yml`, 느리거나
   네트워크에 의존하는 검사는 `nightly.yml`)에 연결합니다.

새 언어를 처음부터 끝까지 추가하는 전체 절차(감지, build-prep, 예제 프로젝트,
갱신할 문서)는 [패키지 매니저 추가 가이드](package-managers.ko.md)를 참고하세요.

## 헬퍼 함수 레퍼런스

아래는 `tests/test-scan.sh` 상단에 정의되어 그 파일 안의 테스트 블록이 쓰는
함수입니다. 다른 스크립트가 함께 쓰는 공용 라이브러리는 아닙니다.

| 함수 | 검증 내용 |
|------|-------------|
| `assert_bom_sane <파일> <프로젝트>` | 파일이 CycloneDX 형식이고, `metadata.component.name`이 입력한 프로젝트 이름과 같고, `components`가 배열인지 |
| `assert_spdx_sane <파일>` | 유효한 SPDX 2.x 문서인지(`spdxVersion`이 `SPDX-`로 시작, `SPDXID`가 `SPDXRef-DOCUMENT`, `packages`가 배열) |
| `assert_root_has_direct_deps <파일>` | 루트 컴포넌트의 `dependencies` 항목에 비어 있지 않은 `dependsOn`이 있는지 |
| `find_bom_file <프로젝트> <버전>` | 현재의 실행별 하위 폴더 구조와 예전의 평면 구조 양쪽에서 생성된 BOM을 찾는다 |

이 밖의 검증은 대부분 생성된 BOM에 대한 평범한 `jq -e '...'` 식입니다. 별도의
단언 라이브러리는 없습니다. 독립 스크립트는 필요할 때마다 자기만의 작은 헬퍼를
정의합니다(`test-android-scope.sh`의 `count()`, `has_direct()` 등).

### 테스트 작성 원칙

**독립성**: 각 테스트는 다른 테스트에 의존하지 않아야 합니다. 테스트 순서가 달라져도 결과가 동일해야 합니다.

**정리**: `test-scan.sh`는 이미 `trap cleanup EXIT` 하나로 종료 시 작업 공간(로그 제외)을 정리합니다. 이 파일 안에 블록을 추가할 때는 따로 정리할 필요 없이 작업이 끝나면 `$TEST_DIR`로 돌아가기만 하면 됩니다. 독립 스크립트는 자기 작업 공간을 스스로 정리해야 합니다.

**명확한 이름**: `print_test`/`print_success`/`print_error`에 넘기는 문자열은 어떤 언어인지가 아니라 그 블록이 무엇을 검증하는지를 말해야 합니다.

**최소 단언**: 그 변경이 지키려는 것만 검증하고, 그 이상은 넣지 않습니다.

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

### 실패 하나 디버깅하기

```bash
# tests/test-workspace/를 보존하므로 실행 후 픽스처와 BOM을 확인할 수 있다
DEBUG_MODE=true ./tests/test-scan.sh

# 또는 독립 스크립트를 직접 디버깅
VERBOSE=true ./tests/test-android-scope.sh
```

## CI 통합

### GitHub Actions

`ci.yml`은 메인 테스트를 실행하고, 실패하면 보존된 로그를 업로드합니다.

```yaml
- name: Run integration tests
  run: |
    VERBOSE=true ./tests/test-scan.sh

- name: Upload test logs on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: test-logs
    path: tests/test-workspace/failed-tests-logs/
```

독립 스크립트들은 `test-scan.sh`에서 호출되는 대신 각자 별도의 단계로 연결되어
있습니다. 예를 들어 `bash tests/test-aibom.sh`는 `ci.yml`에서 실행되고, 느리고
네트워크에 의존하는 `test-android-scope.sh`는 `nightly.yml`에서 실행됩니다.

### 테스트 실패 시 대응 절차

1. `DEBUG_MODE=true` 로 재실행하여 상세 로그를 확인합니다.
2. 실패한 언어의 예제 디렉터리에서 `scan-sbom.sh`를 직접 실행합니다.
3. Docker 이미지를 최신 버전으로 업데이트합니다: `docker pull ghcr.io/sktelecom/bomlens:latest`
4. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/bomlens/issues)에 환경 정보와 로그를 첨부해 제보해 주세요.

---

> **관련 문서**: [기여 가이드](https://github.com/sktelecom/bomlens/blob/main/CONTRIBUTING.ko.md) | [아키텍처](../concepts/architecture.ko.md) | [패키지 매니저 추가](package-managers.ko.md)
</content>
