# 기여 가이드

> **English**: [CONTRIBUTING.en.md](CONTRIBUTING.en.md)

BomLens 프로젝트에 관심 가져 주셔서 감사합니다! 버그 수정, 문서 개선, 새로운 언어 지원 추가 등 어떤 형태의 기여든 환영합니다.

> **관련 문서**: [아키텍처](docs/concepts/architecture.ko.md) | [테스트 가이드](docs/contribute/testing.ko.md) | [패키지 매니저 추가](docs/contribute/package-managers.ko.md)

## 목차

- [행동 강령](#행동-강령)
- [기여 방법](#기여-방법)
- [개발 환경 설정](#개발-환경-설정)
- [Pull Request 절차](#pull-request-절차)
- [코딩 스타일](#코딩-스타일)
- [커밋 메시지 규칙](#커밋-메시지-규칙)
- [이슈 및 토론](#이슈-및-토론)

## 행동 강령

이 프로젝트는 [Contributor Covenant](https://www.contributor-covenant.org/) 기반의 [행동 강령](CODE_OF_CONDUCT.md)을 따릅니다. 프로젝트에 참여함으로써 이 강령을 지키는 데 동의하는 것으로 간주합니다. 보안 취약점은 [보안 정책](SECURITY.md)에 따라 비공개로 신고해 주세요.

## 기여 방법

| 유형 | 방법 |
|------|------|
| 버그 수정 | [Issues](https://github.com/sktelecom/sbom-tools/issues)에서 버그를 찾아 수정 |
| 새 언어 지원 | [패키지 매니저 추가 가이드](docs/contribute/package-managers.ko.md) 참고 |
| 문서 개선 | 오타 수정, 예제 추가, 설명 보완 |
| 테스트 작성 | [테스트 가이드](docs/contribute/testing.ko.md) 참고 |
| 기능 제안 | [Discussions](https://github.com/sktelecom/sbom-tools/discussions)에서 먼저 논의 |

한국어 문서를 작성·수정할 때는 [한국어 문서 문체 가이드](docs/korean-style-guide.md)를 따른다.

## 개발 환경 설정

### 필수 요구사항

- Docker 20.10 이상
- Git
- bash (Linux/macOS) 또는 Git Bash (Windows)

### 저장소 클론 및 환경 준비

```bash
git clone https://github.com/sktelecom/sbom-tools.git
cd sbom-tools

# Docker 이미지 빌드 (로컬 수정 시)
cd docker && docker build -t sbom-scanner:local .

# 기본 동작 확인
cd examples/nodejs
../../scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --generate-only
```

## Pull Request 절차

1. 새 기능이나 버그 수정 전에 관련 이슈를 먼저 생성하거나, 기존 이슈에서 작업 의사를 밝혀 주세요.

2. 저장소를 포크하고 목적에 맞는 브랜치를 만듭니다.
   ```bash
   git checkout -b feat/add-kotlin-support
   git checkout -b fix/java-gradle-detection
   ```

3. 코드를 수정하고 테스트가 모두 통과하는지 확인합니다.
   ```bash
   ./tests/test-scan.sh
   ```

4. 변경 사항을 명확히 설명하는 PR을 제출합니다. 아래 체크리스트를 모두 확인해 주세요.

5. 리뷰어의 피드백에 성실히 응답하고 필요한 수정을 진행합니다.

### PR 체크리스트

- [ ] 변경 사항에 대한 테스트를 작성했습니다.
- [ ] `./tests/test-scan.sh` 가 모두 통과합니다.
- [ ] 관련 문서를 업데이트했습니다.
- [ ] 커밋 메시지가 [규칙](#커밋-메시지-규칙)을 따릅니다.

## 코딩 스타일

### Shell 스크립트

- 첫 줄: `#!/usr/bin/env bash`
- 전역 변수: `UPPER_SNAKE_CASE`, 지역 변수: `lower_snake_case`
- 함수명: `lower_snake_case`
- 오류 처리: 스크립트 상단에 `set -euo pipefail` 사용
- 짧은 옵션보다 긴 옵션 선호 (`--verbose` > `-v`)

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT_NAME="${1:-}"

function validate_input() {
    local project_name="$1"
    if [[ -z "$project_name" ]]; then
        echo "ERROR: Project name is required" >&2
        return 1
    fi
}
```

### Dockerfile

- 공식 베이스 이미지 사용
- `RUN` 명령어를 통합하여 레이어 최소화
- 각 설치 단계에 명확한 주석 작성

## 커밋 메시지 규칙

[Conventional Commits](https://www.conventionalcommits.org/) 형식을 따릅니다.

```
<type>(<scope>): <subject>

[body]

[footer]
```

### Type 목록

| Type | 설명 |
|------|------|
| `feat` | 새로운 기능 추가 |
| `fix` | 버그 수정 |
| `docs` | 문서 변경 |
| `test` | 테스트 추가/수정 |
| `refactor` | 리팩토링 (기능·버그 변경 없음) |
| `chore` | 빌드, 의존성 등 기타 변경 |

### 작성 예시

```
feat(scanner): add Kotlin/Gradle support

Add support for Kotlin projects using Gradle build system.
Uses cdxgen with KOTLIN_HOME environment variable.

Closes #42
```

## 이슈 및 토론

### 버그 리포트

[GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)를 이용해 주세요. 아래 정보를 포함하면 빠른 해결에 도움이 됩니다.

- 환경: OS, Docker 버전, 스크립트 버전
- 재현 방법: 버그를 재현하는 최소한의 단계
- 기대 결과와 실제 결과 (에러 메시지 포함)

### 기능 제안

[GitHub Discussions](https://github.com/sktelecom/sbom-tools/discussions)에서 먼저 논의한 뒤 이슈로 이어가면 좋습니다.

---

문의: [opensource@sktelecom.com](mailto:opensource@sktelecom.com)
