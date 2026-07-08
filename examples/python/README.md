# Python 프로젝트 예제

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

Flask 기반 간단한 REST API 애플리케이션입니다. SBOM 생성 테스트를 위한 예제로 사용됩니다. Flask, Pandas, NumPy, Requests, SQLAlchemy, Pytest 등 널리 쓰이는 Python 패키지를 의존성으로 포함합니다.

## SBOM 생성

### 방법 1: BomLens 스크립트 사용 (권장)

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/start/first-scan.ko.md) 참고.

```bash
# 프로젝트 디렉토리로 이동
cd examples/python

# SBOM 생성
../../scripts/scan-sbom.sh \
  --project "PythonFlaskExample" \
  --version "1.0.0" \
  --generate-only
```

결과는 `PythonFlaskExample_1.0.0/` 폴더에 저장됩니다(`PythonFlaskExample_1.0.0_bom.json` 등).

### 방법 2: Docker 직접 사용

```bash
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="PythonFlaskExample" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/bomlens:latest
```

이 방법은 스크립트와 달리 출력 폴더에 바로(하위 폴더 없이) 저장됩니다.

### 방법 3: cyclonedx-py 사용

```bash
# cyclonedx-py 설치
pip install cyclonedx-bom

# SBOM 생성
cyclonedx-py requirements \
  -i requirements.txt \
  -o bom.json \
  --format json
```

## 생성된 SBOM 확인

```bash
# SBOM 파일 확인
ls -lh PythonFlaskExample_1.0.0/PythonFlaskExample_1.0.0_bom.json

# 컴포넌트 개수 확인 (jq 필요)
cat PythonFlaskExample_1.0.0/PythonFlaskExample_1.0.0_bom.json | jq '.components | length'

# Flask 관련 의존성 확인
cat PythonFlaskExample_1.0.0/PythonFlaskExample_1.0.0_bom.json | jq -r '.components[] | select(.name | contains("flask")) | "\(.name)@\(.version)"'
```

예상 컴포넌트 수는 약 30-40개입니다(전이적 의존성 포함).
<!-- expected-components: 30-40 -->

생성된 SBOM에는 다음과 같은 정보가 포함됩니다:

- 웹 프레임워크: flask, werkzeug, jinja2, itsdangerous
- 데이터 처리: pandas, numpy, pytz
- HTTP: requests, urllib3, certifi, charset-normalizer
- 검증: pydantic, pydantic-core
- 데이터베이스: sqlalchemy, greenlet
- 테스트: pytest, pytest-cov, coverage
- 유틸리티: python-dotenv, click

## 문제 해결

### SBOM이 비어있음

```bash
# requirements.txt 위치 확인
ls -la requirements.txt

# requirements.txt 생성
pip freeze > requirements.txt
```

### pip 설치 실패

```bash
# pip 업그레이드
pip install --upgrade pip

# 캐시 삭제 후 재설치
pip install --no-cache-dir -r requirements.txt
```

## Poetry 사용 (선택)

Poetry(`pyproject.toml`)를 쓰는 프로젝트도 같은 방식으로 스캔할 수 있습니다. `--project` 이름만 바꿔서 방법 1 명령을 그대로 실행하면 됩니다.

## 다음 단계

- [사용 가이드](../../docs/reference/cli.ko.md) - 상세한 사용법
- [시작하기](../../docs/start/first-scan.ko.md) - 첫 SBOM 생성
- [Docker 가이드](../../docker/README.md) - Docker 이미지 사용법

## 참고

이 예제는 SBOM 생성 테스트 목적으로 만들어졌습니다. 실제 프로덕션 환경에서는 인증, 에러 처리, 로깅, 모니터링 등을 추가해야 합니다.
