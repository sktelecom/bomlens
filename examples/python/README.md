# Python 프로젝트 예제

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

Flask 기반 간단한 REST API 애플리케이션입니다. SBOM 생성 테스트를 위한 예제로 사용됩니다.

## 프로젝트 정보

- 언어: Python 3.11+
- 프레임워크: Flask 3.0
- 주요 의존성:
  - Flask (웹 프레임워크)
  - Pandas (데이터 처리)
  - NumPy (수치 계산)
  - Requests (HTTP 클라이언트)
  - SQLAlchemy (ORM)
  - Pytest (테스트)

## 사전 요구사항

- Python 3.8 이상
- pip (또는 Docker)

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

결과로 `PythonFlaskExample_1.0.0_bom.json` 파일이 생성됩니다.

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

## 애플리케이션 실행

### 가상 환경 생성 및 활성화

```bash
# 가상 환경 생성
python3 -m venv venv

# 활성화 (Linux/macOS)
source venv/bin/activate

# 활성화 (Windows)
venv\Scripts\activate
```

### 의존성 설치

```bash
pip install -r requirements.txt
```

### 애플리케이션 실행

```bash
# 개발 모드
python app.py

# 또는
flask run
```

접속 주소는 http://localhost:5000 입니다.

### Docker로 실행

```bash
# Dockerfile 생성
cat > Dockerfile <<EOF
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]
EOF

# 빌드 및 실행
docker build -t python-example:latest .
docker run -p 5000:5000 python-example:latest
```

## API 엔드포인트

### GET /

메인 페이지 - 애플리케이션 정보 반환

```bash
curl http://localhost:5000/
```

응답:
```json
{
  "message": "SBOM Example Application is running!",
  "version": "1.0.0",
  "timestamp": "2026-01-15T10:30:00.123456"
}
```

### GET /health

헬스 체크

```bash
curl http://localhost:5000/health
```

응답:
```json
{
  "status": "OK"
}
```

### GET /data

샘플 데이터 반환 (Pandas 사용)

```bash
curl http://localhost:5000/data
```

응답:
```json
{
  "data": [
    {"id": 1, "value": 0.123, "label": "Item 1"},
    {"id": 2, "value": 0.456, "label": "Item 2"}
  ],
  "count": 10
}
```

### POST /analyze

숫자 배열 통계 분석 (NumPy 사용)

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"numbers": [1, 2, 3, 4, 5]}'
```

응답:
```json
{
  "mean": 3.0,
  "median": 3.0,
  "std": 1.4142135623730951,
  "min": 1.0,
  "max": 5.0
}
```

## 생성된 SBOM 확인

```bash
# SBOM 파일 확인
ls -lh PythonFlaskExample_1.0.0_bom.json

# 컴포넌트 개수 확인 (jq 필요)
cat PythonFlaskExample_1.0.0_bom.json | jq '.components | length'

# Flask 관련 의존성 확인
cat PythonFlaskExample_1.0.0_bom.json | jq -r '.components[] | select(.name | contains("flask")) | "\(.name)@\(.version)"'
```

예상 컴포넌트 수는 약 30-40개입니다(전이적 의존성 포함).

## 예상 SBOM 내용

생성된 SBOM에는 다음과 같은 정보가 포함됩니다:

- 웹 프레임워크: flask, werkzeug, jinja2, itsdangerous
- 데이터 처리: pandas, numpy, pytz
- HTTP: requests, urllib3, certifi, charset-normalizer
- 검증: pydantic, pydantic-core
- 데이터베이스: sqlalchemy, greenlet
- 테스트: pytest, pytest-cov, coverage
- 유틸리티: python-dotenv, click

## 개발

### 테스트 실행

```bash
# pytest 설치 (requirements.txt에 포함)
pip install pytest pytest-cov

# 테스트 실행
pytest

# 커버리지 포함
pytest --cov=.
```

### 코드 포맷팅

```bash
# black 설치 (requirements.txt에 포함)
pip install black

# 코드 포맷팅
black app.py

# 린팅
flake8 app.py
```

## 문제 해결

### pip 설치 실패

```bash
# pip 업그레이드
pip install --upgrade pip

# 캐시 삭제 후 재설치
pip install --no-cache-dir -r requirements.txt
```

### SBOM이 비어있음

```bash
# requirements.txt 위치 확인
ls -la requirements.txt

# requirements.txt 생성
pip freeze > requirements.txt
```

### Python 버전 오류

```bash
# Python 버전 확인
python --version

# Python 3.8 이상 필요
# pyenv 등으로 Python 버전 관리 권장
```

### 가상 환경 문제

```bash
# 가상 환경 삭제 후 재생성
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Poetry 사용 (선택)

Poetry를 사용하는 경우:

```bash
# pyproject.toml 생성
poetry init

# 의존성 추가
poetry add flask pandas numpy requests

# SBOM 생성
../../scripts/scan-sbom.sh \
  --project "PythonPoetryExample" \
  --version "1.0.0" \
  --generate-only
```

## 다음 단계

- [사용 가이드](../../docs/reference/cli.ko.md) - 상세한 사용법
- [시작하기](../../docs/start/first-scan.ko.md) - 첫 SBOM 생성
- [Docker 가이드](../../docker/README.md) - Docker 이미지 사용법

## 참고

이 예제는 SBOM 생성 테스트 목적으로 만들어졌습니다. 실제 프로덕션 환경에서는 인증, 에러 처리, 로깅, 모니터링 등을 추가해야 합니다.
