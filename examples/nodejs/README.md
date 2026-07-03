# Node.js 프로젝트 예제

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

Express.js 기반 간단한 REST API 애플리케이션입니다. SBOM 생성 테스트를 위한 예제로 사용됩니다.

## 프로젝트 정보

- 언어: Node.js 18+
- 프레임워크: Express.js 4.18
- 주요 의존성:
  - Express (웹 프레임워크)
  - Helmet (보안)
  - CORS (교차 출처 리소스 공유)
  - Morgan (로깅)
  - Lodash (유틸리티)
  - Moment (날짜/시간)
  - Winston (로거)

## 사전 요구사항

- Node.js 18 이상
- npm 9 이상 (또는 Docker)

## SBOM 생성

### 방법 1: BomLens 스크립트 사용 (권장)

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/start/first-scan.ko.md) 참고.

```bash
# 프로젝트 디렉토리로 이동
cd examples/nodejs

# package-lock.json 생성 (없는 경우)
npm install --package-lock-only

# SBOM 생성
../../scripts/scan-sbom.sh \
  --project "NodeJsExpressExample" \
  --version "1.0.0" \
  --generate-only
```

결과로 `NodeJsExpressExample_1.0.0_bom.json` 파일이 생성됩니다.

### 방법 2: Docker 직접 사용

```bash
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="NodeJsExpressExample" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/bomlens:latest
```

### 방법 3: @cyclonedx/bom 사용

```bash
# @cyclonedx/bom 설치
npm install -g @cyclonedx/bom

# SBOM 생성
cyclonedx-npm --output-file bom.json
```

## 애플리케이션 실행

### 의존성 설치

```bash
# package-lock.json 생성 및 의존성 설치
npm install
```

### 개발 모드 실행

```bash
# nodemon 사용 (자동 재시작)
npm run dev

# 또는 일반 실행
npm start
```

접속 주소는 http://localhost:3000 입니다.

### 프로덕션 모드

```bash
NODE_ENV=production npm start
```

### Docker로 실행

```bash
# Dockerfile 생성
cat > Dockerfile <<EOF
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY index.js ./

EXPOSE 3000

CMD ["node", "index.js"]
EOF

# 빌드 및 실행
docker build -t nodejs-example:latest .
docker run -p 3000:3000 nodejs-example:latest
```

## API 엔드포인트

### GET /

메인 페이지 - 애플리케이션 정보 반환

```bash
curl http://localhost:3000/
```

응답:
```json
{
  "message": "SBOM Example Application is running!",
  "version": "1.0.0",
  "timestamp": "2026-01-15T10:30:00+09:00",
  "framework": "Express.js"
}
```

### GET /health

헬스 체크 및 시스템 정보

```bash
curl http://localhost:3000/health
```

응답:
```json
{
  "status": "OK",
  "uptime": 123.456,
  "memory": {
    "rss": 50000000,
    "heapTotal": 20000000,
    "heapUsed": 15000000
  }
}
```

### GET /data

샘플 데이터 반환 (Lodash 사용)

```bash
curl http://localhost:3000/data
```

응답:
```json
{
  "data": [
    {
      "id": 1,
      "value": 42,
      "label": "Item 1",
      "timestamp": "2026-01-14T10:30:00+09:00"
    }
  ],
  "count": 10
}
```

### POST /analyze

숫자 배열 통계 분석

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"numbers": [1, 2, 3, 4, 5]}'
```

응답:
```json
{
  "mean": 3,
  "sum": 15,
  "min": 1,
  "max": 5,
  "count": 5
}
```

### GET /utils/date

날짜/시간 유틸리티 (Moment.js 사용)

```bash
curl http://localhost:3000/utils/date
```

응답:
```json
{
  "current": "2026-01-15 10:30:00",
  "utc": "2026-01-15 01:30:00",
  "unix": 1705294200,
  "iso": "2026-01-15T01:30:00.000Z"
}
```

## 생성된 SBOM 확인

```bash
# SBOM 파일 확인
ls -lh NodeJsExpressExample_1.0.0_bom.json

# 컴포넌트 개수 확인 (jq 필요)
cat NodeJsExpressExample_1.0.0_bom.json | jq '.components | length'

# Express 관련 의존성 확인
cat NodeJsExpressExample_1.0.0_bom.json | jq -r '.components[] | select(.name | contains("express")) | "\(.name)@\(.version)"'
```

예상 컴포넌트 수는 약 80-120개입니다(전이적 의존성 포함).
<!-- expected-components: 80-120 -->

## 예상 SBOM 내용

생성된 SBOM에는 다음과 같은 정보가 포함됩니다:

- Express 스택: express, body-parser, cookie-parser, serve-static
- 보안: helmet, cors
- 유틸리티: lodash, moment, dotenv
- 로깅: morgan, winston
- HTTP: axios, http-errors
- 압축: compression
- 개발 도구: nodemon, jest, eslint, prettier

## 개발

### 테스트 실행

```bash
# Jest로 테스트
npm test

# 커버리지 포함
npm test -- --coverage
```

### 린팅

```bash
# ESLint
npm run lint

# Prettier
npm run format
```

### 환경변수

`.env` 파일 생성:

```bash
PORT=3000
NODE_ENV=development
LOG_LEVEL=info
```

## 문제 해결

### npm install 실패

```bash
# 캐시 삭제
npm cache clean --force

# node_modules 삭제 후 재설치
rm -rf node_modules package-lock.json
npm install
```

### SBOM이 비어있음

```bash
# package.json 위치 확인
ls -la package.json

# package-lock.json 생성
npm install --package-lock-only

# 의존성 확인
npm list
```

### Node.js 버전 오류

```bash
# Node.js 버전 확인
node --version

# Node.js 18 이상 필요
# nvm 사용 권장
nvm install 18
nvm use 18
```

### 포트 충돌

```bash
# 다른 포트 사용
PORT=3001 npm start

# 또는 .env 파일 수정
echo "PORT=3001" > .env
```

## Yarn 사용 (선택)

Yarn을 사용하는 경우:

```bash
# yarn.lock 생성
yarn install

# SBOM 생성
../../scripts/scan-sbom.sh \
  --project "NodeJsYarnExample" \
  --version "1.0.0" \
  --generate-only
```

## pnpm 사용 (선택)

pnpm을 사용하는 경우:

```bash
# pnpm-lock.yaml 생성
pnpm install

# SBOM 생성
../../scripts/scan-sbom.sh \
  --project "NodeJsPnpmExample" \
  --version "1.0.0" \
  --generate-only
```

## 다음 단계

- [사용 가이드](../../docs/reference/cli.ko.md) - 상세한 사용법
- [시작하기](../../docs/start/first-scan.ko.md) - 첫 SBOM 생성
- [Docker 가이드](../../docker/README.md) - Docker 이미지 사용법

## 참고

이 예제는 SBOM 생성 테스트 목적으로 만들어졌습니다. 실제 프로덕션 환경에서는 인증, 데이터베이스 연동, 에러 처리, 로깅, 모니터링 등을 추가해야 합니다.
