# Node.js 프로젝트 예제

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

Express.js 기반 간단한 REST API 애플리케이션입니다. SBOM 생성 테스트를 위한 예제로 사용됩니다. Express, Helmet, CORS, Morgan, Lodash, Moment, Winston 등 널리 쓰이는 npm 패키지를 의존성으로 포함합니다.

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

결과는 `NodeJsExpressExample_1.0.0/` 폴더에 저장됩니다(`NodeJsExpressExample_1.0.0_bom.json` 등).

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

이 방법은 스크립트와 달리 출력 폴더에 바로(하위 폴더 없이) 저장됩니다.

### 방법 3: @cyclonedx/cyclonedx-npm 사용

```bash
npx @cyclonedx/cyclonedx-npm --output-file bom.json
```

## 생성된 SBOM 확인

```bash
# SBOM 파일 확인
ls -lh NodeJsExpressExample_1.0.0/NodeJsExpressExample_1.0.0_bom.json

# 컴포넌트 개수 확인 (jq 필요)
cat NodeJsExpressExample_1.0.0/NodeJsExpressExample_1.0.0_bom.json | jq '.components | length'

# Express 관련 의존성 확인
cat NodeJsExpressExample_1.0.0/NodeJsExpressExample_1.0.0_bom.json | jq -r '.components[] | select(.name | contains("express")) | "\(.name)@\(.version)"'
```

예상 컴포넌트 수는 약 100-140개입니다(배포 의존성 + 전이적 의존성). 스캔은 배포에 포함되는 `dependencies`만 담고, `devDependencies`(jest·eslint 등 빌드/테스트 도구)는 제외합니다.
<!-- expected-components: 100-140 -->

생성된 SBOM에는 다음과 같은 정보가 포함됩니다:

- Express 스택: express, body-parser, cookie-parser, serve-static
- 보안: helmet, cors
- 유틸리티: lodash, moment, dotenv
- 로깅: morgan, winston
- HTTP: axios, http-errors
- 압축: compression

## 문제 해결

### SBOM이 비어있음

```bash
# package.json 위치 확인
ls -la package.json

# package-lock.json 생성
npm install --package-lock-only

# 의존성 확인
npm list
```

### npm install 실패

```bash
# 캐시 삭제
npm cache clean --force

# node_modules 삭제 후 재설치
rm -rf node_modules package-lock.json
npm install
```

## Yarn / pnpm 사용 (선택)

Yarn(`yarn install`)이나 pnpm(`pnpm install`)으로 잠금 파일(`yarn.lock`, `pnpm-lock.yaml`)을 생성한 프로젝트도 같은 방식으로 스캔할 수 있습니다. `--project` 이름만 바꿔서 방법 1 명령을 그대로 실행하면 됩니다.

## 다음 단계

- [사용 가이드](../../docs/reference/cli.ko.md) - 상세한 사용법
- [시작하기](../../docs/start/first-scan.ko.md) - 첫 SBOM 생성
- [Docker 가이드](../../docker/README.md) - Docker 이미지 사용법

## 참고

이 예제는 SBOM 생성 테스트 목적으로 만들어졌습니다. 실제 프로덕션 환경에서는 인증, 데이터베이스 연동, 에러 처리, 로깅, 모니터링 등을 추가해야 합니다.
