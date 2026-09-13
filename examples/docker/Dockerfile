# Docker 이미지 SBOM 예제
# 
# 멀티 스테이지 빌드를 사용한 Node.js 애플리케이션 예제
# SBOM 생성 테스트를 위한 Docker 이미지입니다.

# Stage 1: Builder
FROM node:18-alpine AS builder

WORKDIR /build

# package.json 복사 및 의존성 설치
COPY package*.json ./
RUN npm install --omit=dev

# 애플리케이션 코드 복사
COPY index.js ./

# Stage 2: Production
FROM node:18-alpine

LABEL maintainer="SK Telecom OSPO <opensource@sktelecom.com>"
LABEL description="SBOM Example Docker Image"
LABEL version="1.0.0"

# 보안: 비-루트 사용자 생성
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Builder 스테이지에서 필요한 파일만 복사
COPY --from=builder --chown=nodejs:nodejs /build/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /build/package*.json ./
COPY --from=builder --chown=nodejs:nodejs /build/index.js ./

# 비-루트 사용자로 전환
USER nodejs

# 헬스 체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

EXPOSE 3000

CMD ["node", "index.js"]
