---
description: 생성한 SBOM을 Dependency-Track 서버나 TRUSCA 네이티브 ingest 엔드포인트로 업로드합니다.
---

# Dependency-Track / TRUSCA 업로드

스캐너가 생성한 SBOM을 업로드하는 방법과 TRUSCA 네이티브 ingest 엔드포인트로 보내는 방법을 설명합니다.

스캔이 끝나면 기본적으로 SBOM을 업로드합니다(`--generate-only`이면 로컬 저장만 하고 업로드는 건너뜁니다). 업로드 대상은 `UPLOAD_TARGET`으로 고릅니다.

- `dependency-track`(기본): 일반 Dependency-Track 서버. `API_URL`과 `API_KEY`(`X-Api-Key`)로 인증하며 프로젝트를 자동 생성합니다.
- `trusca`: TRUSCA 네이티브 ingest 엔드포인트. Dependency-Track와 호환되지 않아 인증 방식과 입력이 다릅니다.

TRUSCA에 올리려면 세 가지를 준비합니다.

- `API_URL`: TRUSCA 서버 주소
- `API_KEY`: TRUSCA가 발급한 Bearer 토큰(`tos_`로 시작, developer 권한)
- project_id: 업로드할 TRUSCA 프로젝트 id(UUID). 사전에 존재해야 하며 자동 생성되지 않습니다.

```bash
API_URL="https://<TRUSCA 주소>" API_KEY="tos_..." \
  ./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.2.3" --all \
  --trusca "<project_id>"
```

`--trusca <id>`는 `--upload-target trusca`와 `TRUSCA_PROJECT_ID` 설정을 합친 단축형입니다. ref와 release 라벨은 `TRUSCA_REF`(기본 `main`)와 `TRUSCA_RELEASE`(기본 `--version` 값)로 조정합니다. 업로드가 접수되면 `202`와 스캔 id를 출력하며, 진행 상태는 TRUSCA UI(`GET /v1/scans/{id}`)에서 확인합니다.

> TRUSCA ingest는 컴포넌트, 취약점, 선언 라이선스, 의존성 그래프, 빌드 게이트를 채웁니다. scancode 정밀 라이선스(`--deep-license`), cosign 서명(`--sign`), 소스 보존은 소스 트리가 없어 채우지 못합니다. 이 산출물이 필요하면 `--generate-only`로 로컬에 함께 생성하세요.
