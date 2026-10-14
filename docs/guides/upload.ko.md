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

## 웹 UI에서

CLI 없이도 업로드할 수 있습니다. 새 스캔 화면에서 **업로드** 단계를 켜고 Dependency-Track 또는 TRUSCA를 고른 뒤 서버 주소와 접근 토큰을 입력합니다(TRUSCA는 프로젝트 id도 입력). 스캔이 실행된 뒤 위에서 설명한 것과 같은 엔드포인트와 인증으로 한 번에 업로드합니다. 주소와 토큰은 그 실행에만 쓰이고 저장되지 않습니다. 자세한 내용은 [웹 UI 레퍼런스](../reference/ui.ko.md)를 참고하세요.

## 문제 해결

| 증상 | 원인/해결 |
|------|-----------|
| `TRUSCA upload needs API_URL, API_KEY (Bearer token), and TRUSCA_PROJECT_ID` | 셋 중 하나가 빠졌습니다. `--trusca`/`UPLOAD_TARGET=trusca`는 세 가지 모두 필요하며 일부만 넣는 방식은 없습니다. |
| `API_KEY and API_URL are required for upload` | Dependency-Track 경로(기본 대상)도 같은 조건입니다. |
| `Upload to <url> did not complete (curl exit N: no response)` | 서버에 닿지 않습니다 — 주소가 틀렸거나 네트워크·프록시 문제거나 서버가 꺼져 있습니다. 스캔 자체는 이미 끝나 산출물은 저장돼 있으므로, `API_URL`을 고쳐 다시 업로드하거나 `--generate-only`로 업로드 단계 자체를 건너뛰세요. |
| `TRUSCA ingest failed (HTTP <code>)` | TRUSCA가 요청을 거부했습니다. 오류와 함께 찍히는 응답 본문에 이유가 있습니다(잘못된 토큰, 존재하지 않는 프로젝트 id, 형식이 잘못된 SBOM 등). |
| `Upload failed (HTTP <code>)` (Dependency-Track) | 마찬가지로 찍히는 응답 본문에 서버가 밝힌 이유가 있습니다. 401이면 대개 `API_KEY`가 잘못됐거나 만료된 것입니다. |
| `Cannot reach Dependency Track at <url>` (경고일 뿐, 실패 아님) | 사전 확인이 실패해도 업로드는 그대로 시도합니다. 일부 서버는 버전 조회 엔드포인트는 막아 두고 BOM 업로드는 받기 때문입니다. 뒤이은 업로드마저 실패하면 그때는 실제 연결 문제입니다. |
| `Dependency-Track ... refused the CycloneDX 1.7 SBOM (HTTP 400)` (경고) | Dependency-Track은 4.14.4와 5.1.0부터 CycloneDX 1.7을 읽으며, 그보다 오래된 서버는 1.7 SBOM을 거부합니다. `--spec-version 1.7`로 만든 SBOM과, 기본값에서도 1.7인 AI 모델과 데이터셋 SBOM(`--model`)이 여기에 해당합니다. 서버의 `/api/version`이 이보다 오래된 버전을 알리거나 버전을 알리지 않으면 SBOM의 1.6 사본을 한 번 더 보내고, 저장된 SBOM은 1.7로 유지합니다. 사본에서는 1.6이 허용하지 않는 부분도 고칩니다. 라이선스와 표현식이 섞인 라이선스 목록은 `AND`로 이은 표현식 하나가 되고(SPDX id가 없는 라이선스가 있으면 라이선스 목록이 됩니다), 1.7에만 있는 필드는 지웁니다. 사본도 거부되면 두 응답을 모두 출력합니다. |
| `Dependency-Track <version> reads CycloneDX 1.7, so the refusal (HTTP 400) is not about the version` (경고) | 서버가 4.x의 4.14.4 이상이거나 5.1.0 이상이어서 1.7 SBOM(`--spec-version 1.7` 또는 `--model`)을 읽으므로 1.6 사본을 보내지 않습니다. 출력된 응답 본문에 서버가 거부한 이유가 있습니다. |

TRUSCA는 `HTTP 202`가 접수를 큐에 넣었다는 뜻일 뿐입니다. 완료까지 추적하는 건 BomLens가 아니라 TRUSCA UI(`GET /v1/scans/{id}`)에서 합니다.

---

> **관련 문서**: [CLI 레퍼런스](../reference/cli.ko.md) | [웹 UI 레퍼런스](../reference/ui.ko.md) | [고지문·보안·위험 보고서 생성](reports.ko.md)
