# Vendored-OSS identification — adversarial test campaign findings

> 성격: 메인테이너용 내부 기록. `--identify-vendored`(C/C++ vendored 오픈소스 SCANOSS 식별, PR #168)를 CLI·UI 모두에서 적대적으로 테스트한 캠페인의 발견 사항과 처리.

## 커버리지 (세 층)

- **Layer 1 — No-Docker 적대 단위** (`tests/test-vendored-adversarial.sh`, 27 assertions): mock scanoss-py로 악성·기형 raw를 주입. CPE 인젝션, 버전 형태, 필드 누락, snippet 제외, 무효 JSON, 중복 dedup, 이름/경로 인젝션, 2000-매치 대량, reconcile 엣지, suggest 경계, byte-stable. CI postprocess job 편입.
- **Layer 2 — 실 OSSKB** (로컬 scanoss-py 1.53.1로 실 api.osskb.org; 컨테이너 경로는 `SCANOSS_E2E` 게이트로 `tests/test-e2e.sh`에 영구화. 공유 Docker 디스크 부족으로 이미지 빌드는 보류).
- **Layer 3 — Playwright UI** (`docker/web/frontend/tests/ui/`, 4 specs): 브라우저 자동화 신규 도입. API를 page.route로 스텁해 토글 게이팅·배너·배지+match%·XSS를 결정적으로 검증. CI `ui` job 편입.

## 발견 사항

### F1 — 적대적 버전이 깨진 CPE를 만든다 (버그, 수정 완료)

- **심각도: 높음.** SCANOSS 매치 버전에 `:`·공백·와일드카드가 있으면(`1.0:evil va*l`) cpe:2.3 version 필드에 그대로 들어가 13필드 문법이 어긋남(14필드). 잘못된 CPE는 Trivy가 SBOM 전체를 거부해 보안 보고서를 비울 수 있음(swift-purl 버그와 동일 계열).
- **수정**: `normalize-sbom.sh`가 버전이 CPE-safe 토큰일 때만 CPE를 합성, 아니면 식별만(PURL 유지, CPE 없음). 정상 버전(`3.0.0`, `1.1.1w`, `3.0.0-beta2`, `1_1_1w`)은 유효한 13필드 CPE 유지.
- **회귀**: Layer 1의 CPE 인젝션 케이스(적대 6종 → CPE 없음, 정상 4종 → 유효 CPE).

### F2 — 다운스트림 포크로 잘못 귀속 (한계, 문서화)

- **심각도: 중간.** 실 OSSKB로 zlib v1.2.11 소스 5개를 스캔하니 `madler/zlib`가 아니라 SourceForge의 `api-simple-completa`(version `2025-03`)로 매치됨. madler/zlib는 purl에 아예 없음. 흔히 복사되는 파일은 그것을 vendored한 다운스트림 프로젝트로 귀속될 수 있고, 그러면 실제 zlib가 다른 이름으로 보고돼 CVE를 놓침.
- **원인**: 지식 베이스의 랭킹·커버리지 한계(무료 OSSKB에서 더 두드러짐). 우리 파이프라인 버그 아님.
- **처리**: 가이드에 명시 + 더 정확한 귀속이 필요하면 `SCANOSS_API_URL`로 상용·자체 호스팅 엔드포인트 권고. 기존 best-effort·검토 전제·`status:pending` 자세와 일치.

### F3 — 공개 소스 자가 매치 (한계, 예상 동작)

- **심각도: 낮음.** `examples/nodejs/index.js`가 우리 자신의 공개 repo `pkg:github/sktelecom/sbom-tools`로 매치. 공개 저장소에 이미 게시된 파일은 그 저장소로 매치되는 정상 동작.
- **처리**: 의도한 용도(비공개 공급사 C 소스)에는 발생하지 않음. C/C++·무패키지매니저 스코핑과 자동 제안 게이트, reconcile이 이를 추가로 억제. 가이드에 명시.

## 결함 없음으로 확인된 항목 (실측·단위)

first-party 독점 C → 매치 0(오탐 없음); `node_modules` 등 `--skip-folder` 제외 동작; 잘못된 엔드포인트·무네트워크 graceful degrade; snippet 제외; purl 기준 dedup; reconcile 정확일치만/대소문자/null base; suggest 경계(헤더만 트리·루트 manifest 억제); byte-stable 결정성; 2000-매치 대량; NOTICE.html XSS 이스케이프; UI 토글 게이팅·배너·배지+match%·XSS 무력화.

## 순효과

코드 버그 1건(F1, 고위험) 발굴·수정·회귀 고정. 한계 2건(F2·F3)은 지식 베이스 품질 문제로, 문서화 + 상용 KB 경로 안내로 처리. 세 층의 테스트가 CI에 영구 편입됨.
