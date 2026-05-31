# 후속 구현 지시문 (Implementation Prompts)

펌웨어 분석(FIRMWARE 모드)과 공급사 SBOM 검증·분석(ANALYZE 모드)은 **설계·문서화는 완료**되었고 **실제 코드 구현은 후속 작업**입니다. 아래 지시문을 **새 세션에 그대로 붙여넣으면** 바로 구현을 시작할 수 있습니다.

- 설계 근거: [firmware-analysis.md](../firmware-analysis.md), [supplier-sbom-analysis.md](../supplier-sbom-analysis.md), [direction-study.md](../direction-study.md) Phase 6·7
- 두 기능은 독립적이므로 **각각 별도 세션**에서 진행 권장(컨텍스트 분리·리뷰 단위 명확). 순서: 지시문 1(펌웨어) → 지시문 2(공급사).

---

## 지시문 1 — 펌웨어 분석 (FIRMWARE 모드)

```
sbom-tools(/Users/1112821/projects/sbom-tools)에 펌웨어 분석 기능(FIRMWARE 모드)을 구현해.

## 먼저 읽을 것 (설계는 이미 확정·문서화됨)
- docs/firmware-analysis.md (특히 §5 구현 설계, §6 Phase 분해, §8 라이선스 주의)
- docs/direction-study.md 의 "Phase 6 — 펌웨어 분석"
- 기존 패턴 참고: docker/entrypoint.sh(case 구조/공통 파이프라인), docker/lib/scan-security.sh·generate-notice.sh(인자·로깅·jq 스타일), scripts/scan-sbom.sh(MODE 분기·pp_env·docker run)

## 확정된 결정 (다시 묻지 말 것)
- 언팩: unblob 기본 + BANG 폴백.
- 식별: syft dir + cve-bin-tool. 기존 normalize/notice/security 후처리 무수정 재사용.
- SCANOSS·함수 핑거프린팅은 Phase 3(보류). 이번 목표 = Phase 1+2.
- 패키징: 무거운 도구는 별도 opt-in 이미지 sbom-scanner-firmware 에만. 기본 이미지는 건드리지 말 것(permissive-only 유지).

## 구현 범위
1. docker/lib/scan-firmware.sh (신규): mktemp 작업디렉터리(trap cleanup) → 언팩(unblob 우선, 실패/미설치 시 BANG) → rootfs 탐색 → syft dir → cve-bin-tool(CycloneDX) → jq/cyclonedx-cli 병합 → $OUTPUT_FILE. 기존 lib 스타일(인자 위치, [prefix] 로깅, best-effort) 준수.
2. docker/entrypoint.sh: BINARY case 뒤에 FIRMWARE) case 추가 → scan-firmware.sh 호출. LIBDIR 정의를 case 블록 위로 이동. 그 아래 공통 파이프라인은 그대로 재사용.
3. scripts/scan-sbom.sh: FIRMWARE_IMAGE 변수, is_firmware() 헬퍼(확장자 .bin/.img/.squashfs/.ubi/.trx 등 + magic), 타깃 감지 분기, --firmware 강제 플래그, case에 FIRMWARE 디스패치(RUN_IMAGE 선택). --help 갱신.
4. docker/Dockerfile: ARG SBOM_FIRMWARE=false + 버전 핀(UNBLOB/CVE_BIN_TOOL/BANG). scancode opt-in 블록 패턴 그대로 COPY 이전에 firmware opt-in RUN 추가. 펌웨어 이미지 LABEL(라이선스/소스 오퍼).
5. THIRD_PARTY_LICENSES.md: 펌웨어 이미지 표가 이미 있으니 실제 설치 버전과 일치하는지 확인·갱신. 기본 이미지 GPL-free 회귀 점검(CI 또는 테스트).
6. tests/: 소형 squashfs fixture로 FIRMWARE e2e 케이스 추가(tests/test-scan.sh 또는 test-e2e.sh 패턴). 기본 이미지에 firmware 도구 미설치 회귀 확인.

## 작업 원칙
- 기존 코드/유틸 재사용 최대화. 임의로 아키텍처·파싱 로직 변경 금지(CLAUDE.md 규칙).
- POSIX/엄격 에러 처리, ShellCheck 통과. 에러 메시지는 원인+해결 안내.
- 검증: VERBOSE=true ./tests/test-scan.sh 통과. 펌웨어 이미지 빌드(docker build --build-arg SBOM_FIRMWARE=true -t sbom-scanner-firmware ./docker) 후 squashfs fixture로 scan-sbom.sh --firmware --all --generate-only → SBOM components>0, security/NOTICE 생성 확인.
- 커밋: main 직접 금지. 기능 브랜치(feat/firmware-mode 등) + PR. Conventional Commits(feat(scanner): ...). 다른 세션 작업 파일과 분리해서 add. 푸시·PR·머지는 내가 지시할 때만.
```

---

## 지시문 2 — 공급사 SBOM 검증·분석 (ANALYZE 모드)

```
sbom-tools(/Users/1112821/projects/sbom-tools)에 공급사 제출 SBOM 검증·분석 기능(ANALYZE 모드)을 구현해.

## 먼저 읽을 것 (설계는 이미 확정·문서화됨)
- docs/supplier-sbom-analysis.md (§3 ANALYZE 모드, §4 검증기, §5 SPDX 변환, §6 위험 보고서, §7 Phase)
- docs/direction-study.md 의 "Phase 7 — 공급사 제출 SBOM 검증·분석"
- SKT 가이드: https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/
- 기존 패턴 참고: docker/entrypoint.sh(POSTPROCESS case·공통 파이프라인), docker/lib/scan-security.sh·generate-notice.sh(스타일), scripts/scan-sbom.sh(MODE 분기·마운트·pp_env)

## 확정된 결정 (다시 묻지 말 것)
- 입력: --analyze <sbom> (별칭 --sbom), CycloneDX/SPDX 모두. --target과 상호배타.
- SPDX는 입력을 CycloneDX로 변환(syft convert 재사용)해 단일 경로화 → normalize/generate-notice는 변경하지 말 것.
- 검증(conformance)은 변환 전 "원본" 기준으로 수행.
- 이번 목표 = 전체(검증+분석+위험보고서, Phase 1~3). 웹 UI 업로드(Phase 4)는 후순위/보류.
- 역할 경계: sbom-tools=로컬 단일 SBOM 검증·분석·보고서. TOSCA/전사 관리는 범위 밖.

## 구현 범위
1. docker/lib/validate-sbom.sh (신규): SKT 요구사항 충족 검증. 포맷 판별(CycloneDX/SPDX-JSON/SPDX-TagValue), 필수(timestamp·tool·top-component·name/version·PURL·pkg:generic 금지·transitive edge 존재) + 권장(license/hash) 커버리지. 임계치 상단 변수화. pass/fail + 누락 목록 → _conformance.{json,md,html}. 파이프라인 중단 금지.
2. docker/lib/convert-to-cdx.sh (신규): CycloneDX면 cp, SPDX면 syft convert -o cyclonedx-json, 실패 시 jq fallback(.packages→.components, 라이선스 보존).
3. docker/lib/generate-risk-report.sh (신규): 새 스캔 없이 _conformance.json·_security.json·_NOTICE.* 재집계 → 요구사항 충족표 + 취약점 집계 + Critical 7일/High 30일 대응 기한 문구 + 다음 단계 → _risk-report.{md,html}.
4. docker/entrypoint.sh: ANALYZE) case 신설 → ① validate-sbom.sh(원본) ② convert-to-cdx.sh로 $OUTPUT_FILE 생성. 이후 공통 파이프라인 재사용. 끝에 generate-risk-report.sh. conformance/risk-report를 ARTIFACTS에 누적.
5. scripts/scan-sbom.sh: --analyze/--sbom 플래그 + ANALYZE_SBOM, MODE=ANALYZE, 입력 디렉터리 /input:ro 마운트(BINARY의 FD/FN 패턴), --analyze 시 GENERATE_NOTICE/SECURITY 자동 on, --target 상호배타 검증, --help 갱신.
6. HTML 산출물은 scan-security.sh의 카드/테이블·CSP·이스케이프 패턴 차용.

## 작업 원칙
- 기존 코드/유틸 재사용 최대화. normalize-sbom.sh·generate-notice.sh는 변경 불필요(변환 단일 경로). 임의 로직 변경 금지(CLAUDE.md).
- POSIX/엄격 에러 처리, ShellCheck 통과. 외부 입력(JSON) 파싱 시 경로 탐색·주입 방어 유효성 검사.
- 검증(host jq로 Docker 없이 가능, tests/test-e2e.sh Group 2 패턴): 정상 CycloneDX→pass / 정상 SPDX→pass+변환 후 components>0+라이선스 추출 / 결함 SBOM 4종(pkg:generic·PURL누락·tools없음·dependencies없음)→각각 fail+누락목록 / 위험보고서에 "7일"·"30일"·Critical/High 표 / --help에 --analyze 노출. fixture는 tests/fixtures/에 신규 추가.
- 커밋: main 직접 금지. 기능 브랜치(feat/analyze-mode 등) + PR. Conventional Commits(feat(scanner): ...). 다른 세션 작업과 분리. 푸시·PR·머지는 내가 지시할 때만.
```
