# 검출 모드 (Detection Modes)

> **관련 문서**: [아키텍처](../concepts/architecture.ko.md) · [입력별 파이프라인](../concepts/pipeline-by-input.ko.md) · [방향성 조사 보고서](direction-study.md) · [개선 로드맵](improvement-roadmap.md)
>
> 성격: 설계·의사결정 문서 (메인테이너용). **미구현 — 제안 단계**입니다. SOURCE 스캔이 무조건 빌드+Docker로만 동작하는 현행에, 빌드를 생략하는 경량·정적 검출 모드를 옵트인으로 더하는 설계입니다. 출처는 OpenChain Korea Work Group SCA 벤치마크 팀의 검출 모드 제안 보고서입니다. 정적 백엔드 최종 선택은 벤치마크 후로 남겨 둡니다.

## 요약 (Executive Summary)

현행 SOURCE 스캔은 언어별 cdxgen Docker 이미지를 띄우고 실제로 빌드·설치(`pip install`, `go mod tidy`, `gradle dependencies` 등)한 뒤 스캔합니다. 이 방식은 전이 의존성 버전 정확도, 다언어 지원, 재현성, 격리에서 강점이 큽니다. 다만 모든 입력에 최적은 아닙니다. 빌드가 불가능하거나, 보안상 외부 코드를 실행할 수 없거나, 빠른 사전 스캔이 더 중요한 상황이 있습니다.

이 문서는 기본(현행) 방식을 그대로 두고, 빌드를 생략하는 두 모드를 옵트인으로 더하는 설계를 다룹니다.

- 경량(lightweight): Docker를 생략하고 호스트의 빌드 도구를 재사용합니다. 빌드 환경이 이미 갖춰진 CI나 단일 언어 프로젝트에서 시작 시간을 줄입니다. 비용은 재현성과 격리가 약해지는 것입니다.
- 정적(static): 설치 없이 매니페스트와 lockfile만 해석합니다. 빠르고 결정적이며, 코드를 실행하지 않아 안전합니다. 비용은 전이 의존성 버전이 근사하다는 점입니다.

핵심 결정은 새 MODE를 만들지 않고, SOURCE에만 적용되는 직교 옵션 `DETECTION=build|lightweight|static`(기본 `build`)으로 도입하는 것입니다. 이렇게 하면 9개 MODE 디스패치와 stage2(POSTPROCESS) 파이프라인을 손대지 않습니다.

## 목차
- [1. 배경 — 현행 검출 방식과 벤치마크 관찰](#1-배경--현행-검출-방식과-벤치마크-관찰)
- [2. 설계 — 직교 옵션 DETECTION](#2-설계--직교-옵션-detection)
- [3. CLI 표면](#3-cli-표면)
- [4. 웹 UI 인프로세스 경로 (entrypoint)](#4-웹-ui-인프로세스-경로-entrypoint)
- [5. 정적 백엔드 비교 (syft vs OSV-SCALIBR)](#5-정적-백엔드-비교-syft-vs-osv-scalibr)
- [6. 품질 신호 (degraded)](#6-품질-신호-degraded)
- [7. 웹 UI 표면](#7-웹-ui-표면)
- [8. 기본값과 자동 추천](#8-기본값과-자동-추천)
- [9. 트레이드오프와 영향 파일](#9-트레이드오프와-영향-파일)
- [10. 정직한 한계](#10-정직한-한계)

---

## 1. 배경 — 현행 검출 방식과 벤치마크 관찰

`scan-sbom.sh`가 언어별 cdxgen 이미지를 `docker run`으로 띄우고, 컨테이너 안에서 `build-prep.sh`가 빌드와 설치를 수행한 뒤 cdxgen이 설치된 환경을 스캔합니다. 그 결과 매니페스트만 파싱하는 도구가 놓치는 전이 의존성을 실제 설치 환경에서 정확한 버전으로 잡습니다.

벤치마크 팀의 관찰은 다음과 같습니다.

- lockfile이 없는 Python(requirements.txt)에서 실제 설치 방식과 정적 해석이 전이 의존성 11개를 모두 발견했지만, 핀되지 않은 전이의 버전이 갈렸습니다. 실제 설치는 `idna 2.10`(pip가 실제로 설치하는 버전), 정적 해석은 `idna 2.9.0`(resolver가 고른 값)이었습니다. 실제 설치가 실제로 놓이는 버전을 정확히 반영합니다.
- lockfile이 있는 입력(npm package-lock)에서는 모든 도구가 같은 결과로 수렴했습니다. 전이가 lockfile에 박제돼 있어 빌드가 변별을 만들지 못합니다.
- lockfile 관행이 약하고 빌드로만 전이가 풀리는 생태계(Gradle 등)에서는, 실제 빌드를 하는 기본 모드가 정적 해석보다 완전성에서 앞설 것으로 예상됩니다.

결론은 기본 모드를 대체하지 않고, 입력 상황에 맞춰 정확도와 속도·안전·이식성을 맞교환할 수 있도록 모드를 더하는 것입니다.

---

## 2. 설계 — 직교 옵션 DETECTION

검출 모드를 새 MODE로 만들지 않고, SOURCE에만 적용되는 직교 옵션 `DETECTION=build|lightweight|static`(기본 `build`)으로 도입합니다.

근거:

- 기존 9개 MODE(SOURCE/IMAGE/BINARY/ROOTFS/FIRMWARE/AIBOM/ANALYZE/MERGE/POSTPROCESS)는 "입력 종류와 SBOM 소싱 경로" 축입니다. 검출 모드는 동일한 SOURCE 입력을 어떤 비용과 정확도로 푸느냐는 별개 축이라, MODE로 곱하면 `entrypoint.sh`의 case 문과 `server.py`의 source별 MODE 매핑이 중복으로 늘어납니다.
- 검출 모드는 SOURCE에만 의미가 있습니다. IMAGE/BINARY/ROOTFS는 이미 빌드 없이 syft로 메타데이터를 읽고, FIRMWARE/AIBOM/ANALYZE/MERGE는 빌드 개념 자체가 없습니다. SOURCE 외 MODE에서 `DETECTION`은 무시됩니다. `--deep-license`나 `--identify-vendored`가 SOURCE 외에서 무시되는 기존 패턴과 같습니다.
- 현행 코드에 직교 축의 선례가 있습니다. `FETCH_LICENSE`, `DEEP_LICENSE`, `IDENTIFY_VENDORED`, `BYTE_STABLE`은 모두 SOURCE 동작을 변조하는 환경변수 플래그이지 MODE가 아닙니다. `DETECTION`은 같은 가족으로 들어갑니다.

모드 의미:

| `DETECTION` | stage1 실행 위치 | 빌드·설치 | 도구 | 전이 해석 |
|---|---|---|---|---|
| `build` (기본, 현행) | cdxgen 언어 이미지 (`docker run`) | 함 (`build-prep.sh`) | cdxgen | 설치 기반, 정확 |
| `lightweight` | 호스트 (Docker 생략) | 함 (호스트 도구) | 호스트 cdxgen + 언어 도구 | 설치 기반, 호스트 의존 |
| `static` | 인프로세스 | 안 함 | syft `dir:` (1차) 또는 OSV-SCALIBR (후보) | 매니페스트·lockfile 해석, 근사 |

---

## 3. CLI 표면

대상 파일: `scripts/scan-sbom.sh`

- 변수 초기화 블록에 `DETECTION="${DETECTION:-build}"`를 더합니다.
- 인자 루프(`--deep-license` 인접)에 `--detection) DETECTION="$2"; shift ;;`를 더합니다. `build|lightweight|static` 외의 값은 즉시 에러로 처리합니다. SOURCE 외 MODE에서 build가 아닌 값이 들어오면 하드 에러 대신 경고만 출력하고 진행합니다(기존 관용과 일치).
- 분기는 SOURCE stage1 블록 안에서만 합니다. stage2(POSTPROCESS) 파이프라인은 어느 모드에서도 손대지 않습니다. 세 모드 모두 stage1이 `$OUTPUT_HOST_DIR/$OUTPUT_FILE`에 CycloneDX를 남기면, normalize/notice/security/sign이 동일하게 흐릅니다. 이것이 직교 설계의 가장 큰 이득입니다.

3-way 분기:

- `build`: 현행 그대로(무변경).
- `lightweight`: `docker run`을 건너뛰고 호스트에서 `build-prep.sh`를 직접 호출합니다. `build-prep.sh`는 이미 인자 3개와 환경변수 3개 계약, 그리고 `command -v cargo/go/gradle/cdxgen` 가드를 갖춰 재작성이 필요 없습니다. 호출 위치만 컨테이너에서 호스트로 바뀝니다. 단 호스트 PATH에 `cdxgen`이 없으면 SBOM이 비므로 stage1 실패로 잡아 degraded 처리합니다.
- `static`: 빌드를 건너뛰고 정적 엔진을 한 번 호출합니다(1차는 호스트 `syft "dir:..." -o cyclonedx-json`). 이어서 `mark_sbom_degraded ... static-approximate`를 찍습니다. 언어 감지와 이미지 선택(`detect_lang`/`img_for_lang`)은 불필요합니다.

어느 파일이 바뀌는지:

| 파일·함수 | build | lightweight | static |
|---|---|---|---|
| `scan-sbom.sh` SOURCE 블록 | 무변경 | `docker run` → 호스트 `build-prep` 직접 호출 | 빌드 스킵, 정적 엔진 호출 |
| `docker/lib/build-prep.sh` | 그대로 | 그대로 재사용 (호스트에서 실행) | 미사용 |
| `docker/lib/source-detect.sh` | 그대로 | `detect_lang`만 사용 | 정적이 자체 감지하면 미사용 |
| `docker/entrypoint.sh` stage2 | 무변경 | 무변경 | 무변경 |

---

## 4. 웹 UI 인프로세스 경로 (entrypoint)

대상 파일: `docker/entrypoint.sh`

웹 UI의 SOURCE 스캔은 `entrypoint.sh`가 인프로세스로 처리하며, 이미 build(`generate_sbom_cdxgen`, sibling docker run) ↔ syft 폴백의 2-way 분기가 자연스럽게 있습니다. `DETECTION` 환경변수로 이 분기를 사용자 선택으로 승격합니다.

- `DETECTION=build`(기본): 조건 충족 시 `generate_sbom_cdxgen`, 실패 시 syft 폴백(현행 그대로).
- `DETECTION=static`: 조건을 평가하지 않고 곧장 syft `dir:` 실행 후 `mark_sbom_degraded ... static-approximate`.
- `DETECTION=lightweight`: 컨테이너 내부라 의미가 약합니다(이미 Docker 안). 웹 UI에서는 제공하지 않습니다([7절](#7-웹-ui-표면) 참조).

syft 폴백 경로가 두 가지 다른 의미(자동 폴백 대 사용자가 고른 static)를 갖게 되므로, reason 토큰을 구분합니다. 자동 폴백은 `cdxgen-unavailable`(현행 유지), 사용자 선택 static은 `static-approximate`입니다. 이 구분이 UI 메시지의 톤(경고 대 정상 선택)을 가릅니다.

---

## 5. 정적 백엔드 비교 (syft vs OSV-SCALIBR)

| 항목 | syft `dir:` (번들됨) | OSV-SCALIBR | osv-scanner |
|---|---|---|---|
| 번들 상태 | 이미지에 이미 존재 | 미통합, 신규 바이너리 | 미통합 |
| CycloneDX 직접 출력 | 예 (`-o cyclonedx-json`) | 부분적, 변환 필요 | 제한적 |
| 전이 (lockfile 있음) | lockfile 파싱으로 포함 | 강함, 생태계 폭넓음 | 강함 |
| 전이 (requirements.txt, lockfile 없음) | 직접 의존성 위주, 전이 약함 | 더 성숙(버전 근사) | 해석(근사) |
| Gradle (빌드로만 전이) | 약함 | 약함(정적 공통 한계) | 약함 |
| 결정성 | 높음 | 높음 | 높음 |
| 이미지 크기 비용 | 0 추가 | Go 바이너리 + DB | Go 바이너리 + OSV DB |
| 라이선스 | Apache-2.0 | Apache-2.0 | Apache-2.0 |
| 코드 실행 | 없음 | 없음 | 없음 |

결정: 1차 정적 백엔드는 syft `dir:`로 합니다. 이미 번들돼 추가 비용이 없고, 현행 폴백 경로를 옵트인으로 승격할 뿐이라 신규 코드가 최소이며, CycloneDX 직접 출력으로 stage2 파이프라인을 손대지 않습니다. 최종 선택은 벤치마크 후로 보류하되, OSV-SCALIBR 통합 지점만 미리 고정합니다.

1. Dockerfile: 정적 엔진 바이너리를 stage2 베이스 이미지에 더합니다. Apache-2.0이고 코드를 실행하지 않으므로 firmware/aibom처럼 opt-in 이미지로 격리할 필요는 없습니다.
2. `entrypoint.sh`에 `generate_sbom_static()` 헬퍼를 신설해 `generate_sbom_cdxgen` 옆에 두고, `DETECTION=static`일 때 호출합니다. CycloneDX를 직접 내지 않는 엔진은 `convert-to-cdx.sh`(ANALYZE 모드가 이미 사용)로 변환합니다.
3. 어느 엔진이든 `mark_sbom_degraded "$OUTPUT_FILE" "static-approximate"` 한 줄로 동일한 신호를 남깁니다. 백엔드를 교체해도 UI와 리포트 계약이 깨지지 않습니다.
4. `DETECTION_STATIC_ENGINE=syft|scalibr` 내부 환경변수(사용자에게 노출하지 않음, CI·운영자용)로 벤치마크 중 A/B를 토글합니다. 기본은 `syft`입니다.

---

## 6. 품질 신호 (degraded)

기존 `mark_sbom_degraded`를 그대로 재사용합니다. 이 함수는 `metadata.properties[]`에 `bomlens:sbom-tool-degraded = <reason>`을 박고, 서버가 이 신호를 읽어 UI에서 의존성 그래프가 얕은 이유를 설명합니다. 따라서 새 메커니즘 없이 reason 토큰만 확장합니다.

| 상황 | reason 토큰 | UI 톤 |
|---|---|---|
| 자동 폴백 (현행) | `cdxgen-unavailable` | 경고 (의도치 않게 얕음) |
| 디스크 부족 (현행) | `disk-space` | 경고 + 조치 안내 |
| 사용자 선택 static | `static-approximate` | 중립 (정적 모드 선택됨, 전이 버전 근사) |
| lightweight, 호스트 도구 부족 | `lightweight-host-incomplete` | 경고 |
| lightweight 정상 | 마킹 없음 또는 정보성 | 정상 |

핵심 원칙은 모드 선택이 SBOM에 흔적을 남긴다는 것입니다. 같은 입력이라도 어떤 모드로 떴는지가 `scan_config`([7절](#7-웹-ui-표면))과 SBOM 프로퍼티 양쪽에 기록되어, 결과를 비교할 때 정확도와 비용의 맞교환을 추적할 수 있습니다. 전이 버전의 근사성을 컴포넌트 단위로 더 분명히 드러내는 안(`bomlens:version-approximate` 프로퍼티)도 있으나, 후처리가 늘어 1차 범위 밖으로 둡니다.

---

## 7. 웹 UI 표면

셀렉터 위치: Scan Options 섹션(Outputs 아님). `useScanForm.ts` 주석대로 Outputs는 무엇이 생성되는가, Scan Options는 어떻게 스캔하는가입니다. 검출 모드는 스캔 방법이므로 deep-license·vendored와 같은 그룹에 둡니다. 두 토글과 달리 검출 모드는 3택이라, Scan Options 최상단에 세그먼트(Build / Lightweight / Static)로 두고 그 아래 기존 토글을 잇습니다.

가시성 게이팅: `isSourceScan`(current-dir/git-url/zip-upload) 조건을 재사용해 `showDetection = isSourceScan`으로 두고, `showScanOptions`에 OR로 더합니다.

lightweight는 호스트 도구에 의존합니다. 웹 UI 컨테이너 안에는 호스트 툴체인이 없어 사실상 불가능합니다. 따라서 `/capabilities`에 `lightweight`를 더하고(`lightweight_capable()` = `shutil.which("cdxgen") is not None`, `docker_capable()` 패턴을 따름), 컨테이너 UI에서는 보통 false가 되어 옵션을 숨깁니다. 결론적으로 웹 UI는 build와 static 2종만 노출하고, lightweight는 CLI의 1급 기능으로 둡니다(보고서의 CI·단일 언어 타깃과 일치). static은 syft가 번들돼 항상 가용합니다.

계약 필드는 하나만 늘립니다.

| 레이어 | 위치 | 추가 |
|---|---|---|
| 프론트 타입 | `api.ts` `ScanParams` | `detection: "build" \| "lightweight" \| "static"` |
| 폼 상태 | `useScanForm.ts` | 상태와 submit 매핑(`detection: showDetection ? detection : "build"`) |
| 재스캔 시드 | `ScanConfig` + `scan_config` | `detection` 기록 (`includeOsv` 패턴을 따름) |
| 와이어→env | `server.py` env.update | `env["DETECTION"]=...` (화이트리스트 검증, 외 값은 build로 강제) |
| 소비자 | `entrypoint.sh` SOURCE 분기 | `$DETECTION`을 읽어 [4절](#4-웹-ui-인프로세스-경로-entrypoint) 분기 |

---

## 8. 기본값과 자동 추천

기본값은 항상 `build`입니다. 보고서의 "기본 모드를 대체하지 않는다"는 권고의 핵심입니다. 사용자가 명시적으로 옵트인해야 lightweight나 static으로 갑니다.

자동 추천은 힌트로만 노출하고 자동 전환은 하지 않습니다. 자동 전환은 재현성을 깹니다(같은 명령이 환경에 따라 다른 모드로 뜸). 대신 보고서의 선택 기준을 추천으로 보여 줍니다.

| 입력 상황 | 감지 (기존 자산) | 추천 |
|---|---|---|
| lockfile 있음 | `detect_lang` 디렉터리에서 `package-lock.json`·`go.sum`·`Cargo.lock`·`poetry.lock`·`Gemfile.lock` glob | static (가장 저렴) |
| lockfile 없음 + 다언어 | `detect_lang`이 `mixed` | build |
| 호스트 빌드 환경 + 단일 언어 | `detect_lang` 단일 + `lightweight_capable()` | lightweight (CLI 한정) |
| 빌드 불가 / 코드 실행 금지 | 사용자 의도(감지 불가) | static |

노출 위치:

- CLI: `--detection` 미지정 시 배너에 "감지된 언어와 lockfile 기준 추천: static, 강제하려면 `--detection static`" 한 줄을 정보로 출력합니다. 동작은 그대로 `build`입니다.
- 웹 UI: `/capabilities` 응답에 가벼운 `sourceHint`(감지 언어 + lockfile 유무)를 끼워 프론트가 배지를 렌더합니다. current-dir 스캔에 한정하고, git-url·zip은 추출 전이라 생략합니다.

추천 산출은 `detect_lang`이 이미 매니페스트를 grep하므로, 같은 디렉터리에서 lockfile glob 한 줄을 더하는 수준입니다. 자동 전환을 하지 않으므로 잘못된 추천이 결과를 망치지 않습니다.

---

## 9. 트레이드오프와 영향 파일

| 결정 | 이득 | 비용·위험 |
|---|---|---|
| MODE 대신 직교 `DETECTION` | case 문·stage2·web 매핑 무변경, 9-MODE 보존 | SOURCE 외 무시 처리 필요(경고로 해결) |
| static 1차 백엔드 = syft | 추가 번들 0, 폴백 재사용, CDX 직접 출력 | 전이·Gradle 약함(정적 공통 한계) |
| OSV-SCALIBR 보류 | 벤치마크 근거로 결정, 성급한 의존 회피 | 통합 지점만 설계, 우월성 미검증 |
| lightweight = CLI 한정 | 호스트 의존 비용을 UI에서 못 켜게 차단 | UI 사용자는 lightweight 불가(의도된 제약) |
| `mark_sbom_degraded` reason 확장 | UI·리포트 계약 무변경, 백엔드 교체 안전 | reason 의미 분화 문서화 필요 |
| 추천은 힌트, 전환은 수동 | 재현성 보존, 잘못된 추천이 무해 | 사용자가 힌트를 무시할 수 있음(허용) |

영향 받는 핵심 파일:

- `scripts/scan-sbom.sh` — `--detection` 파싱, SOURCE stage1 3-way 분기, 추천 힌트 배너
- `docker/entrypoint.sh` — 웹 UI SOURCE 분기에 `$DETECTION` 적용, `generate_sbom_static()` 신설, `mark_sbom_degraded` reason 확장
- `docker/lib/build-prep.sh` — lightweight에서 호스트 직접 실행으로 재사용(계약 무변경, 호출 위치만 변경)
- `docker/web/server.py` — `scan_config`·env에 `detection`, `/capabilities`에 `lightweight`·`sourceHint`, `lightweight_capable()` 헬퍼
- `docker/web/frontend/src/lib/api.ts` — `ScanParams.detection`
- `docker/web/frontend/src/lib/useScanForm.ts` — 폼 상태·게이팅(`isSourceScan` 재사용)·submit 매핑
- `docker/web/frontend/src/components/NewScan.tsx`와 `ScanOptions` — 세그먼트 셀렉터, 추천 배지

---

## 10. 정직한 한계

- 정적 모드는 전이 버전이 근사합니다. 보고서의 `idna 2.10`(실제 설치) 대 `idna 2.9.0`(정적 해석) 사례가 이 한계의 회귀 기준입니다. 정확도가 중요한 입력에는 기본 모드를 써야 합니다.
- Gradle처럼 빌드로만 전이가 풀리는 생태계에서는 어떤 정적 엔진도 전이를 완전히 풀지 못합니다. 정적 모드의 공통 한계입니다.
- 경량 모드는 호스트 환경에 의존해 재현성과 격리가 약합니다. 예를 들어 macOS에서 툴체인 호환성 문제가 있을 수 있습니다. 신뢰할 수 없는 소스의 설치 스크립트(setup.py, postinstall)를 격리하지 못하므로, 신뢰 경계가 명확한 입력에만 권합니다.
- 정적 백엔드 최종 선택은 미정입니다. syft를 1차로 두되, lockfile 없는 Python과 Gradle 입력에서 OSV-SCALIBR와 전이 검출력을 벤치마크한 뒤 결정합니다.
