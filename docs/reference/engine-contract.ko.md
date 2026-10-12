---
description: BomLens 이미지를 스캔 엔진으로 쓰는 프로그램을 위해 모든 스캔이 남기는 결과 매니페스트(bomlens-result.json)입니다.
---

# 엔진 계약

BomLens 이미지를 스캔 엔진으로 쓰는 프로그램은 모든 스캔이 출력 폴더에 남기는 `bomlens-result.json`을 읽습니다. 이 파일에는 실행이 어떻게 끝났는지, 각 단계가 실행됐는지, 설정으로 꺼졌는지, 실행할 수 없었는지, 실패했는지, 그리고 폴더의 어떤 파일이 어떤 역할인지가 들어 있습니다. 그래서 호출하는 프로그램이 로그를 해석하거나 파일 이름을 추측하지 않아도 됩니다.

형식은 CI의 `tests/test-engine-contract.sh`가 [`schemas/engine-result-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-result-1.json)으로 검사합니다. 이 문서는 계약 버전 `1.2.0`을 설명합니다.

## 파일

`bomlens-result.json`은 이름이 고정되어 있으므로 스캔마다 출력 폴더를 따로 두세요. 이전 실행이 남긴 매니페스트는 실행을 시작하자마자 다른 확인보다 먼저 지우고, 새 매니페스트는 실행이 끝날 때 씁니다. 오류로 중간에 멈춘 경우에도 씁니다. 실행 뒤에 매니페스트가 없다면 엔진이 매니페스트를 쓰기 전에 강제 종료된 것입니다.

계약 때문에 스캔의 종료 코드가 바뀌지는 않습니다. SBOM을 만든 실행은 도중에 어떤 단계가 실패해도 0으로 끝나며, 그 실패는 매니페스트로 알립니다.

| 필드 | 뜻 |
|---|---|
| `contract` | `name`은 `bomlens-engine`, `version`은 계약 버전입니다(유의적 버전, BomLens 버전과 별개) |
| `engine` | `version`은 이미지에 들어 있는 BomLens 버전입니다. `image`와 `image_digest`는 호출자가 `BOMLENS_IMAGE_REF`와 `BOMLENS_IMAGE_DIGEST`를 넘기면 그 값을 그대로 적습니다. 이미지는 자기 참조를 알 수 없기 때문입니다 |
| `input` | `kind`(`source`, `image`, `sbom`, `binary`, `rootfs`, `firmware`, `ai-model`, `dataset`), 실행한 `MODE`, `target`(이미지 스캔의 이미지 참조, 경로는 적지 않음) |
| `run` | `status`, `reason`, `started_at`, `ended_at`(UTC), `exit_code` |
| `steps[]` | 단계마다 하나씩, 기록된 순서대로. 단계는 끝날 때 기록됨(아래 표) |
| `tools` | 도구 이름과 버전입니다. SBOM에 적힌 생성 도구, syft, 취약점 스캔이 돌았다면 Trivy가 들어갑니다 |
| `engines` | 이번 실행에서 결과를 낸 취약점 엔진(`trivy`, `grype`, `cve-bin-tool`, `yocto`) |
| `data_sources.trivy_db` | 취약점 스캔이 돌았을 때 Trivy 데이터베이스의 스키마 버전, `updated_at`, `downloaded_at` |
| `outputs[]` | 실행이 쓴 파일마다 `role`, `path`(출력 폴더 기준 상대 경로), `sha256`, `bytes` |

## 실행 상태

| `run.status` | 조건 |
|---|---|
| `succeeded` | 종료 코드 0이고, 기록된 모든 단계가 `ok`, `disabled`, 또는 읽을 것이 없어 건너뛴 `skipped`(`no_input`) 중 하나 |
| `succeeded_degraded` | 종료 코드 0이고, `failed`나 `degraded`인 단계, 또는 다른 사유로 `skipped`된 단계(요청했지만 실행할 수 없었던 단계: 도구 미설치, 입력 한도 초과, 이미지 사용 불가)가 하나 이상 있음. SBOM은 유효하며, 실패한 단계가 중요한지는 `steps[]`를 보고 판단합니다 |
| `failed` | 0이 아닌 종료 코드로 끝남(`reason`은 `exit_code`) |
| `cancelled` | 시그널로 중단됨(종료 코드 130 또는 143) |

취약점 스캔이 실패하면 `succeeded`가 되지 않습니다. Trivy는 데이터베이스를 읽지 못하면 빈 결과에 `ScanError`를 붙여 씁니다. 매니페스트는 이를 `scan-security`의 `failed`로 적고 Trivy의 메시지를 `detail`에 남기므로, "취약점 0건"과 "스캔이 돌지 않음"이 구분됩니다.

## 단계

스캔 모드에 해당하는 단계는 실행되지 않았더라도 모두 기록합니다. 모드에 아예 해당하지 않는 단계(AI 모델의 CPE 보강 등)는 기록하지 않습니다.

| `status` | 뜻 |
|---|---|
| `ok` | 실행되어 끝까지 완료됨 |
| `degraded` | 실행됐지만 필요한 것이 일부 없었음(예: 오프라인 지원 종료 데이터가 없음) |
| `failed` | 실행됐지만 실패함. SBOM은 그대로 씀. 대부분의 후처리 단계는 SBOM의 `bomlens:pipeline-step-failed` 속성에도 이름을 남기지만, 빠짐없는 기록은 매니페스트임 |
| `skipped` | 실행할 수 없었음. 도구가 이미지에 없거나 입력이 없음 |
| `disabled` | 설정으로 꺼짐 |

<!-- reasons:begin -->
| `reason` | 뜻 |
|---|---|
| `failed` | 단계가 오류를 냄 |
| `timeout` | 시간 제한을 넘김 |
| `not_installed` | 필요한 도구가 이 이미지에 없음 |
| `too_large` | 입력이 단계의 크기 제한을 넘음 |
| `fallback` | 더 단순한 방법으로 대신함(매니페스트만 읽는 대체 경로로 SBOM을 만들어 직접 의존성만 있음, 또는 `poetry.lock`이 없는 Poetry 프로젝트를 일부만 풀었음: 범위·테이블 의존성이 빠졌거나 고정 버전의 하위 의존성을 풀지 못함), 또는 필요한 이미지 없이 진행함(scancode 이미지를 내려받지 못한 `--deep-license`) |
| `unavailable` | 단계가 읽는 데이터를 쓸 수 없었음 |
| `budget_exhausted` | 작업량 제한에서 멈춤 |
| `no_input` | 단계가 읽을 것이 없었음(소스 트리 없음, 서명 키 없음) |
| `no_components` | 소스가 의존성을 선언했는데(매니페스트나 lock 파일에 의존성이 있음) SBOM에 컴포넌트가 없음. `detail`에 해당 매니페스트와, 있으면 실패한 해석 단계를 적음. `generate` 단계에 기록 |
<!-- reasons:end -->

`budget_exhausted`는 아직 어느 단계도 내지 않습니다. 이후 릴리스에서 기록할 작업량 제한 사유로 예약해 둔 값입니다.

각 단계에는 `stage`(이 컨테이너가 시작되기 전에 언어 이미지가 만든 SBOM이면 1, 나머지는 2), `started_at`, `ended_at`, 500자 이하의 선택 항목 `detail`이 있고, 일부 단계에는 `counts`가 있습니다(`generate`는 `components`를 기록하고, 생성기가 보았지만 이름을 알 수 없어 뺀 패키지가 있으면 `unresolved`를 기록하며 `detail`에 그 사실을 적음).

<!-- steps:begin -->
| 단계 | 하는 일 |
|---|---|
| `plan` | 실행 계획 작성(`MODE=PLAN`, 아래 참조) |
| `generate` | SBOM 생성(소스 스캔은 언어 이미지가 먼저 돌므로 1단계) |
| `os-licenses` | 이미지·루트 파일시스템 스캔에서 Debian 패키지의 라이선스를 Trivy로 채움. syft가 해시로 남기는 copyright 파일에서 Trivy가 라이선스 이름, common-licenses 참조, 라이선스 본문을 읽음. `counts`에 `replaced`, `hashes_dropped`를 기록하고, Trivy가 대상을 읽지 못하거나 어떤 Debian 패키지에도 라이선스를 주지 못하면 `degraded`(`unavailable`), Trivy가 없으면 `skipped`(`not_installed`), `BOMLENS_OS_LICENSES=false`이면 `disabled` |
| `vendored` | 소스에 복사해 넣은 오픈소스 식별(`--identify-vendored`) |
| `suggest-vendored` | C/C++ 프로젝트 스캔 결과가 거의 비었을 때 위 식별을 권함 |
| `cocoapods` | `Podfile.lock`의 CocoaPods 의존성 추가 |
| `stamp-metadata` | 루트 컴포넌트를 프로젝트 이름과 버전으로 지정. 실패하면 실행이 멈춤 |
| `docmeta` | 문서 작성자, 도구, 수명 주기 단계 기록 |
| `license-registry` | 패키지 레지스트리에서 빠진 라이선스를 조회하고, 하나뿐인 강한 카피레프트나 비상업 라이선스를 확인(`--license-registry`). `counts`에 `candidates`, `filled`, `superseded`, `confirmed`, `no_answer`, `not_found`, `non_standard`, `lookup_failed`, `budget_reached`를 기록 |
| `normalize` | 라이선스, PURL, 중복 정규화 |
| `enrich-cpe` | CPE 식별자 추가 |
| `enrich-os-context` | 운영체제 패키지의 배포판 기록 |
| `enrich-distro-supplier` | 배포판을 운영체제 패키지의 공급자로 기록 |
| `enrich-maven-cpe` | Maven 컴포넌트의 CPE 추가 |
| `enrich-github-cpe` | GitHub 저장소로 식별된 컴포넌트의 CPE 추가 |
| `enrich-interpreter-cpe` | 언어 런타임의 CPE 추가 |
| `enrich-eol` | 지원이 끝난 버전 표시(오프라인 데이터) |
| `enrich-malicious` | 알려진 악성 패키지 표시(오프라인 데이터) |
| `enrich-staleness` | 버전이 얼마나 뒤처졌는지 측정(선택, 온라인) |
| `declared-sources` | AI 선언에 적힌 데이터셋 출처 적용 |
| `declared-service` | AI 선언에 적힌 AI 서비스 적용 |
| `assess-ai-risk` | AI 모델 위험 판정 |
| `resolve-purl` | 각 PURL을 패키지 저장소에서 조회(`--resolve-purl`) |
| `describe-input` | 공급사 SBOM의 원래 형식과 도구 기록(`--analyze`) |
| `conformance` | 최소 요소 기준으로 SBOM 검사 |
| `deep-license` | scancode로 소스 파일의 라이선스 탐지(`--deep-license`) |
| `source-file-tree` | 스캔한 트리의 파일 목록 기록 |
| `source-snapshot` | 파일 보기 화면용으로 스캔한 파일 내용 보관 |
| `generate-notice` | 오픈소스 고지문 작성 |
| `scan-security` | Trivy로 취약점 매칭 |
| `generate-risk-report` | 위험 보고서 작성 |
| `model-security` | AI 모델 파일의 위험한 내용 검사 |
| `verify-weights` | 공개된 모델 가중치가 해시와 맞는지 확인 |
| `enrich-aibom` | 모델 허브 페이지에서 읽은 정보 추가 |
| `sign` | cosign으로 SBOM 서명(`--sign`) |
<!-- steps:end -->

## 출력 역할

| `role` | 파일 |
|---|---|
| `sbom.cyclonedx` | `_bom.json` |
| `sbom.spdx` | `_bom.spdx.json` |
| `sbom.spdx3` | `_bom.spdx3.json` |
| `vulnerabilities.trivy` | Trivy 자체 결과입니다. 다른 엔진이 결과를 더하지 않았으면 `_security.json`이고, 더했으면 병합 전에 따로 남긴 `_security_trivy.json`입니다 |
| `vulnerabilities.all` | `_security.json`. Trivy 결과에 다른 엔진의 결과를 병합한 파일 |
| `vulnerabilities.other` | 다른 엔진의 결과(`_security_grype.json`, `_security_cvebintool.json`, `_security_yocto.json`) |
| `license-scan.scancode` | `_scancode.json` |
| `vendored.cyclonedx` | `_vendored.cdx.json` |
| `conformance` | `_conformance.json` |
| `input-description` | `_input.json` |
| `events` | `bomlens-events.jsonl`(`BOMLENS_EVENTS=file`) |
| `other` | 실행이 쓴 그 밖의 파일(보고서, 보조 파일) |

## 패키지 식별자

`bom.json`의 운영체제 패키지 PURL은 Trivy와 purl-spec이 쓰는 형식을 따르므로, Trivy 스캔이나 공급사 SBOM의 같은 패키지와 연결됩니다.

- deb: epoch는 버전의 일부가 아니라 `epoch` 한정자입니다(`pkg:deb/debian/bsdutils@2.38.1-5?arch=amd64&distro=debian-12&epoch=1`).
- apk: `distro`는 릴리스 번호입니다(`distro=3.20.10`).
- deb, rpm, apk: `upstream` 한정자는 없습니다. 소스 패키지는 `aquasecurity:trivy:SrcName` 속성(과 `SrcVersion`, `SrcRelease`, `SrcEpoch`)에 있으며, Trivy는 이 값으로 배포판 권고를 매칭합니다.
- 한정자는 이름순으로 정렬합니다.

이 형식을 바꾸는 것은 메이저 버전 변경입니다(아래 참조).
## 실행 계획

소스 스캔은 컨테이너 두 개로 돕니다. 1단계는 cdxgen 언어 이미지에서 의존성을 해석하고, 2단계는 이 이미지를 `POSTPROCESS` 모드로 실행합니다. 컨테이너를 직접 실행하는 프로그램(Kubernetes Job, 보안 설정을 한 Docker 실행기 등)은 `MODE=PLAN`으로 무엇을 실행할지 BomLens에 묻습니다. 소스를 `/src`에 읽기 전용으로, 출력 폴더를 `/host-output`에 마운트하면 이미지가 그 폴더에 `bomlens-plan.json`을 쓰고 1단계가 마운트할 파일을 `bomlens-plan/`에 복사합니다. 스캔은 하지 않습니다. 형식은 [`schemas/engine-plan-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-plan-1.json)입니다.

```bash
docker run --rm -v "$PWD/src:/src:ro" -v "$PWD/out:/host-output" \
  -e MODE=PLAN -e PROJECT_NAME=app -e PROJECT_VERSION=1.0 -e HOST_OUTPUT_DIR=/host-output \
  -e BOMLENS_IMAGE_REF=ghcr.io/sktelecom/bomlens:<version> -e BOMLENS_IMAGE_DIGEST=sha256:... \
  ghcr.io/sktelecom/bomlens:<version>
```

| 필드 | 뜻 |
|---|---|
| `status` | `ok`, 또는 `reason`과 `detail`이 붙은 `unsupported`(`android-sdk-image`: Android SDK 이미지는 사용자가 빌드하며 발행하지 않음). `unsupported`이면 단계가 없음 |
| `input.detected_ecosystem` | 1단계 이미지를 고른 언어 감지 결과 |
| `output_file` | 1단계가 쓰고 2단계가 읽는 SBOM 파일 이름 |
| `stages[]` | 순서대로 `generate`(1단계)와 `postprocess`(2단계) |

각 단계에는 `image`와 `image_digest`(1단계는 항상 다이제스트로 고정, 2단계는 `BOMLENS_IMAGE_REF`와 `BOMLENS_IMAGE_DIGEST`를 그대로 적음), `user`, `entrypoint`, `args`, `workdir`, `env`(설정할 이름과 값), `env_passthrough`(값이 있으면 호출자의 환경에서 그대로 넘길 이름), `network`(패키지 레지스트리 접속이 필요한지), `mounts`가 있습니다. 마운트에는 `role`(`source`, `output`, 출력 폴더 안 경로를 `source`로 가진 `plan-file`, 선택 항목인 `guard-state`와 캐시, 선택 항목인 `trivy-db`), `target`, `mode`가 있습니다. 데이터베이스(`db/trivy.db`)가 든 Trivy 캐시 폴더를 `trivy-db`로 읽기 전용 마운트하고 `GENERATE_SECURITY=true`를 주면(2단계 보고서 옵션은 이미지 참조 문서대로 호출자가 정함), 2단계는 그 데이터베이스를 내려받거나 갱신하거나 쓰지 않고 그대로 읽습니다. 그래서 네트워크 없이, 읽기 전용 루트로 실행됩니다. `trivy-db` 마운트에 데이터베이스가 없으면 `scan-security`가 그 사유로 실패하고, 데이터베이스가 `BOMLENS_TRIVY_DB_MAX_AGE_DAYS`일(7일)보다 오래됐으면 `degraded`(`unavailable`)로 기록합니다. 나이는 `db/metadata.json`의 `UpdatedAt`(데이터베이스를 만든 시각)부터 셉니다. 데이터베이스를 갱신하는 주기에 맞는 값을 넘기세요. 소스는 1단계에서만 쓰기 가능합니다. 해석기가 그 안에 lock 파일을 쓰고, 1단계가 끝날 때 트리를 원래대로 되돌립니다. 1단계가 강제 종료되면(메모리 부족, 시간 초과) 되돌리지 못합니다. 호출자의 폴더 하나를 `guard-state`로 마운트하고 스캔마다 고유한 `BOMLENS_GUARD_ID`를 넘겨 두면, 강제 종료 뒤 같은 1단계를 `BOMLENS_GUARD_RESTORE_ONLY=1`로 다시 실행해 소스를 되돌릴 수 있습니다. 두 단계 모두에 `HOST_UID`와 `HOST_GID`를 넘기면 단계가 쓴 파일이 root가 아니라 호출자 사용자 소유가 됩니다. 2단계는 임의 사용자(`user`가 `null`이므로 호출자가 정함)와 읽기 전용 루트 파일시스템으로도 실행됩니다. 이때 쓰기 가능한 `$TMPDIR`(기본 `/tmp`, tmpfs)와 그 사용자가 쓸 수 있는 출력 폴더가 필요하며, 쓸 수 없는 홈 폴더는 그 아래에 마운트된 것이 없으면 `$TMPDIR` 안의 폴더로 바꿔 씁니다. `trivy-db` 마운트가 없으면 Trivy가 그곳에 수백 MB의 데이터베이스를 내려받는데, 메모리 기반 tmpfs에서는 이것이 메모리로 잡히므로 `trivy-db`를 마운트하세요. 1단계는 root로 실행합니다. 해석기가 패키지를 설치하고 소스에 파일을 쓰기 때문입니다. 쓰기 가능한 `/tmp`(`HOME`이 가리키는 곳)가 있으면 읽기 전용 루트 파일시스템으로도 실행됩니다(계정의 `~/.gradle`에 쓸 수 없으면 Gradle 파일은 그곳에 둡니다).

`MODE=PLAN`에 `CDXGEN_IMAGE_PREFIX`를 주면 1단계 이미지 이름을 레지스트리 미러 경로로 씁니다(예: `ghcr.io/cdxgen/` 대신 `registry.example/mirror/cdxgen/`). 다이제스트는 공개 이미지의 것을 그대로 쓰므로, 미러에는 다이제스트까지 같은 이미지가 있어야 합니다. pull-through 캐시이거나 모든 플랫폼을 복사한 미러(`skopeo copy --all`, `crane copy`)여야 합니다. `docker pull`, `docker tag`, `docker push`로 채운 미러는 한 플랫폼만 다른 다이제스트로 담으므로, 계획의 `image@image_digest`를 받으려 하면 "manifest unknown"으로 실패합니다.

`MODE=PLAN`은 계획을 썼으면 `ok`든 `unsupported`든 0으로 끝납니다. `unsupported` 계획은 결과 매니페스트에 `plan` 단계를 `skipped`로 기록하므로 실행은 `succeeded_degraded`입니다. 빈 소스(대개 컨테이너에 닿지 않은 마운트)는 0이 아닌 종료 코드로 거부합니다. 계획을 쓰기 전에 출력 폴더에서 이전 계획과 이전 실행의 1단계 산출물을 지웁니다. 2단계는 새 SBOM과 남은 SBOM을 구분할 수 없기 때문입니다. 1단계 이미지는 이 BomLens 릴리스가 시험한 cdxgen 태그로 고정되어 있어, `CDXGEN_TAG`를 바꾸면 언어 이미지는 `unsupported`(`no-pinned-digest`)가 됩니다.

2단계는 1단계 종료 코드와 관계없이 실행하고, 그 코드를 `BOMLENS_STAGE1_EXIT`로, 1단계 컨테이너가 메모리 부족으로 종료됐으면 `BOMLENS_STAGE1_OOM`에 `true`를, 출력 폴더에 저장한 1단계 로그의 파일 이름을 `BOMLENS_STAGE1_LOG`로 넘깁니다. 1단계가 실패했거나 SBOM을 남기지 않았으면 2단계가 syft로 소스를 대신 스캔하고(직접 의존성만), 사유를 `bomlens:sbom-tool-degraded`(`oom`, `disk-space`, `network`, `cdxgen-crash`, `cdxgen-unavailable`)에 적으며, 결과 매니페스트는 `generate`를 `degraded`(`fallback`)로 기록합니다. CLI와 같은 동작입니다. 1단계를 실행하지 않는 `unsupported` 계획에서는 SBOM 없이 `BOMLENS_STAGE1_EXIT=127`(또는 `BOMLENS_STAGE1_REASON=cdxgen-unavailable`)을 넘기면 사유가 `cdxgen-unavailable`이 됩니다.

## 제한된 네트워크

스캔이 네트워크로 접속하는 대상과 각 대상의 설정입니다. 실행 계획은 이 이름들을 `env_passthrough`에 담으므로, 호출자는 자기가 설정한 값을 넘기면 됩니다.

| 대상 | 단계 | 설정 |
|------|------|------|
| 프록시 | 1, 2 | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`(소문자 이름도) |
| 패키지 레지스트리(pip, npm, Maven 등) | 1 | 프록시를 거침. 각 패키지 관리자의 미러 설정도 평소대로 쓸 수 있음 |
| cdxgen의 라이선스 조회 | 1 | `FETCH_LICENSE=false`로 끔 |
| Trivy 취약점 데이터베이스 | 2 | `trivy-db` 마운트(네트워크가 전혀 필요 없음). 또는 미러를 `TRIVY_DB_REPOSITORY`, `TRIVY_JAVA_DB_REPOSITORY`로 지정. 컨테이너에 설정된 그 밖의 `TRIVY_*` 변수도 Trivy가 읽음(CLI는 가진 것을 모두 넘김) |
| EPSS와 CISA KEV | 2 | 계획에서는 꺼져 있음(2단계 `env`가 `SECURITY_ENRICH=false`). CLI와 이미지를 단독으로 쓰면 켜져 있음. 미러는 `EPSS_API`, `KEV_URL` |
| deps.dev(레지스트리 라이선스, 버전 경과 기간) | 2 | 요청할 때만 켜짐(`LICENSE_REGISTRY`, `STALENESS_ENRICH`). 미러는 `LICENSE_REGISTRY_API` |
| PURL 저장소 확인 | 2 | 요청할 때만 켜짐(`PURL_RESOLVE`) |
| SCANOSS(벤더링 코드 식별) | 2 | 요청할 때만 켜짐(`IDENTIFY_VENDORED`). 자체 설치 엔드포인트는 `SCANOSS_API_URL` |
| NVD(심층 CVE 일치 확인) | 2 | 요청할 때만 켜짐(`DEEP_CVE`와 함께 `SECURITY_NVD_VERIFY`) |

지원 종료(end-of-life) 데이터와 악성 패키지 데이터는 이미지에 들어 있어 네트워크가 필요 없습니다.

## 진행 이벤트

`BOMLENS_EVENTS=file`로 두면 실행이 진행되는 동안 출력 폴더의 `bomlens-events.jsonl`에 JSON 객체를 한 줄씩 쓰고, `BOMLENS_EVENTS=stderr`로 두면 표준 오류에 씁니다. 표준 오류에는 경고와 내장 도구의 메시지도 함께 나오므로 `{"v":1`로 시작하는 줄만 읽습니다. 실행 중 진행 상황을 보여 줄 때 씁니다. 최종 기록은 결과 매니페스트이며, 둘이 다르면 매니페스트를 따릅니다. 각 줄은 [`schemas/engine-event-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-event-1.json)을 따릅니다.

```json
{"v":1,"seq":12,"ts":"2026-10-11T03:04:05Z","type":"step.end","step":"normalize","stage":2,"status":"ok","reason":null}
```

| `type` | 시점 |
|---|---|
| `run.start` | 실행 시작 |
| `step.start` | 단계 시작(`step`, `stage`) |
| `step.end` | 단계 종료. `status`, `reason`, `detail`은 매니페스트와 같음. 설정으로 꺼졌거나 실행할 수 없었던 단계는 시작 없이 종료만 있음 |
| `run.end` | 실행 종료. 매니페스트의 `run.status`를 담음. 중단된 실행(`cancelled`)에는 시작만 있고 종료가 없는 단계가 남을 수 있음 |

`seq`는 이벤트마다 1씩 늘어나므로 빠지거나 순서가 바뀐 줄을 알 수 있습니다. 파일은 매니페스트의 `outputs`에 역할 `events`로 올라가며, 매니페스트는 이벤트가 모두 기록된 뒤에 나타납니다. 이전 실행이 폴더에 남긴 이벤트 파일은 실행을 시작할 때 지웁니다.

## 버전 관리

계약 버전은 BomLens 릴리스와 따로 올립니다.

- 메이저: 필드, 단계 이름, 출력 역할, 상태 값을 지우거나 이름을 바꾸거나 뜻을 바꿀 때, 같은 입력에서 다른 PURL이나 라이선스 식별자가 나오게 바뀔 때, 실패를 성공으로 보고하게 바뀔 때.
- 마이너: 선택 필드, 단계 이름, 사유, 출력 역할을 새로 추가할 때. 읽는 쪽은 모르는 값을 무시합니다.
- 패치: 위 필드에서 읽는 쪽이 알아챌 변화가 없을 때.

SBOM 안의 `bomlens:*` 속성과 사람이 읽는 보고서는 계약에 포함되지 않으며 어느 릴리스에서든 바뀔 수 있습니다.
