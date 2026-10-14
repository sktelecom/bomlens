---
description: BomLens 이미지를 스캔 엔진으로 쓰는 프로그램을 위해 모든 스캔이 남기는 결과 매니페스트(bomlens-result.json)입니다.
---

# 엔진 계약

BomLens 이미지를 스캔 엔진으로 쓰는 프로그램은 모든 스캔이 출력 폴더에 남기는 `bomlens-result.json`을 읽습니다. 이 파일에는 실행이 어떻게 끝났는지, 각 단계가 실행됐는지, 설정으로 꺼졌는지, 실행할 수 없었는지, 실패했는지, 그리고 폴더의 어떤 파일이 어떤 역할인지가 들어 있습니다. 그래서 호출하는 프로그램이 로그를 해석하거나 파일 이름을 추측하지 않아도 됩니다.

형식은 CI의 `tests/test-engine-contract.sh`가 [`schemas/engine-result-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-result-1.json)으로 검사합니다. 이 문서는 계약 버전 `1.3.0`을 설명합니다.

## 파일

`bomlens-result.json`은 이름이 고정되어 있으므로 스캔마다 출력 폴더를 따로 두세요. 이전 실행이 남긴 매니페스트는 실행을 시작하자마자 다른 확인보다 먼저 지우고, 새 매니페스트는 실행이 끝날 때 씁니다. 오류로 중간에 멈춘 경우에도 씁니다. 실행 뒤에 매니페스트가 없다면 엔진이 매니페스트를 쓰기 전에 강제 종료된 것입니다.

계약 때문에 스캔의 종료 코드가 바뀌지는 않습니다. SBOM을 만든 실행은 도중에 어떤 단계가 실패해도 0으로 끝나며, 그 실패는 매니페스트로 알립니다. 예외는 `--component-versions` 파일을 거부한 경우 하나입니다. 이때도 파일은 모두 쓰지만, 받은 버전을 적용하지 못했으므로 1로 끝납니다.

| 필드 | 뜻 |
|---|---|
| `contract` | `name`은 `bomlens-engine`, `version`은 계약 버전입니다(유의적 버전, BomLens 버전과 별개) |
| `engine` | `version`은 이미지에 들어 있는 BomLens 버전입니다. `image`와 `image_digest`는 호출자가 `BOMLENS_IMAGE_REF`와 `BOMLENS_IMAGE_DIGEST`를 넘기면 그 값을 그대로 적습니다. 이미지는 자기 참조를 알 수 없기 때문입니다 |
| `input` | `kind`(`source`, `image`, `sbom`, `binary`, `rootfs`, `firmware`, `ai-model`, `dataset`), 실행한 `MODE`, `target`(이미지 스캔의 이미지 참조, 경로는 적지 않음), 이미지 스캔이면 `image`(아래 참조) |
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
| `fallback` | 더 단순한 방법으로 대신함(매니페스트만 읽는 대체 경로로 SBOM을 만들어 직접 의존성만 있음, 또는 `poetry.lock`이 없는 Poetry 프로젝트를 일부만 풀었음: 범위·테이블 의존성이 빠졌거나 고정 버전의 하위 의존성을 풀지 못함), 또는 필요한 이미지 없이 진행함(scancode 이미지를 내려받지 못한 `--deep-license`, grype 이미지를 내려받지 못한 `--deep-cve`) |
| `unavailable` | 단계가 읽는 데이터를 쓸 수 없었음 |
| `budget_exhausted` | 작업량 제한에서 멈춤 |
| `no_input` | 단계가 읽을 것이 없었음(소스 트리 없음, 서명 키 없음) |
| `no_components` | 소스가 의존성을 선언했는데(매니페스트나 lock 파일에 의존성이 있음) SBOM에 컴포넌트가 없음. `detail`에 해당 매니페스트와, 있으면 실패한 해석 단계를 적음. `generate` 단계에 기록 |
<!-- reasons:end -->

`budget_exhausted`는 아직 어느 단계도 내지 않습니다. 이후 릴리스에서 기록할 작업량 제한 사유로 예약해 둔 값입니다.

각 단계에는 `stage`(이 컨테이너가 시작되기 전에 언어 이미지가 만든 SBOM이면 1, 나머지는 2), `started_at`, `ended_at`, 500자 이하의 선택 항목 `detail`이 있고, 일부 단계에는 `counts`가 있습니다(`generate`는 `components`를 기록하고, 생성기가 보았지만 이름을 알 수 없어 뺀 패키지가 있으면 `unresolved`를 기록하며 `detail`에 그 사실을 적음). `POSTPROCESS` 모드에서는 `generate`에 `input_fingerprint`, `reused`, `reuse_unsafe`가 있고, 실행 계획 뒤에는 `plan_mismatch`도 있습니다([입력 지문](#입력-지문) 참고).

<!-- steps:begin -->
| 단계 | 하는 일 |
|---|---|
| `plan` | 실행 계획 작성(`MODE=PLAN`, 아래 참조) |
| `generate` | SBOM 생성(소스 스캔은 언어 이미지가 먼저 돌므로 1단계). 생성 중에 실패한 단계(펌웨어 스캔의 syft 실행, 소스 스캔의 해석 단계)가 SBOM의 `bomlens:pipeline-step-failed`에만 남았으면 `degraded`(`failed`)로 기록하고 그 단계 이름을 `detail`에 적음. 그 단계에 펌웨어 syft 실행이 있고 amd64 이미지가 ARM 호스트에서 에뮬레이션으로 돌았으면 그 사실도 `detail`에 적고, arm64 호스트이면 대신 쓸 `linux/arm64` 이미지를 안내함. 후처리 단계(이 표에 따로 있는 단계)의 이름은 이전 실행이 남긴 SBOM에 있더라도 여기에 세지 않음 |
| `os-licenses` | 이미지·루트 파일시스템 스캔에서 Debian 패키지의 라이선스를 Trivy로 채움. syft가 해시로 남기는 copyright 파일에서 Trivy가 라이선스 이름, common-licenses 참조, 라이선스 본문을 읽음. `counts`에 `replaced`, `hashes_dropped`를 기록하고, Trivy가 대상을 읽지 못하거나 어떤 Debian 패키지에도 라이선스를 주지 못하면 `degraded`(`unavailable`), Trivy가 없으면 `skipped`(`not_installed`), `BOMLENS_OS_LICENSES=false`이면 `disabled` |
| `vendored` | 소스에 복사해 넣은 오픈소스 식별(`--identify-vendored`) |
| `suggest-vendored` | C/C++ 프로젝트 스캔 결과가 거의 비었을 때 위 식별을 권함 |
| `cocoapods` | `Podfile.lock`의 CocoaPods 의존성 추가 |
| `stamp-metadata` | 루트 컴포넌트를 프로젝트 이름과 버전으로 지정. 실패하면 실행이 멈춤 |
| `docmeta` | 문서 작성자, 도구, 수명 주기 단계 기록 |
| `license-registry` | 패키지 레지스트리에서 빠진 라이선스를 조회하고, 하나뿐인 강한 카피레프트나 비상업 라이선스를 확인(`--license-registry`). `counts`에 `candidates`, `filled`, `superseded`, `confirmed`, `no_answer`, `not_found`, `non_standard`, `lookup_failed`, `budget_reached`를 기록 |
| `component-versions` | 펌웨어, 루트 파일시스템, 바이너리 스캔에서 `--component-versions`로 받은 버전을 채우고, 아직 버전이 없는 컴포넌트를 `_component-versions.template.csv`로 씀. 파일을 거부하면 `failed`이고 이유를 `detail`에 적으며, 실행은 1로 끝남 |
| `normalize` | 라이선스, PURL, 중복 정규화 |
| `enrich-cpe` | CPE 식별자 추가 |
| `upstream-purl` | 펌웨어, 루트 파일시스템, 바이너리 스캔에서 변환표로 upstream 소스 저장소 purl을 붙임. `ENRICH_UPSTREAM_PURL=false`이면 `disabled` |
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
| `match-cpe` | `--security`를 켠 펌웨어, 루트 파일 시스템, 바이너리 스캔에서 패키지 PURL이 없는 컴포넌트의 CPE를 이미지에 들어 있는 NVD CPE 인덱스와 대조. `counts`에 `offered`, `components`, `cves`를 담고, 인덱스가 없는 이미지에서는 `skipped`(`not_installed`), `--security`가 꺼져 있거나 `CVE_BIN_TOOL_MODE=components-only`이면 `disabled` |
| `scan-security` | Trivy로 취약점 매칭 |
| `deep-cve` | `--security`를 켰을 때 CPE가 있는 컴포넌트와 `bomlens:cpeAlternates`의 추가 CPE를 grype로 NVD와 대조(`--deep-cve`, deep-cve 이미지). grype가 없는 이미지에서 요청하면 `skipped`(`not_installed`), CLI가 deep-cve 이미지 없이 실행했으면 `skipped`(`fallback`, 이미지를 내려받지 못했거나 스캐너 이미지가 로컬 빌드, 1.13.2보다 낮은 버전, BomLens 이름이 아닌 이미지여서이며 `detail`에 이유를 적음. 그대로 둔 이미지에 grype가 있으면(`SBOM_DEEP_CVE=true`로 빌드) 대조를 실행하고 실제 결과를 기록), 요청하지 않았거나 `--security`가 꺼져 있거나 펌웨어 또는 AI 모델 스캔이면 `disabled` |
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
| `vulnerabilities.trivy` | Trivy 자체 결과입니다. 아무것도 고치지 않았으면 `_security.json`이고, 다른 엔진이 결과를 더했거나 권고 번호로 보고된 항목을 옮겼으면 따로 남긴 `_security_trivy.json`입니다([보안 보고서](../guides/reports.ko.md) 참고) |
| `vulnerabilities.all` | `_security.json`. Trivy 결과에 다른 엔진의 결과를 병합하고, 권고 번호로 보고된 항목을 관련 CVE로 바꾸거나 최상위 `Advisories` 목록으로 옮긴 파일 |
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

## 이미지 스캔

`IMAGE` 모드에서는 syft가 먼저 이미지를 읽고, Debian 패키지의 라이선스를 읽는 Trivy(`os-licenses`)와 파일 보기가 같은 이미지를 한 번 더 읽습니다. 이 두 번째 읽기는 syft가 읽은 다이제스트로 이미지를 지정하므로(`<저장소>@sha256:...`), 그사이에 태그가 다른 이미지를 가리키게 되어도 같은 이미지를 읽습니다. `input.image`에 그 내용을 적습니다.

```json
"image": {
  "reference": "alpine:3.20",
  "source": "registry",
  "digest": "sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d",
  "platform": "linux/arm64/v8",
  "index_digest": "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
}
```

| 필드 | 뜻 |
|---|---|
| `reference` | 입력으로 받은 이미지 참조(`TARGET_IMAGE`) |
| `source` | syft가 이미지를 읽은 곳입니다. `registry`(`registry:` 스킴, 또는 Docker 소켓이 없을 때의 일반 이름), `daemon`(`docker:`와 `podman:`), `archive`(`docker-archive:`, `oci-archive:`, `oci-dir:`), `other`(`containerd:`)이며, syft가 이미지를 읽기 전에 실행이 멈췄다면 `null`입니다. 소켓이 있으면 syft는 일반 이름을 데몬에서 읽고, 데몬에서 이미지를 받지 못하면 레지스트리에서 읽습니다. syft의 기록에는 어느 쪽인지 적혀 있지 않으므로 기록 내용으로 판단합니다. Docker Hub 저장소 다이제스트가 전체 이름(`index.docker.io/...`)으로 적혀 있으면 `registry`, 태그가 있으면 `daemon`, 둘 다 아니면 `unknown`입니다 |
| `digest` | `registry`이면 읽은 이미지의 매니페스트 다이제스트(플랫폼 하나), `daemon`과 `unknown`이면 그 저장소에 대해 기록된 저장소 다이제스트입니다. 다중 플랫폼 이미지라면 인덱스의 다이제스트이며, 데몬과 레지스트리에서 같은 내용을 가리킵니다. 아카이브는 파일을 그대로 읽으므로 `null`이고, 다이제스트를 알아낼 수 없을 때도 `null`입니다. 저장소 다이제스트가 없는 경우(로컬에서 빌드하고 푸시하지 않은 이미지), 일반 이미지 이름이 아닌 경우, syft의 소스 기록을 쓰지 못한 경우가 여기에 해당합니다. 이때 두 번째 읽기는 받은 참조를 그대로 쓰고, 로그에 그 사실을 남깁니다 |
| `platform` | 읽은 이미지의 `os/architecture[/variant]`, 알 수 없으면 `null`입니다. variant는 syft의 `architectureVariant`를 쓰고, 없으면 이미지 설정의 `variant`를 씁니다(Docker는 arm64 이미지에 `v8`을 적습니다) |
| `index_digest` | `registry`일 때만, 참조가 가리킨 이미지 인덱스(매니페스트 목록)의 다이제스트가 `digest`와 다르면 적습니다 |

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
| `input_fingerprint` | 1단계가 읽는 입력을 sha256 값으로 나타낸 것([입력 지문](#입력-지문) 참고). `generate` 단계의 값과 같고, 단계가 없을 때도 여기에 있음 |
| `stages[]` | 순서대로 `generate`(1단계)와 `postprocess`(2단계) |

각 단계에는 `image`와 `image_digest`(1단계는 항상 다이제스트로 고정, 2단계는 `BOMLENS_IMAGE_REF`와 `BOMLENS_IMAGE_DIGEST`를 그대로 적음), `user`, `entrypoint`, `args`, `workdir`, `env`(설정할 이름과 값), `env_passthrough`(값이 있으면 호출자의 환경에서 그대로 넘길 이름), `network`(패키지 레지스트리 접속이 필요한지), `mounts`가 있습니다. 마운트에는 `role`(`source`, `output`, 출력 폴더 안 경로를 `source`로 가진 `plan-file`, 선택 항목인 `guard-state`와 캐시, 선택 항목인 `trivy-db`), `target`, `mode`가 있습니다. 데이터베이스(`db/trivy.db`)가 든 Trivy 캐시 폴더를 `trivy-db`로 읽기 전용 마운트하고 `GENERATE_SECURITY=true`를 주면(2단계 보고서 옵션은 이미지 참조 문서대로 호출자가 정함), 2단계는 그 데이터베이스를 내려받거나 갱신하거나 쓰지 않고 그대로 읽습니다. 그래서 네트워크 없이, 읽기 전용 루트로 실행됩니다. `trivy-db` 마운트에 데이터베이스가 없으면 `scan-security`가 그 사유로 실패하고, 데이터베이스가 `BOMLENS_TRIVY_DB_MAX_AGE_DAYS`일(7일)보다 오래됐으면 `degraded`(`unavailable`)로 기록합니다. 나이는 `db/metadata.json`의 `UpdatedAt`(데이터베이스를 만든 시각)부터 셉니다. 데이터베이스를 갱신하는 주기에 맞는 값을 넘기세요. 소스는 1단계에서만 쓰기 가능합니다. 해석기가 그 안에 lock 파일을 쓰고, 1단계가 끝날 때 트리를 원래대로 되돌립니다. 1단계가 강제 종료되면(메모리 부족, 시간 초과) 되돌리지 못합니다. 호출자의 폴더 하나를 `guard-state`로 마운트하고 스캔마다 고유한 `BOMLENS_GUARD_ID`를 넘겨 두면, 강제 종료 뒤 같은 1단계를 `BOMLENS_GUARD_RESTORE_ONLY=1`로 다시 실행해 소스를 되돌릴 수 있습니다. 두 단계 모두에 `HOST_UID`와 `HOST_GID`를 넘기면 단계가 쓴 파일이 root가 아니라 호출자 사용자 소유가 됩니다. 2단계는 임의 사용자(`user`가 `null`이므로 호출자가 정함)와 읽기 전용 루트 파일시스템으로도 실행됩니다. 이때 쓰기 가능한 `$TMPDIR`(기본 `/tmp`, tmpfs)와 그 사용자가 쓸 수 있는 출력 폴더가 필요하며, 쓸 수 없는 홈 폴더는 그 아래에 마운트된 것이 없으면 `$TMPDIR` 안의 폴더로 바꿔 씁니다. `trivy-db` 마운트가 없으면 Trivy가 그곳에 수백 MB의 데이터베이스를 내려받는데, 메모리 기반 tmpfs에서는 이것이 메모리로 잡히므로 `trivy-db`를 마운트하세요. 1단계는 root로 실행합니다. 해석기가 패키지를 설치하고 소스에 파일을 쓰기 때문입니다. 쓰기 가능한 `/tmp`(`HOME`이 가리키는 곳)가 있으면 읽기 전용 루트 파일시스템으로도 실행됩니다(계정의 `~/.gradle`에 쓸 수 없으면 Gradle 파일은 그곳에 둡니다).

2단계 이미지는 2단계에 어떤 옵션을 주든 `BOMLENS_IMAGE_REF`에 적은 이미지입니다. `DEEP_CVE=true`에는 grype가, `DEEP_LICENSE=true`에는 scancode가 필요하고 각각 `bomlens-deep-cve`와 `bomlens-deep-license` 이미지에만 들어 있으므로, 2단계를 그 이미지로 실행하고 `BOMLENS_IMAGE_REF`에도 그 이미지를 적습니다. 두 도구를 모두 가진 이미지는 없습니다. 둘 다 쓰려면 먼저 출력 폴더에 남은 이전 `<prefix>_scancode.json`을 지우고, deep-license 이미지에서 `/usr/local/lib/sbom/deep-license.sh /src /host-output/<prefix>_scancode.json`을 실행합니다(엔트리포인트 `bash`, 마운트는 같음, 파일 소유자를 내 사용자로 하려면 `HOST_UID`와 `HOST_GID`도 넘김). 이어서 2단계를 deep-cve 이미지로 `DEEP_LICENSE=true`와 함께 실행하면서 그 스크립트의 종료 코드를 `BOMLENS_DEEP_LICENSE_RC`로 넘기고, 필요하면 시작과 종료 시각을 `BOMLENS_DEEP_LICENSE_STARTED`와 `BOMLENS_DEEP_LICENSE_ENDED`(`YYYY-MM-DDTHH:MM:SSZ`)로 넘깁니다. 출력 폴더가 소스 트리 안에 있으면 `DEEP_LICENSE_EXCLUDE`에 그 폴더 이름을 적어(공백으로 구분한 폴더 이름, 어느 깊이에서든 제외) 라이선스 스캔이 결과 파일을 읽지 않게 합니다. 스크립트는 끝까지 마치지 못하면(종료 코드 0과 6 외) 출력 파일을 지우고, 2단계는 종료 코드가 0이나 6일 때만 그 파일을 남기고 그 밖에는 지운 뒤 종료 코드로 `deep-license` 단계를 기록합니다. CLI는 두 옵션을 함께 켜면 이렇게 실행합니다. 도구가 없는 이미지로 실행하면 결과 매니페스트가 그 단계(`deep-cve` 또는 `deep-license`)를 `skipped`(`not_installed`)로, 실행을 `succeeded_degraded`로 기록합니다. `DEEP_CVE=true`와 함께 `SECURITY_NVD_VERIFY=true`를 주면 2단계가 `NVD_API_KEY`를 읽으며, 계획은 이 이름을 값 없이 `env_passthrough`에 적습니다.

`MODE=PLAN`에 `CDXGEN_IMAGE_PREFIX`를 주면 1단계 이미지 이름을 레지스트리 미러 경로로 씁니다(예: `ghcr.io/cdxgen/` 대신 `registry.example/mirror/cdxgen/`). 다이제스트는 공개 이미지의 것을 그대로 쓰므로, 미러에는 다이제스트까지 같은 이미지가 있어야 합니다. pull-through 캐시이거나 모든 플랫폼을 복사한 미러(`skopeo copy --all`, `crane copy`)여야 합니다. `docker pull`, `docker tag`, `docker push`로 채운 미러는 한 플랫폼만 다른 다이제스트로 담으므로, 계획의 `image@image_digest`를 받으려 하면 "manifest unknown"으로 실패합니다.

CycloneDX 1.7 SBOM을 계획하려면 `MODE=PLAN`에 `CYCLONEDX_SPEC_VERSION`(`1.6`이 기본값, 또는 `1.7`. CLI의 `--spec-version`)을 줍니다. 계획은 이 값을 1단계에는 `build-prep.sh`의 마지막 인자로, 2단계에는 `env`의 `CYCLONEDX_SPEC_VERSION`으로 넘깁니다. 그래서 2단계의 대체 스캔(syft)도 같은 버전으로 쓰고, 2단계는 1.4, 1.5, 1.6으로 쓰인 SBOM을 1.7로 올립니다(1.3 이하는 버전을 그대로 둡니다). 이 값은 입력 지문(`CDX_SPEC_VERSION`)에도 들어갑니다. 다른 값을 주면 `MODE=PLAN`이 0이 아닌 코드로 멈춥니다.

`MODE=PLAN`은 계획을 썼으면 `ok`든 `unsupported`든 0으로 끝납니다. `unsupported` 계획은 결과 매니페스트에 `plan` 단계를 `skipped`로 기록하므로 실행은 `succeeded_degraded`입니다. 빈 소스(대개 컨테이너에 닿지 않은 마운트)는 0이 아닌 종료 코드로 거부합니다. 계획을 쓰기 전에 출력 폴더에서 이전 계획과 이전 실행의 1단계 산출물을 지웁니다. 2단계는 새 SBOM과 남은 SBOM을 구분할 수 없기 때문입니다. 1단계 이미지는 이 BomLens 릴리스가 시험한 cdxgen 태그로 고정되어 있어, `CDXGEN_TAG`를 바꾸면 언어 이미지는 `unsupported`(`no-pinned-digest`)가 됩니다.

2단계는 1단계 종료 코드와 관계없이 실행하고, 그 코드를 `BOMLENS_STAGE1_EXIT`로, 1단계 컨테이너가 메모리 부족으로 종료됐으면 `BOMLENS_STAGE1_OOM`에 `true`를, 출력 폴더에 저장한 1단계 로그의 파일 이름을 `BOMLENS_STAGE1_LOG`로 넘깁니다. 1단계가 실패했거나 SBOM을 남기지 않았으면 2단계가 syft로 소스를 대신 스캔하고(직접 의존성만), 사유를 `bomlens:sbom-tool-degraded`(`oom`, `disk-space`, `network`, `cdxgen-crash`, `cdxgen-unavailable`)에 적으며, 결과 매니페스트는 `generate`를 `degraded`(`fallback`)로 기록합니다. CLI와 같은 동작입니다. 1단계를 실행하지 않는 `unsupported` 계획에서는 SBOM 없이 `BOMLENS_STAGE1_EXIT=127`(또는 `BOMLENS_STAGE1_REASON=cdxgen-unavailable`)을 넘기면 사유가 `cdxgen-unavailable`이 됩니다.

## 입력 지문

계획의 `generate` 단계에는 `input_fingerprint`가 있습니다. 소스 트리 전체와 1단계를 실행하는 데 쓰이는 파일과 설정에 대한 sha256입니다. 이 값이 1단계가 종료 코드 0으로 끝난 이전 스캔의 `sha256`과 같으면 1단계를 건너뛰고, 그 스캔의 1단계 산출물을 2단계에 대신 줄 수 있습니다. 출력 폴더에 SBOM(`output_file`, 있었다면 `_conda.cdx.json`도)을 두고, 그 종료 코드를 `BOMLENS_STAGE1_EXIT`로, 로그를 `BOMLENS_STAGE1_LOG`로 넘기며, `BOMLENS_STAGE1_REUSED=1`을 함께 넘깁니다. 종료 코드 0으로 끝난 1단계만 다시 쓰고, 실패한 1단계는 다시 실행합니다. 2단계는 항상 실행합니다. 소스 파일의 라이선스 검사, 레지스트리 조회, 버전 노후도, 취약점은 1단계만이 아니라 파일 내용과 실행 시점에 따라 달라지기 때문입니다. 그래서 `--deep-license`를 켠 채로도 다시 쓸 수 있습니다.

지문은 판단이 어려우면 다시 쓸 수 없다고 봅니다. 1단계가 같은 결과를 낼지 검사로 확인할 수 없으면 `reusable`은 `false`입니다.

```json
{"algorithm": "bomlens-input-1", "sha256": "9e61...", "reusable": true, "reasons": [],
 "components": [{"kind": "file", "name": ".", "sha256": "a729...", "count": 1840}, ...]}
```

| 필드 | 뜻 |
|---|---|
| `algorithm` | `bomlens-input-1`. `sha256`과 함께 비교함. 알고리즘이 다른 두 값은 같은 값으로 보지 않음 |
| `sha256` | 지문. `reusable`이 `false`이면 `null` |
| `reusable` | 이 입력에 대한 1단계 결과를 다시 쓸 수 있는지 |
| `reasons` | `reusable`이 `false`일 때 그 사유(아래). 사유마다 한 항목 |
| `components` | 입력 하나하나를 `kind`(`file`, `engine`, `image`, `setting`), `name`, `sha256`으로 나타냄. 값은 항상 sha256으로만 적음 |

구성 요소는 종류와 이름 순서로 정렬합니다.

- `file`: 소스 트리 전체를 `.`이라는 이름의 구성 요소 하나로 적습니다. 1단계는 종류를 지정하지 않고 트리 전체에서 cdxgen을 실행하며, cdxgen은 여러 종류의 파일(자체 설정 파일 `.cdxgenrc`, 압축 파일, 설치된 패키지의 메타데이터, 여러 도구의 빌드 파일)을 읽습니다. 그래서 이름이 `.git`인 폴더나 파일(워크트리의 `.git` 파일에는 절대 경로가 들어 있음)을 뺀 모든 파일을 넣습니다. 그 밖에는 건너뛰는 폴더가 없어서 `node_modules`, `vendor`, 가상 환경, 숨김 폴더, 배포하지 않는 폴더도 해시에 들어갑니다. `sha256`은 파일마다 한 줄씩 `<경로><탭><모드><탭><내용의 sha256>`을 적고, 소스 기준 상대 경로를 바이트 순서(`LC_ALL=C`)로 정렬해 계산합니다. `<모드>`는 실행할 수 있는 파일이면 `755`, 아니면 `644`이며(build-prep은 실행할 수 있을 때만 `./gradlew`를 씀), 링크이면 앞에 `l`이 붙어 링크와 사본이 구분됩니다. `count`는 파일 수입니다. lock 파일뿐 아니라 README나 소스 파일이 바뀌어도 값이 바뀌고, `.git`이 바뀌면 바뀌지 않습니다. 링크는 소스 안의 일반 파일을 가리킬 때만 따라갑니다. 해시를 낼 수 없는 경로(읽을 수 없는 파일이나 폴더, 끊어졌거나 소스 밖을 가리키는 링크, 폴더 링크, FIFO나 소켓이나 장치 파일, 탭이나 줄바꿈이 든 이름)는 `sha256`이 `null`인 `file` 구성 요소로 따로 적고, 그러면 트리의 `sha256`도 `null`이 됩니다. 그래서 설치된 pnpm `node_modules`(폴더 링크로 이루어짐)나 가상 환경(링크가 소스 밖을 가리킴)이 있는 트리는 다시 쓸 수 없습니다. 파일과 폴더를 합쳐 `BOMLENS_FINGERPRINT_MAX_FILES`개(200000) 넘게 보거나 `BOMLENS_FINGERPRINT_TIMEOUT`초(300)가 지나면 순회를 멈추며, 이때 구성 요소에 `truncated: true`가 붙고 `sha256`은 `null`입니다. 아래 검사까지 포함한 계산 전체는 그 한도에서 30초가 더 지나면 멈추며, 이때 지문은 구성 요소 없이 `unhashable-input`인, 다시 쓸 수 없는 값이 됩니다. 검사는 파일을 4 MiB까지만 읽습니다. 그보다 큰 매니페스트, lock 파일, Go 소스는 판단할 수 없으므로 값이 `unhashable-input`이 됩니다(해시는 끝까지 냄). CLI 소스 스캔의 결과 매니페스트에서는 그 실행의 출력 폴더가 소스 안에 있으면(기본값) 그 실행의 결과가 들어 있으므로 순회에서 뺍니다. 다만 이때 값은 다시 쓸 수 없습니다(`unhashable-input`이며, 그 폴더를 `sha256`이 `null`인 구성 요소로 적음). 1단계가 그 폴더를 비우기 전에 실행되어 이전 실행의 파일을 읽었을 수 있기 때문입니다. CLI 경로에서 다시 쓸 수 있는 값을 얻으려면 출력 폴더를 소스 밖에 두세요(`--output-dir`).
- `engine`: 1단계가 BomLens에서 가져와 실행하는 파일의 내용을 sha256으로 적습니다. `build-prep.sh`, `identify-conda.py`, 그리고 1단계의 인자와 환경을 정하는 파일로, 계획에서는 `make-plan.sh`입니다. CLI 소스 스캔의 결과 매니페스트에서는 그 파일이 `scan-sbom.sh`이고, `build-prep.sh`와 `identify-conda.py`는 CLI가 마운트한 CLI 쪽 사본입니다. 그래서 CLI의 값은 다른 CLI의 값과만 비교할 수 있습니다.
- `image`: 1단계 이미지의 다이제스트인 `stage1`과, `BOMLENS_IMAGE_DIGEST`인 `bomlens`입니다(넘기지 않으면 `null`이며, 이 다이제스트가 대신하던 파일은 이미 `engine` 구성 요소에 있음). CLI 스캔은 1단계 이미지를 받아 온 다이제스트를 기록하며, 로컬에서 빌드한 이미지에는 다이제스트가 없습니다.
- `setting`: `detected_ecosystem`, `PROJECT_NAME`, `PROJECT_VERSION`, `FETCH_LICENSE`, `HOST_GOTOOLCHAIN`, `CDX_SPEC_VERSION`(1단계의 `--spec-version`), 그리고 build-prep 옵션 `BOMLENS_KEEP_BUILD_OUTPUT`, `BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_ANDROID_FULL_GRAPH`, `BOMLENS_NODE_FULL_GRAPH`, `BOMLENS_PHP_FULL_GRAPH`, `BOMLENS_INCLUDE_NON_SHIPPED`, `BOMLENS_INCLUDE_DEV_DEPENDENCIES`, `BOMLENS_NO_COPYRIGHT`, `BOMLENS_NO_CARGO_LICENSE`, `BOMLENS_PREP_TIMEOUT`의 값을 sha256으로 적습니다(설정하지 않았으면 빈 값의 sha256). `FETCH_LICENSE`와 `HOST_GOTOOLCHAIN`은 1단계 `env`의 값입니다. build-prep 옵션은 `MODE=PLAN`이 자기 환경에서 읽으므로, 두 단계에 주는 값과 같은 값을 `MODE=PLAN`에도 주세요. 계획의 2단계 `env_passthrough`에도 이 이름들이 있습니다.

구성 요소에 넣지 않는 것은 절대 경로, 실행 시각, 스캔 ID, 프록시 설정(`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`와 소문자 이름), `GOPROXY`, `GOSUMDB`, `TRIVY_*`, `CDXGEN_IMAGE_PREFIX`(미러도 같은 다이제스트를 제공함), `HOST_UID`와 `HOST_GID`, 그리고 2단계만 읽는 `SRC_TREE_EXCLUDE`입니다. 1단계의 고정된 인자와 환경은 그것을 정하는 `engine` 파일로 반영됩니다.

다음 두 가지는 호출자가 책임집니다.

- 소스 말고 1단계에 마운트하는 것은 반영되지 않습니다. `cache-maven`, `cache-gradle` 마운트와 그 안의 Maven `settings.xml`, Gradle `init.d` 스크립트나 `gradle.properties`가 해당합니다. 이를 바꾸면 같은 지문이 다른 결과를 가리킬 수 있습니다.
- `FETCH_LICENSE=true`이면 cdxgen이 라이선스를 온라인으로 조회합니다. 지문은 이 설정을 구성 요소로 넣되, 결과는 다시 쓸 수 있다고 봅니다. 게시된 버전의 라이선스 메타데이터는 거의 바뀌지 않는다는 전제입니다.

아래 검사는 트리가 같아도 해석기가 레지스트리에 다시 물어 1단계 결과가 달라질 수 있는지 봅니다. Go, Maven, Gradle은 루트에서 트리 전체를 해석하므로 어디에 있든 검사합니다(Go는 go 도구처럼 `testdata`, `vendor`, `.`이나 `_`로 시작하는 이름을 뺌). 다른 언어는 소스 스캔이 건너뛰는 폴더(`node_modules`, `vendor`, `.venv`, `site-packages`, 그리고 `BOMLENS_INCLUDE_NON_SHIPPED=1`이 아니면 배포하지 않는 폴더)를 해시에는 넣되 검사하지 않습니다.

재사용 여부는 계획만이 아니라 결과 매니페스트로 판단하세요. 결과 매니페스트의 `input_fingerprint`가 `reusable`인 1단계만 재사용할 결과로 보관합니다. 1단계가 종료 코드 0으로 끝났어도 결과가 모자라면 2단계가 그곳에 `stage1-degraded`를 넣습니다.

<!-- fingerprint-reasons:begin -->
| `reasons` | 뜻 |
|---|---|
| `no-lockfile` | 의존성을 선언한 매니페스트의 폴더에 lock 파일이 없음. Node.js `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`, Python `poetry.lock`, `uv.lock`, `Pipfile.lock`, Rust `Cargo.lock`, Go `go.sum`(`require`가 있는 `go.mod`마다 자기 것이 있어야 함), Ruby `Gemfile.lock`, PHP `composer.lock`, Swift `Package.resolved`, `Podfile.lock`. 위 폴더의 lock 파일은 선언된 워크스페이스 구성원만 덮음. npm, yarn, pnpm, bun의 `workspaces`(또는 `pnpm-workspace.yaml`)와 Cargo의 `[workspace] members`가 해당함. Gradle은 빌드 스크립트마다(루트가 `subprojects {}`나 `allprojects {}`로 의존성을 선언하면 `settings.gradle`이 포함하는 프로젝트마다) `group:artifact:version=` 항목이 하나 이상 있는 자기 `gradle.lockfile`이 있어야 함(`empty=` 줄만 있으면 아무것도 고정하지 않음). 그 파일은 의존성 잠금(`lockAllConfigurations()`이나 `activateDependencyLocking()`, 주석 제외)을 켰을 때만 인정하며, 잠금은 프로젝트 자기 빌드 파일에 있거나, 하위 프로젝트라면 루트의 `subprojects {}`나 `allprojects {}` 블록 안에 있어야 함. 루트 빌드 파일 맨 위의 잠금은 루트 프로젝트만 고정함. .NET은 프로젝트마다 자기 `packages.lock.json`이나 `obj/project.assets.json`, 또는 위 폴더의 `paket.lock`이 있어야 하며, .NET 프로젝트가 있는데 이 중 어느 것도 트리에 없으면 `no-lockfile`임. `requirements*.txt`(또는 `requirements/` 아래의 `.txt`)는 pip의 해시 확인 모드일 때만 lock으로 봄. 모든 요구 사항이 `--hash`가 붙은 `name==version`이고, 포함(`-r`, `-c`), 편집 가능 설치, URL, 경로, `${변수}` 요구 사항이 없어야 함. 1단계가 pip로 레지스트리에서 설치하므로 다른 lock 파일은 이를 덮지 않음 |
| `unpinned-versions` | Maven은 아래의 `registry-resolution`에 더해, 트리 안 pom의 요소에 버전 범위, `-SNAPSHOT`, `LATEST`, `RELEASE`가 그대로 적힌 경우임. 속성은 펼치지 않으므로 속성으로 정한 버전은 여기서 판단하지 않으며, 그 트리는 어느 쪽이든 다시 쓸 수 없음. .NET은 프로젝트, `.props`, `.targets` 파일의 유동 버전이나 범위 버전(`*`, `[1.0,2.0)`, MSBuild `$(속성)`)이 해당함. 의존성 자체의 pom에 있는 버전은 보이지 않으며 검사하지 않음 |
| `registry-resolution` | 트리가 그대로여도 1단계가 레지스트리에서 다시 해석함. Maven은 `pom.xml`이 하나라도 있는 경우로, 전이 의존성을 고정하는 lock 파일이 없고 의존성 자체의 pom에 있는 범위는 볼 수 없기 때문임. Node.js는 루트 `package.json`에 `package-lock.json`이 없고(yarn, pnpm, bun 프로젝트, 또는 `npm-shrinkwrap.json`만 있는 프로젝트) 워크스페이스 루트도 아닌 경우로, 운영 범위 필터가 npm으로 다시 해석하기 때문임(`BOMLENS_NODE_FULL_GRAPH=1`이면 해당 없음). npm lock 파일이 `package.json`과 맞지 않는 경우(lock 파일에 기록된 그 패키지의 의존성 명세가 다르거나, lockfile 버전 1이면 의존성 이름이 빠짐)도 해당함. Ruby는 `Gemfile.lock`의 `DEPENDENCIES`에 `Gemfile`이 적은 gem이 없는 경우, Swift는 `Package.resolved`가 `Package.swift`가 적은 원격 패키지를 모두 고정하지 않은 경우임. Go는 `.go` 파일이 `go.mod`에 없는 모듈을 import하는 경우로, `go mod tidy`가 그 모듈의 최신 버전을 추가하기 때문임. 요구 모듈 경로가 import 경로의 앞부분이면 덮는 것으로 봄(앞부분 뒤에 `/vN` 주 버전이 오면 덮지 않음). 앞부분이 요구 모듈과 같지만 실제로는 요구하지 않은 별도 모듈에 있는 import는 찾지 못함 |
| `unsupported-ecosystem` | 1단계가 재현 가능하게 해석하지 않는 언어. `unknown`, 트리 어딘가의 Conan이나 vcpkg 매니페스트, Modelica 라이브러리(`package.mo`), Xcode 프로젝트만 있는 Swift 프로젝트 |
| `plan-unsupported` | 계획의 `status`가 `unsupported`임 |
| `stage1-degraded` | 결과 매니페스트에만 나옴. 1단계 SBOM에 실패한 단계(`bomlens:pipeline-step-failed`)나 대체 경로(`bomlens:sbom-tool-degraded`)가 기록됐거나, `generate`가 `degraded`나 `failed`임 |
| `unhashable-input` | 해시를 낼 수 없는 입력이 있음. 읽을 수 없는 파일이나 폴더, 끊어졌거나 소스 밖을 가리키는 링크, 폴더 링크(cdxgen이 따라갈 수 있음), FIFO나 소켓이나 장치 파일, 탭이나 줄바꿈이 든 경로, 파일 수나 시간 한도에서 멈춘 순회, 소스 안에 있는 CLI 출력 폴더(또는 소스에 바로 쓰는 평면 출력), requirements 파일이 포함하는데 없거나 소스 밖에 있는 파일 |
| `unknown-stage1-image` | 결과 매니페스트가 1단계 이미지의 다이제스트를 모름. CLI의 1단계 이미지에 RepoDigest가 없거나(로컬에서 빌드한 이미지), 계획 없이 실행한 2단계가 다이제스트를 받지 못함 |
<!-- fingerprint-reasons:end -->

계획이 `unsupported`이면 단계가 없으므로, 지문은 계획 최상위의 `input_fingerprint`에만 `plan-unsupported`와 함께 들어갑니다.

`POSTPROCESS` 실행의 결과 매니페스트는 `generate` 단계에 2단계가 자기 코드로 소스에서 다시 계산한 지문을 적습니다. 출력 폴더에 있는 파일의 값을 그대로 가져오지 않습니다.

- 실행 계획 뒤(같은 `output_file`로 쓰인 `bomlens-plan.json`이 출력 폴더에 있을 때)에는 1단계 이미지 다이제스트, 설정, `--spec-version`을 계획에서 가져오고(다이제스트는 `BOMLENS_STAGE1_DIGEST`를 넘기면 그 값), `engine` 파일은 `bomlens-plan/`의 사본으로 해시를 냅니다. 그러면 값이 계획의 값과 같고 `plan_mismatch`는 `false`입니다. 값이 다르면(계획 뒤에 소스가 바뀌었거나, 다른 스캔에서 남은 계획이면) 계산한 값과 `plan_mismatch: true`를 적습니다. 2단계가 출력 폴더에 파일을 쓰므로 출력 폴더는 소스 밖에 두세요. 소스 안에 있으면 트리가 바뀝니다.
- CLI 소스 스캔 뒤에는 CLI가 넘긴 1단계 이미지의 RepoDigest, 실행한 파일의 sha256, 뺄 출력 폴더(`BOMLENS_FINGERPRINT_EXCLUDE`, 소스 기준 상대 경로)를 씁니다.

`reused`는 `BOMLENS_STAGE1_REUSED=1`을 넘겼으면 `true`입니다. 지문이 `reusable`이 아니거나, 없거나, 계획의 값과 다른데도 재사용했다면 `reuse_unsafe`가 `true`입니다. 이때 SBOM은 지금 1단계를 실행했을 때의 결과와 다를 수 있습니다.

`algorithm`은 구성 요소의 종류나 목록이 바뀌거나, 같은 입력에 대한 `sha256`이 달라지는 변경일 때 올립니다. 사유를 새로 추가하는 것으로는 올리지 않습니다. 이미지 입력의 지문은 이 버전에 포함되지 않습니다.

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

- 메이저: 필드, 단계 이름, 출력 역할, 상태 값을 지우거나 이름을 바꾸거나 뜻을 바꿀 때, 같은 입력에서 다른 패키지 PURL(`pkg:npm`, `pkg:deb`처럼 패키지 생태계 타입이 있는 것)이나 라이선스 식별자가 나오게 바뀔 때, 실패를 성공으로 보고하게 바뀔 때.
- 마이너: 선택 필드, 단계 이름, 사유, 출력 역할을 새로 추가할 때, 그리고 펌웨어, 루트 파일시스템, 바이너리 스캔처럼 패키지 PURL이 없던 컴포넌트(PURL 없음, `pkg:generic`, `pkg:opkg`)에 PURL을 붙이거나 바꿀 때. 읽는 쪽은 모르는 값을 무시합니다.
- 패치: 위 필드에서 읽는 쪽이 알아챌 변화가 없을 때.

SBOM 안의 `bomlens:*` 속성과 사람이 읽는 보고서는 계약에 포함되지 않으며 어느 릴리스에서든 바뀔 수 있습니다.
