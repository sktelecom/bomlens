---
description: BomLens의 전체 CLI 옵션과 환경변수, 산출물 위치, 이미지 고정, 트러블슈팅 레퍼런스입니다.
---

# CLI 레퍼런스

BomLens의 전체 옵션과 분석 모드, CI/CD 통합 방법, 트러블슈팅을 설명합니다.

## 옵션 레퍼런스

```bash
./scripts/scan-sbom.sh [옵션]
```

> **Windows 사용자**: 위 명령은 macOS/Linux 기준입니다. 다음 중 하나를 고르세요. 설치는 [시작하기](../start/first-scan.ko.md)를 참고하세요.
>
> - `./scripts/scan-sbom.sh`를 `scripts\scan-sbom.bat`로 바꿔 실행합니다 (Git Bash 필요).
> - WSL2에서는 명령을 그대로 실행합니다.
> - CLI 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭하거나 데스크톱 앱을 내려받으세요.

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--project <이름>` | — | **(필수)** 프로젝트 이름 |
| `--version <버전>` | — | **(필수)** 프로젝트 버전 |
| `--target <대상>` | 현재 디렉터리 | 분석 대상: 디렉터리(소스 트리, 또는 OS rootfs·빌드 산출물 staging), Docker 이미지, 바이너리 파일, `.zip`/`.tar.gz` 아카이브. Yocto 빌드 디렉터리는 그렇게 인식해서, 빌드 트리를 훑는 대신 `tmp/deploy/images/` 아래에 빌드가 만든 이미지 SBOM을 분석합니다([공급사 SBOM 가이드](../guides/supplier-sbom.ko.md#yocto-이미지) 참고). 소스 트리가 아닌 폴더(최상위에 매니페스트, 잠금 파일, 빌드 파일이 없는 폴더)가 루트 파일시스템이나 펌웨어 이미지를 바로 아래에 하나만 담고 있으면(릴리스의 `images/` 폴더 등) 그 루트 파일시스템이나 이미지를 분석하고, 그렇게 했다고 알려 줍니다. 펌웨어 이미지는 시그니처나 `.bix`, `.trx` 같은 펌웨어 확장자로 판단하며, `.bin`과 `.img`는 시그니처가 있어야 합니다. 최상위에 실행 파일, 공유 라이브러리, `node_modules`, 모델 파일이 있거나 최상위 파일이 20개를 넘는 폴더는 소스로 분석합니다. 여러 개를 담고 있으면 스캔을 멈추고 각각에 쓸 `--target`을 보여 줍니다 |
| `--git <url>` | — | git/GitHub URL을 얕은 클론(shallow) 후 소스로 분석 (비공개 저장소: `GIT_TOKEN` 환경변수) |
| `--branch <ref>` | 기본 브랜치 | `--git` 대상의 브랜치, 태그, 커밋 (별칭 `--ref`) |
| `--exclude <경로>` | — | 소스 스캔에서 제외할 경로. 여러 번 지정할 수 있다. 경로는 스캔할 폴더 기준 상대 경로이다(예: `--exclude vendor/legacy`). 글롭, 절대 경로, `..`은 거부한다. 제외한 경로를 뺀 사본을 스캔하므로 빌드, 라이선스 검사, 파일 트리가 모두 그 경로를 건너뛴다. 없는 경로는 알리고 무시한다 |
| `--firmware` | false | `--target` 파일을 펌웨어 모드로 강제 (opt-in 펌웨어 이미지) |
| `--as-source` | false | 디렉터리 `--target`을 있는 그대로 소스 트리로 분석합니다. 폴더 안의 루트 파일시스템이나 펌웨어 이미지로 바꾸지 않고, Yocto 빌드 디렉터리와 루트 파일시스템도 따로 인식하지 않습니다. `--firmware`와 함께 쓸 수 없습니다 |
| `--analyze <sbom>` | — | 공급사 SBOM 검증·분석 (별칭 `--sbom`). CycloneDX/SPDX. `--target`와 배타 |
| `--model <참조>` | — | AI SBOM(CycloneDX 1.7 ML-BOM)을 생성한다. HuggingFace 모델 ID(`조직/모델`)는 OWASP AIBOM Generator로 처리한다(opt-in `bomlens-aibom` 이미지; 모델 카드 메타데이터를 네트워크로 가져옴). Figshare 항목은 페이지 주소나 DOI, 항목 번호로 주면 공개 항목 조회로 데이터셋으로 기술하며 계정도 별도 이미지도 필요 없다. 이름에 "figshare"가 없는 기관 DOI는 다른 DOI와 구분할 수 없으므로 항목 주소를 준다. HuggingFace 데이터셋은 `datasets/<owner>/<name>`, `https://huggingface.co/datasets/<owner>/<name>`(이름 뒤의 `/tree/main` 같은 부분은 무시), `hf:<owner>/<name>` 중 하나로 주면 기본 이미지에서 데이터셋으로 기술하며, 카드의 `source_datasets`에 적힌 데이터셋도 함께 읽는다(`AIBOM_DATASET_DEPTH`, `AIBOM_DATASET_MAX_LOOKUPS`). HuggingFace가 모델과 데이터셋에 같은 형식을 쓰므로 앞에 아무것도 붙이지 않은 `owner/name`은 항상 모델 id로 읽는다. 접근 제한이 있거나 비공개인 데이터셋은 `HF_TOKEN`이 필요하다. `--target`/`--analyze`/`--git`/`--merge`와 배타 |
| `--model-file <경로>` | — | AI 모델 파일 하나를 읽어 그 헤더만으로 기술한다. GGUF, safetensors, PyTorch(`.pt`/`.pth`/`.ckpt`), pickle, npz, npy, ONNX를 인식한다. 오프라인으로 동작하고 HuggingFace 계정이 필요 없어 공개하지 않은 모델도 스캔할 수 있다. 채울 수 있는 정보는 형식마다 다르다. GGUF는 이름과 라이선스, 아키텍처를 담고 있지만 safetensors는 대개 텐서 정보만 있으며, 파일이 선언하지 않은 값은 추측하지 않고 비워 둔다. `--target`에 `.gguf`나 `.safetensors`, `.pt` 같은 경로를 주면 이 방식으로 읽는다. `--target`/`--analyze`/`--git`와 배타 |
| `--license <spdx-id>` | — | 프로젝트를 배포하는 배포 라이선스(예: `Apache-2.0`). SBOM 루트 컴포넌트에 기록하고, 조건이 충돌하는 의존성을 표시하는 데 쓴다. 소스 스캔으로는 알아낼 수 없어(cdxgen이 maven과 gradle에서 루트 라이선스를 비워 둔다) 지정하지 않으면 충돌 판정을 내리지 않는다. SBOM에 이미 있는 루트 라이선스(공급사가 선언한 값)는 덮어쓰지 않는다 |
| `--sbom-author <name>` | — | 이 SBOM을 생성한 주체. 스캔을 실행하는 조직이나 사람을 가리키며, 도구도 소프트웨어를 만든 쪽도 아니다. `metadata.authors`에 정식 명칭으로 기록하고 약어는 쓰지 않는다. 스캔으로는 알아낼 수 없는 값이라 지정하지 않으면 자리표시자를 채우지 않고 필드를 빼 둔다 |
| `--ai-declare <file>` | — | AI 모델이나 데이터셋 스캔에서, 스캔으로 읽을 수 없는 내용을 모델 공개자가 선언한 파일(JSON). 출시일, 모델과 데이터를 만든 주체, 학습과 평가에 쓴 데이터셋, 기반 모델 리비전, 배포 가중치 범위 같은 값이다. 선언한 값은 대부분 SPDX 3.0.1 AI 문서에만 반영한다. 예외는 모델을 실행하는 서비스(`service`)와 모델의 입력과 출력 종류, 학습 연산량, 적대적 시험 여부이며, 이 값들은 CycloneDX SBOM에도 발행자 선언으로 표시되어 들어간다([아래 예시](#ai-선언-파일) 참고). 모든 AI 스캔이 시작점으로 쓸 빈 양식 `{Project}_{Version}_ai-declaration.template.json`을 만든다. 스캔에 없는 필드, 값, 데이터셋, 기반 모델을 적은 파일은 이유와 함께 거부하고, 문서는 선언 없이 초안으로 만든다. 받아들인 파일은 `{Project}_{Version}_ai-declaration.json`으로 보관하고 같은 버전을 다시 스캔할 때 다시 적용한다. `--model`, `--model-file`, `--target` 없이 이 옵션만 주면 허브 저장소나 파일이 아직 없는 모델을 기술한다(`MODE=AIDECLARE`, 기본 이미지). `model.baseModels[].ref`의 기반 모델과 `datasets[].ref`(`huggingface:<owner>/<name>`)의 데이터셋은 허브에서 id로 읽고, `datasets[].local`에는 허브에 없는 데이터를 적으며, 모델 이름과 버전은 `--project`와 `--version`을 쓴다. 내려받기 주소와 공급자를 선언하지 않으면 SPDX 문서는 초안으로 남는다. `--ui`(모델 · 데이터셋 화면 사용)와 `--diff`에는 쓸 수 없다 |
| `--no-spdx3` | false | AI 모델이나 데이터셋 스캔에서 SPDX 3.0.1 AI 문서와 그 검사 결과, 선언 양식을 만들지 않는다 |
| `--vex <file>` | — | 공급사가 이 제품에 대해 보낸 CycloneDX VEX 문서(JSON). 스캔한 SBOM의 컴포넌트에 해당하는 진술을 `{Project}_{Version}_vex_imported.json`에 보관하며, SBOM과 보안 보고서는 바꾸지 않는다. 진술이 보안 보고서의 발견 항목에 표시되므로 `--deep-cve`처럼 보안 보고서도 함께 켠다. 웹 UI에서 스캔 폴더를 열면 취약점 행에서 볼 수 있다. 제품이나 버전이 다른 문서, 또는 CycloneDX VEX가 아닌 파일은 알리고 건너뛰며 스캔은 끝까지 진행한다. 적용할 진술이 없는 문서는 이전 `_vex_imported.json`을 그대로 둔다. `--ui`(취약점 화면의 "VEX 가져오기" 사용)와 `--diff`에는 쓸 수 없다 |
| `--component-versions <file>` | — | 펌웨어, 루트 파일시스템, 바이너리 스캔에서, 스캔이 찾았지만 버전을 읽지 못한 컴포넌트의 버전을 적은 CSV 파일(`name,version,reason`). 세 번째 열은 넣지 않아도 되며(`name,version` 두 열 파일도 전처럼 읽는다), 버전을 비우고 버전이 없는 사유를 `own-code`, `not-open-source`, `version-unknown` 중 하나로 적으면 컴포넌트에 `bomlens:versionReason`으로 기록한다. 버전과 함께 적은 사유, 스캔이 버전을 읽은 컴포넌트나 찾지 못한 이름에 적은 사유는 경고와 함께 무시한다. 스캔이 배포 파일에서 읽은 버전은 유지하고 두 값을 경고로 보여 준다. 스캔이 찾지 못한 이름은 `bomlens:identifiedBy = supplier-declared` 컴포넌트로 추가한다. 이런 스캔은 아직 버전이 없는 컴포넌트를 같은 형식의 `{Project}_{Version}_component-versions.template.csv`로 쓴다. 256 KiB를 넘거나 형식이 틀린 행이나 정해지지 않은 사유 값이 있는 파일은 거부한다. 이때도 스캔은 그 버전 없이 파일을 모두 쓰고, 이유를 보여 준 뒤 1로 끝난다. 버전도 사유도 비워 둔 행은 건너뛴다. [펌웨어 가이드](../guides/firmware.ko.md#스캔이-읽지-못한-버전-채우기) 참고 |
| `--usage <scenario>` | — | AI 모델 위험 판정을 사용 형태에 맞춘다(`--model`과 `--model-file`): `internal`, `product`, `redistribute`, `outputs-only`. 그 사용 형태에 적용되는 라이선스 조건만으로 판정하고, 보고서에 어떤 형태 기준인지 명시한다. 지정하지 않으면 전체 조건 기준으로 판정한다 |
| `--merge <a.json> <b.json> …` | — | CycloneDX SBOM 두 개 이상을 하나로 병합하고 purl 기준으로 중복을 제거한 뒤, 최상위 컴포넌트를 `--project`/`--version`으로 기재. 선택 기능으로, 외부 시스템이 제품당 단일 BOM을 요구할 때 씁니다. 그 외에는 층별로 따로 둡니다([서버 SBOM 작성 가이드](../guides/server-delivery.ko.md) 참고). `--target`/`--analyze`/`--git`와 배타 |
| `--merge-root <file>` | — | `--merge`와 함께: `--spec-version` 버전의 새 루트를 만드는 대신 이 입력 파일의 `specVersion`과 최상위 컴포넌트를 유지합니다(예: ML-BOM의 CycloneDX 1.7 루트와 모델 카드). `--merge` 입력 중 하나여야 하며, 유지된 루트의 이름과 버전은 `--project`/`--version`으로 바뀝니다 |
| `--diff <old.json> <new.json>` | — | 이미 생성한 AI 모델 SBOM 두 개(`--model` 또는 `--model-file`이 쓴 SBOM)을 비교해 변동을 찾는다. `bomlens:assessment:*` 판정이 이전보다 나빠졌는지, 선언된 라이선스가 바뀌었는지, 그리고 같은 모델 이름·purl·HuggingFace ID인데 가중치 파일의 SHA-256 해시가 달라졌는지를 본다. 마지막 항목이 가장 중요한 신호로, 이름은 그대로인데 그 뒤의 실제 파일이 조용히 바뀌었다는 뜻이다. `--project`/`--version`도 스캔 대상도 필요 없으며, 새 쪽 파일 이름을 따서 `<new>_model-diff.json`을 만든다(위치는 현재 디렉터리, `--output-dir` 지정 시 그 아래) |
| `--generate-only` | false | 업로드 없이 로컬에만 저장 |
| `--upload-target <대상>` | `dependency-track` | 업로드 대상: `dependency-track`(DT 호환) 또는 `trusca`(네이티브 ingest) |
| `--trusca <project_id>` | — | TRUSCA에 업로드(= `--upload-target trusca` + project id). `API_URL`과 Bearer `API_KEY` 필요 |
| `--notice` | 오픈소스 위험 보고서 기본값에 딸려 켜짐 | 오픈소스 고지문(NOTICE, txt+html) 생성. 플래그 자체의 기본값은 꺼짐이며, 기본으로 켜진 오픈소스 위험 보고서가 이를 켠다. 그래서 끄려면 `--notice`를 빼는 게 아니라 `--no-report`를 써야 한다 |
| `--security` | 오픈소스 위험 보고서 기본값에 딸려 켜짐 | Trivy 보안 보고서(json+md+html) 생성. CVSS, EPSS, CISA KEV 우선순위 신호 포함. `--notice`와 같은 구조로, `--no-report`가 꺼야 꺼지고 플래그만 빼서는 꺼지지 않는다 |
| `--spdx` | false | 최종 CycloneDX 결과를 변환한 SPDX 2.3 JSON(`_bom.spdx.json`)을 함께 생성 |
| `--spec-version <1.6\|1.7>` | `1.6` | SBOM의 CycloneDX 버전. `1.7`을 주면 cdxgen과 syft가 1.7로 쓰고, 1.4, 1.5, 1.6으로 만들어진 SBOM은 내보내기 전에 `$schema`까지 1.7로 표기를 바꾼다. 이 버전들은 1.7까지 필드가 더해지기만 했지만, 1.6부터는 property에 이름이 있어야 하므로 이름 없는 1.4, 1.5 property는 버전을 올릴 때 지운다. 1.3 이하인 SBOM은 버전을 그대로 두고, 기본값 `1.6`에서 1.4 SBOM도 버전을 그대로 두며 이때는 `metadata.lifecycles`(1.5 필드)를 넣지 않는다. NOTICE, 보안 리포트, 적합성 검사, 웹 UI는 두 버전을 모두 읽는다. AI 모델과 데이터셋 SBOM은 이 값과 관계없이 1.7이다. Dependency-Track은 4.14.4와 5.1.0부터 1.7을 읽으며, 이를 거부하는 오래된 서버나 버전을 알 수 없는 서버에는 1.6 사본을 보낸다([업로드](../guides/upload.ko.md#문제-해결) 참고). 다른 값을 주면 스캔이 멈춘다 |
| `--all` | — | `--notice --security --spdx` |
| `--no-report` | false | 오픈소스 위험 보고서(risk-report) 생략 (아래 참고) |
| `--lang <en\|ko>` | `en` | 사람이 읽는 적합성·AI 준수 개요 보고서(`.md`/`.html`)의 언어. SBOM과 JSON 보고서는 언어와 무관하게 영어로 유지 |
| `--conformance-profile <default\|skt-submission>` | `default` | 적합성 검사 엄격도. `skt-submission`은 PURL 포함률 100%를 요구하고 `pkg:generic` 식별자가 하나라도 있으면 실패로 판정한다(SKT 공급사 제출 심사 기준과 동일). 필수 항목 "버전 보충 필요"를 더하는데, 버전도 사유도 없는 컴포넌트(`--component-versions`로 채움)만 실패로 보고 사유가 있는 컴포넌트는 공급사 소명으로 따로 보여 준다. 버전은 있지만 upstream purl이 없는 컴포넌트는 권고 항목 "upstream purl 없음"에 나오며 SK텔레콤이 따로 확인한다. 펌웨어, 루트 파일시스템, 바이너리 스캔과, `--analyze`에서 이런 스캔이 기록한 `bomlens:scanMode`가 있는 SBOM에서는 name/version 포함률, PURL 포함률, `pkg:generic`, 전이 의존성 항목이 두 항목이 이미 다루는 컴포넌트 때문에 실패하지 않고 경고로 바뀐다. 이런 스캔은 의존성 그래프가 아니라 찾은 패키지를 기록하기 때문이다. 또 `pkg:sourceforge`와 `pkg:gnu`를 받아들이며, 제출할 파일이 `{Project}_{Version}_bom.json` 하나라는 점을 요약에 적는다. 웹 UI의 제출 전 점검 화면은 `skt-submission`이 기본값이지만 CLI는 아니므로, `--analyze`와 함께 명시적으로 지정해야 한다 |
| `--license-registry` | 꺼짐 | 라이선스가 없는 컴포넌트의 라이선스를 패키지 레지스트리(deps.dev)에 조회하고, 하나뿐인 강한 카피레프트나 비상업 라이선스(GPL, AGPL, SSPL, BUSL, CC-BY-NC)를 레지스트리와 대조한다. 레지스트리 답이 다르면 그 답으로 바꾸고 원래 값은 `bomlens:license:superseded`에 남긴다. 이렇게 쓴 라이선스에는 `bomlens:licenseSource` = `registry (deps.dev)`가 붙는다. 본문, URL, concluded 판정이 붙은 라이선스는 대조하지 않고, `--analyze`에서는 빠진 라이선스만 채운다. 네트워크를 사용 |
| `--resolve-purl` | 꺼짐 | `--analyze` 전용. 제출된 SBOM의 식별자가 실제 있는 패키지를 가리키는지 각 패키지 저장소에 조회해 적합성 검사 보고서에 권고 항목으로 덧붙인다. 적합성 검사에서 네트워크를 쓰는 유일한 부분이다. 조회되지 않는 식별자는 보고만 하고 실패로 보지 않는다. 사내 저장소에만 올린 패키지도 같은 결과가 나오기 때문이다. 사내 네임스페이스는 `PURL_RESOLVE_IGNORE`로 제외한다 |
| `--deep-license` | false | scancode로 프로젝트 자체 파일의 라이선스 정밀 탐지 (opt-in `bomlens-deep-license` 이미지, 자동으로 내려받음. 내려받을 수 없으면 라이선스 탐지 없이 기본 이미지로 스캔). `--deep-cve`를 함께 켜면 라이선스 탐지를 먼저 이 이미지에서 실행하고 후처리는 deep-cve 이미지로 실행하므로, `_scancode.json`과 `_security_grype.json`이 모두 만들어진다 |
| `--deep-cve` | false | grype의 NVD CPE 매칭으로 두 번째 대조를 더한다 (opt-in `bomlens-deep-cve` 이미지, 자동으로 내려받음. 소스 스캔은 후처리 단계를 이 이미지로 실행하고, 내려받을 수 없으면 grype 대조 없이 스캔을 이어 간다. `SBOM_SCANNER_IMAGE`가 로컬 빌드, 1.13.2보다 낮은 버전, 다른 이름이고 `SBOM_DEEP_CVE_IMAGE`가 없으면 후처리는 그 이미지에서 실행되며, 그 이미지에 grype가 있을 때만 대조한다. `--deep-license`를 함께 켜도 같다). BomLens는 Maven 컴포넌트에만 NVD 대조가 가능한 CPE를 붙여 주므로, Trivy가 놓치는 NVD 전용 CVE는 대부분 오래된 Maven 라이브러리에서 나온다. `--security`를 자동으로 켠다. NVD 실시간 버전 범위로 확인하지 못한 결과는 보고서에 버전 미검증으로 표시된다. [정밀 CVE 대조 가이드](../guides/reports.ko.md) 참고 |
| `--reachability` | false | Go 소스나 `--target`으로 준 Go 실행 파일에서, 각 Go 보안 권고가 가리키는 코드에 도달하는지 govulncheck로 판정한다. 소스는 호출 그래프로, 실행 파일은 심볼로 본다. 도달하지 않는 권고는 `{Project}_{Version}_reachability.cdx.json`(CycloneDX VEX)에 `not_affected`로 기록하고(영향받는 패키지가 빌드에 없으면 `code_not_present`, 패키지는 있지만 영향받는 함수에 도달하지 않으면 `code_not_reachable`), `_security.json`의 해당 발견 항목에 표시하며, 보안 보고서의 "Not reachable" 절에 따로 싣는다. 이 항목은 보안 보고서와 위험 보고서의 집계, `--fail-on vulnerability=`에서 빠진다. 도달하는 권고는 호출 경로와 함께 `exploitable`로 기록한다. `--security`를 자동으로 켠다. govulncheck는 Go 취약점 데이터베이스(vuln.go.dev)를 네트워크로 읽으며, 닿지 않으면 이 단계를 건너뛰고 보고서는 이 옵션이 없을 때와 같다. 소스 스캔에서는 1단계의 Go 이미지 안에서 트리의 Go 모듈마다(최대 20개) GOOS linux, darwin, windows(GOARCH amd64)와 기본 빌드 태그로 govulncheck를 실행하며, 사용자 정의 빌드 태그로만 빌드되는 코드는 보지 않는다. `--ui`에서는 웹 UI의 결과 품질 묶음에서 스캔마다 고른다. [Go 도달성](../guides/reports.ko.md#go-도달성---reachability) 참고 |
| `--identify-vendored` | false | 패키지 매니저가 없는 C/C++ 소스에 복사돼 들어간(vendored) 오픈소스를 식별. 파일 지문을 OSSKB 서비스와 대조 (발행 이미지에 포함; 소스가 아니라 해시 전송). [내장 오픈소스 식별 가이드](../guides/identify-vendored.ko.md) 참고 |
| `--verify-weights` | false | `--model`과 함께 쓰면 저장소의 pickle 계열 가중치 파일(`.bin`/`.pt`/`.pth`/`.ckpt`, 로드 시 코드를 실행할 수 있는 형식)을 내려받아 `--model-file`이 실행하는 것과 같은 로컬 picklescan 검증을 돌린다. HuggingFace 자체 스캔 결과(`bomlens:hf:scan:*`)만 믿는 대신 독립적으로 확인하는 것이다. safetensors·GGUF·ONNX 가중치는 내려받지 않는다. 로드 시 코드를 실행하지 않는 형식이라 picklescan으로 확인할 대상이 없기 때문이다. 실제 네트워크·디스크 비용이 들고(`AIBOM_VERIFY_MAX_FILES`/`AIBOM_VERIFY_MAX_BYTES`로 상한, 기본 5개 파일 · 각 2GiB) 메타데이터만 읽는 `ENRICH_HF_SECURITY` 조회와 달리 옵트인이다. AI 모델 스캔 전용 |
| `--byte-stable` | false | 결정론적(재현 가능) SBOM 출력 |
| `--detection <how>` | auto | 소스 스캔이 의존성을 찾는 방식. `build`는 cdxgen 언어 이미지에서 의존성을 해석하고, `static`은 lock 파일을 읽을 뿐 빌드하지 않으며(언어 이미지를 받지 않고 5~10초가 줄지만, 완전한 lock 파일이 없는 프로젝트는 결과가 모자라고, 워크스페이스는 멤버의 의존성이 딸려 들어오며, 빌드가 내려받은 패키지에서 읽는 저작권 표기는, 예를 들어 Rust 프로젝트의 크레이트 98개 중 73개는, 채워지지 않는다), `auto`는 `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock`, `gradle.lockfile` 중 하나가 트리 전체를 덮을 때만 정적으로 읽고 그 외에는 빌드한다. 정적 스캔은 lock 파일에 없는 라이선스를 패키지 레지스트리에서 채우므로(`--license-registry`와 같은 조회) `--byte-stable`이나 `FETCH_LICENSE=false`에서는 `auto`가 빌드한다. 환경변수 `DETECTION=<how>`도 같다. SBOM에는 어느 방식으로 만들었는지가 남는다(`bomlens:detection`) |
| `--fail-on-conformance` | false | 이 스캔 자체의 적합성 검사 보고서가 "fail"이면 종료 코드 2로 끝난다(이 스캔에서 적합성 검사 보고서가 아예 안 만들어졌으면 3). `--ui`와는 함께 쓸 수 없다. [종료 코드](#종료-코드) 참고 |
| `--fail-on <condition>` | — | 이 스캔이 조건에 걸리면 종료 코드 4로, 스캔 결과만으로 조건을 판정할 수 없으면 5로 끝난다. 여러 조건은 옵션을 반복해서 준다. 조건은 닫힌 목록이다. `vulnerability=<critical\|high\|medium\|low>`(해당 심각도 이상의 취약점, 보안 보고서를 함께 켬), `malicious-package`(알려진 악성 패키지로 표시된 컴포넌트), `license-conflict`(제품이 배포되는 라이선스와 양립하지 않는 컴포넌트, SBOM의 루트 컴포넌트에 그 라이선스가 기록돼 있어야 하며 소스와 rootfs 스캔은 `--license`로, 공급사 SBOM은 SBOM 자체에 담겨 있고, 없으면 판정할 수 없음), `empty-result`(스캔이 소프트웨어를 하나도 식별하지 못함. operating-system과 file 항목을 빼고 남는 컴포넌트가 없으면 해당하므로, 패키지를 하나도 식별하지 못한 rootfs나 이미지 스캔도 비어 있는 것으로 본다), `license-coverage=<0-100>`(같은 컴포넌트 중 라이선스를 선언한 비율이 그 값(%) 미만. NOASSERTION과 NONE은 선언으로 세지 않고, 백분율은 내림하며, 값은 필수이고 기본값이 없으며 앞자리 0을 붙일 수 없음). 뒤의 두 조건은 이 스캔의 적합성 검사 보고서를 읽으므로, 보고서가 만들어지지 않았거나 보고서가 그 SBOM 형식을 측정하지 못했으면(변환할 수 없던 SPDX 3.0 문서) 판정할 수 없다. 그런 컴포넌트가 없는 스캔에서는 `license-coverage=`도 판정할 수 없다(그 경우는 `empty-result`를 쓴다). 두 조건은 적합성 판정 자체는 바꾸지 않는다. 취약점은 보안 보고서와 같은 기준으로 센다. 패키지와 ID당 한 번이며 커널 권고는 뺀다. `--vex` 진술은 적용하지 않으므로 공급사가 영향 없음으로 선언한 취약점도 센다. `--reachability`가 도달하지 않는다고 판정한 취약점은 세지 않는다. `vulnerability=`는 의존성이 없는 AI 모델과 데이터셋 입력에는 쓸 수 없다. `empty-result`도 마찬가지다. `--ui`, `--diff`와는 함께 쓸 수 없다. [종료 코드](#종료-코드) 참고 |
| `--sign` | false | cosign 서명 (`COSIGN_KEY` 필요) |
| `--output-dir <dir>` | 현재 디렉터리 | 산출물 베이스 디렉터리 (별칭 `-o`). 스캔마다 그 아래 `{Project}_{Version}/` 하위 폴더에 묶여 저장되어 소스 트리를 오염시키지 않음 |
| `--timestamp` | false | 실행 하위 폴더 이름에 `_YYYYMMDD-HHMMSS`를 덧붙여, 같은 프로젝트와 버전을 다시 스캔해도 덮어쓰지 않고 나란히 보관. 폴더 이름만 바뀌고 SBOM 내용은 그대로 |
| `--ui` | — | 로컬 웹 UI 실행 |
| `--mount <dir>` | — | `--ui`와 함께: 호스트 디렉터리를 웹 UI의 **디렉터리 경로** 입력에서 고를 수 있는 읽기 전용 스캔 대상으로 추가(여러 번 지정 가능). 실행 폴더 밖의 OS 트리를 스캔할 수 있고, `--mount /`로 실행 중인 호스트 OS도 스캔합니다. 결과는 그대로 실행 폴더에 저장됩니다 |
| `--help` | — | 도움말 출력 |

환경변수로 동작을 조정할 수 있습니다.

| 환경변수 | 기본값 | 설명 |
|----------|--------|------|
| `SBOM_SCANNER_IMAGE` | `ghcr.io/sktelecom/bomlens:latest` | 스캐너 이미지를 다른 태그로 재정의 |
| `SBOM_FIRMWARE_IMAGE` | `SBOM_SCANNER_IMAGE`가 레지스트리 경로가 있는 BomLens 이미지 이름이고 태그가 1.13.2 이상이거나 버전이 아닌 태그일 때 그것을 따른다(같은 레지스트리 경로와 태그. `.../bomlens:1.13.2`이면 `.../bomlens-firmware:1.13.2`). 그 밖에는 `ghcr.io/sktelecom/bomlens-firmware:latest` | 펌웨어 분석용 이미지 지정 |
| `SBOM_AIBOM_IMAGE` | `SBOM_SCANNER_IMAGE`가 레지스트리 경로가 있는 BomLens 이미지 이름이고 태그가 1.13.2 이상이거나 버전이 아닌 태그일 때 그것을 따른다(같은 레지스트리 경로와 태그. `.../bomlens:1.13.2`이면 `.../bomlens-aibom:1.13.2`). 그 밖에는 `ghcr.io/sktelecom/bomlens-aibom:latest` | AI 모델(ML-BOM) 생성용 이미지 지정 |
| `SBOM_DEEP_CVE_IMAGE` | `SBOM_SCANNER_IMAGE`가 레지스트리 경로가 있는 BomLens 이미지 이름이고 태그가 1.13.2 이상이거나 버전이 아닌 태그일 때 그것을 따른다(같은 레지스트리 경로와 태그. `.../bomlens:1.13.2`이면 `.../bomlens-deep-cve:1.13.2`). 그 밖에는 `ghcr.io/sktelecom/bomlens-deep-cve:latest` | `--deep-cve`(grype CPE 매칭)용 이미지 지정. 웹 UI의 같은 토글도 이 이미지를 쓴다 |
| `SBOM_DEEP_LICENSE_IMAGE` | 같은 조건에서 `SBOM_SCANNER_IMAGE`를 따른다. 조건에 맞지 않으면 `SBOM_SCANNER_IMAGE` 자체, 둘 다 없으면 `ghcr.io/sktelecom/bomlens-deep-license:latest` | `--deep-license`(scancode)일 때 소스 스캔의 후처리 단계를 실행할 이미지 |
| `SBOM_OUTPUT_FLAT` | — | `1`로 두면 실행별 하위 폴더 없이 산출물을 베이스에 평면으로 저장(격리 이전 배치, 옛 경로를 기대하는 CI용) |
| `SBOM_OUTPUT_DIR` | `~/sbom-output` | 데스크톱 앱과 웹 UI의 산출물 베이스(CLI는 대신 `--output-dir` 사용). 스캔마다 그 아래 `{Project}_{Version}/` 하위 폴더에 저장 |
| `SBOM_UI_MOUNT_DIR` | — | CLI 인자를 받지 않는 Windows 실행 파일 `sbom-ui.bat`용: 웹 UI의 디렉터리 경로 입력에 읽기 전용 대상으로 추가할 폴더 하나(`--ui --mount`의 더블클릭 대응). `& ^ | < >` 가 없는 경로를 쓸 것 — 런처는 이런 문자가 있으면 잘못된 마운트를 Docker에 넘기는 대신 거부한다 |
| `SBOM_LANG` | 시스템 로캘 | Windows 런처와 데스크톱 앱의 언어. `en` 또는 `ko`. 한국어가 아니면 영어로 표시된다 |
| `SBOM_BASH` | 자동 감지 | `scan-sbom.bat`용: Git Bash의 `bash.exe` 경로를 직접 지정(예: `C:\Program Files\Git\bin\bash.exe`). 런처가 PATH의 git으로 자동 감지를 시도했으나 WSL이나 WindowsApps 별칭이 아닌 실제 Git Bash를 못 찾았을 때 쓴다 |
| `CDXGEN_IMAGE_PREFIX` | `ghcr.io/cdxgen/` | 소스 스캔의 cdxgen 이미지(언어 이미지와 올인원 이미지)를 받아 오는 곳으로, 이미지 이름 앞부분 전체다. ghcr.io에 접속할 수 없는 네트워크에서는 같은 이미지를 둔 레지스트리 미러로 지정한다(예: `registry.example/mirror/cdxgen/`). 이미지 이름과 태그는 그대로다. 웹 UI의 소스 스캔(`--ui`, `sbom-ui.bat`, 데스크톱 앱)에도 전달하고, Android SDK 이미지를 빌드할 때는 `--build-arg`로 넘긴다(이 빌드는 기반 이미지를 다이제스트로 고정하므로, 미러는 pull-through 캐시이거나 모든 플랫폼을 복사한 것이어야 한다) |
| `SBOM_PULL` | `missing` | 스캐너 이미지 다운로드 정책. `scan-sbom.sh`와 Windows 런처 모두에 적용된다. `missing`(기본)은 이미지가 없을 때만 받고, 이미 있으면 백그라운드에서 조용히 최신 여부를 확인한다(시간 상한을 두고 최선을 다하는 방식이라, 확인이 멎거나 오프라인이면 그냥 포기하고 로컬 이미지로 진행한다). `always`는 매번 멈춰서 다시 받고, 실패하면 실행 자체를 중단한다. `never`는 네트워크를 전혀 쓰지 않고, 이미지가 없으면 실행을 중단한다. `--deep-cve`나 `--deep-license`에 필요한 opt-in 이미지는 없을 때 한 번 받는다(`always`는 실행마다 한 번). 받는 동안 docker 진행 상황을 보여 주고 시간 제한은 두지 않는다. `always`에서 받기에 실패하면 이미 있는 이미지를 쓰고, 오프라인이거나 `never`라서 이미지를 아예 구할 수 없으면 그 사실을 알리고 그 이미지 없이 스캔을 이어 간다 |
| `SBOM_IMAGE_TAR` | — | `docker save`로 만든 이미지 tar 경로. Windows 런처가 pull 대신 이 파일을 불러온다. 스크립트 옆에 `bomlens-image.tar`가 있으면 자동으로 사용한다. `SBOM_PULL=never`와 함께 쓰면 완전 오프라인 설치가 된다 |
| `CVE_BIN_TOOL_MODE` | `auto` | 펌웨어, 루트 파일시스템, 바이너리 스캔에서 `components-only`로 두면 이미지에 들어 있는 NVD CPE 인덱스와의 CPE 대조를 끔. 펌웨어 바이너리 식별은 그대로 하며, 다른 값은 대조를 켠 채로 둠. 스캐너 컨테이너가 읽는 값(`docker run -e`)으로, CLI는 넘기지 않음 |
| `CVE_BIN_TOOL_HOME` | `/opt/cve-bin-tool-home` | 이미지가 NVD CPE 인덱스(`cpe_match.sqlite`)와 그 데이터 고지를 두는 위치. 펌웨어 이미지는 cve-bin-tool이 시작하는 데 필요한 `cve.db`도 여기에 두지만, 이 파일에는 CVE 데이터가 없음 |
| `CVE_BIN_TOOL_DISABLE_SOURCES` | `GAD,OSV` | 펌웨어 스캔에서 비활성화할 cve-bin-tool 데이터 출처. GAD(GitLab Advisory)와 OSV는 식별 과정이 네트워크로 나가지 않도록 기본 비활성화 |
| `SCANOSS_API_URL` | OSSKB 무료 API | `--identify-vendored`의 엔드포인트. 에어갭·대량 사용 시 SCANOSS 상용·자체 호스팅 엔드포인트로 지정 |
| `SCANOSS_API_KEY` | — | `SCANOSS_API_URL`이 요구하는 경우의 자격 증명 |
| `SCANOSS_MIN_FILES` | `2` | 라이브러리를 보고하기 위해 매치돼야 하는 최소 파일 수. 단발성 다운스트림 포크 노이즈를 거른다. `1`로 두면 단일 파일 매치도 모두 유지 |
| `GIT_TOKEN` | — | 비공개 git 저장소 클론에 쓰는 토큰 |
| `HF_TOKEN` | — | `--model`과 AI SBOM 분석의 데이터셋 메타데이터 조회에 쓰는 HuggingFace read 토큰. 비공개·게이트 저장소에 필요하며, 모델을 공개하기 전 검토할 때 쓴다. `HUGGING_FACE_HUB_TOKEN`도 별칭으로 받는다 |
| `ENRICH_HF_SECURITY` | `true` | `--model` 스캔에서 HuggingFace가 자체 실행한 파일 보안 스캔 결과(파일별 ClamAV·picklescan)를 읽어 ML-BOM에 기록한다. 메타데이터만 읽고 파일은 내려받지 않는다. `false`면 조회를 건너뛴다 |
| `AIBOM_VERIFY_MAX_FILES` | `5` | `--verify-weights`에서 모델당 내려받아 스캔할 pickle 계열 가중치 파일의 최대 개수. 상한을 넘는 나머지 파일은 대기열에 넣지 않고 그냥 확인하지 않는다 |
| `AIBOM_VERIFY_MAX_BYTES` | `2147483648`(2GiB) | `--verify-weights`에서 이 크기를 넘는 가중치 파일(저장소가 선언한 크기든 실제로 내려받은 크기든)은 내려받거나 스캔하지 않고 건너뛴다 |
| `AIBOM_DATASET_DEPTH` | `3` | `--model`에서 데이터셋 카드가 적은 원천(`source_datasets`)을 몇 단계 아래까지 읽어 함께 판정할지. `0`이면 예전처럼 모델 카드가 적은 데이터셋만 읽는다 |
| `AIBOM_DATASET_MAX_LOOKUPS` | `40` | `--model`에서 스캔 한 번에 읽는 데이터셋의 최대 개수(원천 포함). 상한을 넘은 데이터셋은 이름만 기록하고 읽지 않았다고 표시한다 |
| `COSIGN_KEY` | — | `--sign`에 쓰는 서명 키 경로 |
| `CYCLONEDX_SPEC_VERSION` | `1.6` | `--spec-version`과 같다. CLI 없이 `docker run`으로 스캐너 이미지를 실행할 때도 이 값을 읽는다 |
| `FETCH_LICENSE` | `true` | 소스 스캔 시 의존성 라이선스를 자동 조회. `false`면 조회를 생략해 속도를 높임 |
| `GOTOOLCHAIN` | `auto` | Go 소스 스캔에서 모듈을 해석할 Go 툴체인. 기본값에서는 `go.mod`가 스캐너 이미지보다 새 Go를 요구하면 그 버전을 내려받는다. `local`이면 이미지에 든 Go만 쓰고, 이런 프로젝트는 의존성 해석이 실패한다 |
| `GOPROXY` | `https://proxy.golang.org,direct` | Go 소스 스캔에서 모듈과 툴체인을 내려받을 프록시. `proxy.golang.org`에 접근할 수 없는 사내망에서 지정한다. `GOSUMDB`도 같은 방식으로 전달된다 |
| `PROJECT_LICENSE` | — | `--license`와 같다. 프로젝트의 배포 라이선스를 SPDX 식별자로 지정한다. `bomlens:licenseConflict` 판정과 위험 보고서의 충돌 절을 만든다 |
| `SBOM_AUTHOR` | — | `--sbom-author`와 같다. SBOM을 생성한 주체를 `metadata.authors`에 기록한다 |
| `SECURITY_ENRICH` | `true` | 보안 보고서에 EPSS와 CISA KEV 신호를 보강. 폐쇄망에서는 `false`로 외부 조회 생략 |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | — | 스캔 컨테이너에 이름으로 전달(소문자 이름도). 이 컴퓨터의 루프백 주소(`127.0.0.1`, `localhost`)에 있는 프록시는 넘기지 않는다. 컨테이너 안에서는 그 주소가 컨테이너 자신이기 때문이다. 이때는 Docker의 프록시 설정이 적용된다 |
| `TRIVY_*` | — | Trivy 설정을 이름으로 그대로 전달. 예: 데이터베이스 미러 `TRIVY_DB_REPOSITORY`, 오프라인 `TRIVY_SKIP_DB_UPDATE=true`. `TRIVY_CACHE_DIR`은 호스트 경로라 전달하지 않으므로 `SBOM_TRIVY_CACHE`를 쓴다 |
| `SBOM_TRIVY_CACHE` | `~/.cache/bomlens/trivy`(Windows는 `%LOCALAPPDATA%\bomlens\cache\trivy`) | Trivy 캐시로 쓸 호스트 폴더. 취약점 데이터베이스(약 1.5GB)를 스캔마다 받지 않고 한 번만 받아 스캔당 15~25초를 줄인다(웹 UI의 스캔도). 빈 값으로 두면 예전처럼 스캔마다 받는다. 스캔을 동시에 돌려도 되며 데이터베이스만 공유한다. 오프라인 호스트에서는 데이터베이스를 여기에 넣고 `TRIVY_SKIP_DB_UPDATE=true`로 둔다. Linux에서는 안의 파일이 root 소유가 된다 |
| `EPSS_API`, `KEV_URL` | 공개 엔드포인트 | EPSS와 CISA KEV 조회용 미러 |
| `SECURITY_NVD_VERIFY` | `false` | `--deep-cve`와 함께: grype의 `nvd:cpe` 결과를 NVD 실시간 버전 범위와 대조해 범위 밖 오탐을 걸러낸다 (`NVD_API_KEY`와 네트워크 필요, 수 분 추가). 기본은 꺼짐 — 결과를 버리지 않고 버전 미검증으로 표시한다 |
| `NVD_API_KEY` | — | `SECURITY_NVD_VERIFY`에 쓰는 NVD API 키. 컨테이너에 이름으로만 전달하며 명령줄에 노출하지 않는다 |
| `SYFT_REGISTRY_AUTH_USERNAME`, `SYFT_REGISTRY_AUTH_PASSWORD`, `SYFT_REGISTRY_AUTH_TOKEN`, `SYFT_REGISTRY_AUTH_AUTHORITY` | — | 로컬 Docker 데몬에 없는 이미지를 스캔할 때 쓰는 비공개 레지스트리 자격 증명(`docker pull`로 받을 수 있는 이미지에는 필요 없다). `SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY`, `SYFT_REGISTRY_INSECURE_USE_HTTP`, `SYFT_PLATFORM`도 함께 전달한다. 이름으로만 전달한다 |
| `API_URL` | — | 업로드 서버 주소(DT 서버 또는 TRUSCA base) |
| `API_KEY` | — | 업로드 자격. DT는 `X-Api-Key`, TRUSCA는 Bearer 토큰으로 쓰임 |
| `UPLOAD_TARGET` | `dependency-track` | 업로드 대상: `dependency-track` 또는 `trusca` |
| `TRUSCA_PROJECT_ID` | — | TRUSCA 프로젝트 id(UUID). `trusca`일 때 필수 |
| `TRUSCA_REF` | `main` | ingest ref 라벨 |
| `TRUSCA_RELEASE` | `--version` 값 | ingest release 라벨 |
| `EXTERNAL_LOOKUP` | `true` | `--ui`와 함께: 웹 UI의 CVE·패키지 조회 기능을 켠다. 필요할 때 osv.dev로 조회한다. 폐쇄망에서는 `false`로 끈다 |
| `SBOM_UPLOAD_TTL_HOURS` | `24` | `--ui`와 함께: 스캔을 시작하지 않은 업로드 파일(선택만 하고 방치된 업로드)을 보관하는 시간. 최소 1로 제한된다 |

`sbom-scanner:local`처럼 레지스트리 경로가 없는 짧은 로컬 이름이나 1.13.2보다 낮은 버전 태그이면 이전 기본값을 씁니다. opt-in 이미지는 `ghcr.io/sktelecom/bomlens-<이름>:latest`, `--deep-license`는 `SBOM_SCANNER_IMAGE` 자체입니다.

`SBOM_SCANNER_IMAGE`를 digest로만 지정하면 opt-in 이미지는 CLI와 웹 UI에서 `:latest`를, 데스크톱 앱에서 앱 버전 태그를 씁니다. opt-in 이미지도 고정하려면 각 `SBOM_*_IMAGE`를 지정하세요.

`BOMLENS_MAVEN_FULL_GRAPH` 같은 소스 스캔 의존성 해석 옵션은 [Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)에 정리돼 있습니다. `scan-sbom.sh`를 실행하는 셸에서 설정하면 같은 방식으로 의존성 해석에 적용됩니다.

Windows에서는 명령 프롬프트에서 설정한 환경변수가 더블클릭 실행에는 적용되지 않습니다.
그래서 런처는 `UI_PORT`, `SBOM_LANG`, `SBOM_PULL`, `SBOM_IMAGE_TAR`, `SBOM_SCANNER_IMAGE`,
`SBOM_OUTPUT_DIR`, `SBOM_UI_MOUNT_DIR`을 텍스트 파일에서도 읽습니다.
`scripts/bomlens.settings.example.txt`를 스크립트 옆에 `bomlens.settings.txt`로 복사하거나
`%USERPROFILE%\.bomlens\settings.txt`에 두면 됩니다. 실제 환경변수가 있으면 그쪽이 우선합니다.

출력 플래그 상세는 [보고서 생성 가이드](../guides/reports.ko.md)를, 공급사 SBOM 검증은 [공급사 SBOM 검증](../guides/supplier-sbom.ko.md)을 참고하세요.

## AI 선언 파일

`--ai-declare`는 JSON 파일을 받습니다. AI 스캔이 만든 `{Project}_{Version}_ai-declaration.template.json`에서 시작해 해당하는 항목만 채우면 됩니다. 아래 예는 고객 상담 채팅 서비스에서 실행되며 외부 번역 모델을 호출하는 모델을 기술합니다.

```json
{
  "schema": "bomlens-ai-declaration/1",
  "document": {"createdBy": [{"type": "Organization", "name": "Acme AI Lab"}]},
  "model": {
    "releaseTime": "2025-04-15T00:00:00Z",
    "originatedBy": [{"type": "Organization", "name": "Acme AI Lab"}],
    "inputModality": ["text"],
    "outputModality": ["text"],
    "trainingComputeFlops": "3.2e21",
    "trainingComputeBasis": "6 x parameters x training tokens, from the training logs",
    "adversarialTesting": "yes"
  },
  "service": {
    "name": "Acme Support Assistant",
    "packageVersion": "2.3.0",
    "downloadLocation": "https://support.acme.example/assistant",
    "suppliedBy": {"type": "Organization", "name": "Acme Corp"},
    "releaseTime": "2025-06-01T00:00:00Z",
    "autonomyType": "no",
    "dataFlows": [
      {"flow": "outbound", "classification": "personal data",
       "description": "Questions forwarded to the external translation model.",
       "destination": ["https://api.translate.example/v1"]}
    ],
    "externalModels": [
      {"key": "translate", "name": "Example Translate",
       "suppliedBy": {"type": "Organization", "name": "Example Inc"},
       "endpoint": "https://api.translate.example/v1"}
    ]
  }
}
```

```bash
./scripts/scan-sbom.sh --project support-adapter --version 1.0 \
  --model "acme/support-adapter" --ai-declare declaration.json --generate-only
```

`service`와 모델의 입력과 출력 종류, 학습 연산량, 적대적 시험 여부는 같은 실행에서 CycloneDX SBOM에 들어가고, 나머지 값은 SPDX 3.0.1 문서에만 들어갑니다. 키와 허용 값 전체는 [선언한 AI 서비스](artifacts.ko.md#선언한-ai-서비스)에 있습니다. BomLens v1.13 이하는 `service`나 이 모델 키가 있는 파일을 "unknown key(s)" 오류로 거부합니다. `--ai-declare`만 입력으로 줄 때는 `--no-spdx3`를 함께 쓸 수 없습니다. 선언한 값 대부분이 들어갈 곳이 없어지기 때문입니다.

## 산출물 위치

스캔마다 자체 `{Project}_{Version}/` 하위 폴더에 격리되므로, 한 번 실행에서 나온 파일이 한곳에 모이고 CLI가 스캔하는 소스 트리를 오염시키지 않습니다. 이 하위 폴더는 베이스 디렉터리 아래에 만들어집니다.

- **CLI**(`scan-sbom.sh`): 베이스는 명령을 실행한 디렉터리입니다. `--output-dir <dir>`(별칭 `-o`)로 바꿉니다.
- **데스크톱 앱과 웹 UI**: 베이스는 `~/sbom-output`(Windows는 `C:\Users\<사용자>\sbom-output`)입니다. `SBOM_OUTPUT_DIR` 환경변수로 바꿉니다.

`--git`이나 아카이브 수집 시에도 클론과 해제는 종료할 때 정리되는 임시 디렉터리에서 이뤄지고, 출력 하위 폴더만 남습니다.

같은 프로젝트와 버전을 다시 스캔하면 기본적으로 그 하위 폴더를 덮어써 최신 결과만 남깁니다. 매번 따로 보관하려면 `--timestamp`를 붙입니다. 폴더 이름에 `_YYYYMMDD-HHMMSS`가 덧붙어, 예를 들어 `MyApp_1.0.0_20260626-143000/`가 됩니다. 이 옵션은 폴더 이름만 바꿀 뿐 SBOM 파일 이름과 내용은 그대로라서 `--byte-stable`과 함께 쓸 수 있습니다.

이전의 평면 배치, 즉 하위 폴더 없이 베이스에 파일을 바로 저장하던 방식으로 되돌리려면 `SBOM_OUTPUT_FLAT=1`을 설정합니다. 옛 경로를 기대하는 CI를 위한 옵션입니다.

`--diff`는 프로젝트와 버전이 따로 없으므로 실행별 하위 폴더가 아니라 베이스 디렉터리(현재 디렉터리, 또는 `--output-dir`)에 바로 보고서를 씁니다.

## 스캔이 끝날 때 출력하는 내용

`--generate-only`를 쓰면 CLI가 `Analysis Complete!` 뒤에 만든 파일 목록을 보여 줍니다. 요청한 파일이 만들어지지 않았으면 제목이 `Analysis finished with errors`로 바뀌고 빠진 파일을 알리는 경고가 나옵니다. 종료 코드는 0 그대로이므로, 판정하지 못한 스캔에서 파이프라인을 멈추려면 `--fail-on`을 쓰십시오. 소프트웨어를 측정한 스캔(AI 모델과 데이터셋 스캔은 제외)이면 이어서 결과에 무엇이 들었는지 알려 줍니다.

```
  Components:  176 identified (purl on 100%, license declared on 96% (169 of 176))
```

숫자는 스캔 자체의 적합성 측정에서 가져오므로 적합성 검사 보고서의 `licenseCoverage`, `softwareComponentCount` 필드와 같고, purl 비율도 그 보고서의 purl 검사와 같은 패키지를 셉니다. purl 비율은 CycloneDX 결과에서만 나옵니다. 이상이 있으면 경고 줄이 뒤따릅니다.

- `No software was identified`: 결과에 컴포넌트가 없습니다. 스캔한 폴더에 지원하는 생태계의 매니페스트나 lock 파일이 있는지 확인합니다.
- `No component declares a license`: 라이선스를 선언한 컴포넌트가 없어서 라이선스 검사가 다룰 것이 없습니다.
- `Reduced analysis`: 전체 분석 대신 얕은 대체 분석이 돌아 직접 의존성만 식별했습니다. 원인(디스크 부족, 메모리 부족, 내려받기 실패, 의존성 분석기의 실패 또는 미실행)을 함께 보여 줍니다.
- `Steps that failed`: 끝내지 못한 후처리 단계의 이름입니다. 자세한 내용은 위쪽 로그에 있습니다.

마지막 두 줄은 이번 실행이 아니라 제출된 문서의 이력을 말하게 되므로 `--analyze`에서는 나오지 않습니다. 이 요약은 종료 코드를 바꾸지 않습니다. 이런 조건에서 실행을 실패시키려면 `--fail-on empty-result`나 `--fail-on license-coverage=<0-100>`을 씁니다. 요약을 지원하기 전의 스캐너 이미지는 파일 목록만 출력합니다.

## 종료 코드

| 코드 | 의미 |
|------|------|
| 0 | 스캔 성공 |
| 1 | 스캔 실패(잘못된 인자, Docker 미실행, 필수 입력 누락 등) |
| 2 | `--fail-on-conformance`: 스캔은 성공했지만 적합성 검사 보고서가 "fail" |
| 3 | `--fail-on-conformance`: 스캔은 성공했지만 판정할 적합성 검사 보고서가 안 만들어짐 |
| 4 | `--fail-on`: 스캔은 성공했지만 조건 하나 이상에 걸림 |
| 5 | `--fail-on`: 스캔은 성공했지만 조건을 판정할 수 없음(예: 취약점 데이터베이스를 내려받지 못함, `--license` 없이 `license-conflict`, 적합성 검사 보고서가 없거나 SBOM 형식을 측정하지 못했을 때의 `empty-result`와 `license-coverage=`), 또는 판정할 결과가 안 만들어짐 |

2부터 5까지는 해당 옵션을 줬을 때만 나오며, 둘 다 쓰지 않은 스캔은 0 또는 1로 끝납니다. `--fail-on` 조건은 각각 판정 결과와 함께 출력합니다. 둘 이상의 코드가 해당하면 작은 쪽이 우선합니다. 적합성(2, 3)이 4보다, 조건에 걸림(4)이 판정 불가(5)보다 먼저입니다. 판정 불가를 실패로 처리하는 것은 의도한 동작입니다. 살펴보지 못한 스캔은 아무것도 발견하지 못한 스캔과 다르므로, 취약점 데이터베이스가 없는 폐쇄망 실행이 `vulnerability=` 게이트를 우연히 통과하는 일이 없습니다.

## 특정 버전의 스캐너 이미지 사용

스캐너 이미지는 `SBOM_SCANNER_IMAGE` 환경변수로 재정의합니다.

```bash
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/bomlens:<version>" \
  ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only
```

## 트러블슈팅

### Windows: 산출물이 생기지 않음

스캔이 끝났는데 산출물 파일이 PC에 보이지 않으면, 실행 폴더가 Docker 파일 공유에 포함된 경로인지 확인하세요. 홈 디렉터리(`C:\Users\...`) 아래는 Rancher Desktop과 Docker Desktop 모두 기본 공유되므로 안전합니다. 공유되지 않은 위치에서 실행하면 컨테이너가 결과를 호스트에 쓰지 못합니다.

### Docker 권한 오류 (Linux/WSL2)

```
Got permission denied while trying to connect to the Docker daemon
```

Rancher Desktop이나 Docker Desktop을 쓰는 Windows/macOS에는 해당하지 않습니다. 현재 사용자를 `docker` 그룹에 추가합니다.

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### 디스크 공간 부족

```
no space left on device
```

Docker 캐시를 정리합니다. 터미널이 있다면:

```bash
docker system prune -f
```

Rancher Desktop이나 Docker Desktop을 쓴다면 앱의 설정(Preferences) 화면에서도 같은 정리를 할 수 있습니다.

### 소스 트리에 남은 중단된 빌드 산출물

소스 스캔(`--target <디렉터리>`, 웹 UI의 폴더 스캔, 데스크톱 앱)은 스캔한 트리에 빌드 단계(`cargo generate-lockfile`, `go mod tidy`, `npm install` 등)를 실행한 뒤 원래 상태로 되돌립니다 - 빌드 단계가 바꾸거나 새로 만든 파일은 모두 복원되거나 지워집니다. 그 스캔이 강제 종료, 메모리 부족 종료, 호스트 크래시로 끝나면 이 복원이 실행되지 못해 변경 사항이 그대로 남습니다. 같은 소스 트리를 다시 스캔하면, 이전 스캔의 컨테이너가 더는 실행 중이지 않은 것을 확인한 뒤 다른 무엇보다 먼저 그 복원부터 마칩니다.

### 재스캔 시 출력 폴더에 남은 산출물

같은 `--project`/`--version`으로 다시 스캔하면 이전 스캔이 어떻게 끝났든 같은 출력 폴더를 재사용합니다. 새 스캔은 자신의 산출물을 쓰기 전에, 오늘의 모드나 옵션으로는 만들지 않을 BomLens 자신의 파일을 먼저 지웁니다. 그래서 옵션이 달랐던 이전 실행의 산출물이 이번 실행의 결과로 착각될 일이 없습니다. 직접 폴더에 둔 파일이나 다른 버전의 산출물은 그대로 남습니다.

### 그 밖의 문제

1. 같은 명령을 다시 실행하고 터미널 출력을 읽습니다. `[WARN]`과 `[ERROR]` 줄에 건너뛴 것과 실패한 것이 적혀 있습니다.
2. Docker 이미지를 최신 버전으로 업데이트합니다: `docker pull ghcr.io/sktelecom/bomlens:latest`
3. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/bomlens/issues/new?template=bug_report.yml)에 실행한 명령과 터미널 출력을 첨부해 제보해 주세요. 이슈 양식에 필요한 항목이 안내되어 있습니다.

모드별 사용법은 [입력 시나리오 가이드](../guides/by-input.ko.md), 산출물 종류는 [산출물 레퍼런스](artifacts.ko.md), 언어 감지는 [지원 생태계](ecosystems.ko.md), 파이프라인에서 실행하는 방법은 [CI/CD 연동](../guides/ci-cd.ko.md)을 참고하세요.
