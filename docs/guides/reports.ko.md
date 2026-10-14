---
description: BomLens로 SBOM에서 오픈소스 고지문(NOTICE), 보안 취약점 보고서, 관련 산출물을 생성하는 방법을 다룹니다.
---

# 고지문·보안·위험 보고서 생성

BomLens는 SBOM 생성에 더해 오픈소스 고지문(NOTICE)과 보안 취약점 보고서를 한 번에 만듭니다. 이 문서는 그 산출물을 생성하는 방법을 다룹니다. 읽고 해석하는 방법은 [보고서 읽는 법](../concepts/reports-explained.ko.md)을 참고하세요.

## Quickstart (5분)

처음이라면 이것만 따라 하면 됩니다. Docker 엔진이 실행 중인 상태에서 SBOM과 고지문, 보안보고서를 한 번에 만듭니다. 브라우저로도, CLI로도 됩니다.

### 브라우저 UI (명령어 불필요)

UI를 실행하고 프로젝트 이름과 버전을 입력한 뒤 스캔 대상을 골라 실행하면, 고지문과 보안보고서를 내려받을 수 있습니다.

```bash
./scripts/scan-sbom.sh --ui     # http://localhost:8080 (포트 충돌 시 UI_PORT=9090 ./scripts/scan-sbom.sh --ui)
#   Windows: scripts\sbom-ui.bat 더블클릭
```

### CLI

스캔할 프로젝트 폴더에서 실행합니다.

```bash
cd /path/to/your-project
/path/to/bomlens/scripts/scan-sbom.sh --project MyApp --version 1.0.0 --all --generate-only
```

Windows에서는 `scripts\scan-sbom.bat`(Git Bash)를 쓰거나 WSL2에서 그대로 실행합니다. 설치는 [시작하기](../start/first-scan.ko.md)를 참고하세요.

끝나면 `MyApp_1.0.0/MyApp_1.0.0_NOTICE.html`과 `MyApp_1.0.0/MyApp_1.0.0_security.html`을 브라우저로 열어 결과를 바로 확인하세요. 실행 한 번의 산출물은 `MyApp_1.0.0/` 하위 폴더에 함께 생깁니다. 더 자세한 옵션은 아래를 참고하세요.

---

## 사전 준비

- Docker 엔진 20.10 이상. 무료로는 WSL2 + docker-ce나 Rancher Desktop을 쓰면 되고, Docker Desktop은 조직 사용 시 유료입니다.
- 스캐너 이미지 pull:
  ```bash
  docker pull ghcr.io/sktelecom/bomlens:latest   # 이전 이름 sbom-scanner 도 같은 이미지
  ```
- 모든 예시는 스캔할 프로젝트 루트에서 실행합니다.

> 옵션 플래그는 `--generate-only`(로컬 저장)와 함께 쓰는 것을 권장합니다. 외부 시스템(Dependency-Track 서버나 TRUSCA) 자동 업로드를 함께 쓰려면 생략하세요. 대상은 `UPLOAD_TARGET`으로 고릅니다.

---

## 한 번에 모두 생성하기 (`--all`)

`--all`은 `--notice --security --spdx`의 단축형입니다. SBOM과 고지문, 보안보고서, 그리고 SBOM의 SPDX 사본을 한 번의 스캔으로 만듭니다.

웹 UI와 데스크톱 앱에서는 고지문과 보안보고서가 새 스캔 화면의 생성 옵션이고, SPDX 사본은 스캔이 끝난 뒤 결과 화면에서 내보냅니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --all --generate-only
```

생성 파일, 명령을 실행한 위치 아래 `MyApp_1.0.0/` 하위 폴더에 함께 생깁니다([산출물 위치](../reference/cli.ko.md#산출물-위치) 참고):
```
MyApp_1.0.0_bom.json            # SBOM (CycloneDX 1.6)
MyApp_1.0.0_NOTICE.txt          # 고지문 (텍스트)
MyApp_1.0.0_NOTICE.html         # 고지문 (HTML)
MyApp_1.0.0_security.json       # 보안보고서 (Trivy 원본)
MyApp_1.0.0_security.md         # 보안보고서 (요약)
MyApp_1.0.0_security.html       # 보안보고서 (시각화)
MyApp_1.0.0_risk-report.md      # 오픈소스위험분석보고서 (요약)
MyApp_1.0.0_risk-report.html    # 오픈소스위험분석보고서 (시각화)
```

> 오픈소스위험분석보고서(`_risk-report`)는 모든 분석 모드에서 기본 생성됩니다(라이선스+취약점 집계, 대응 기한 포함). 생략하려면 `--no-report`를 쓰세요. 7가지 입력 형태별 처리는 [시나리오별 가이드](by-input.ko.md)를 참고하세요.

산출물 종류 전체 목록은 [산출물 레퍼런스](../reference/artifacts.ko.md)를, 웹 UI로 만들려면 [웹 UI](../reference/ui.ko.md)를 참고하세요.

---

## 오픈소스 고지문 (`--notice`)

SBOM의 `components[].licenses` 정보를 모아 라이선스별로 컴포넌트를 묶은 고지문을 생성합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --generate-only
```

- `_NOTICE.txt` — 배포물에 동봉하기 좋은 표준 텍스트.
- `_NOTICE.html` — 브라우저로 보기 좋은 형식. 모든 패키지 메타데이터는 HTML escape되어 안전합니다.
- 라이선스 정보가 없는 컴포넌트는 `NOASSERTION`으로 분류됩니다.

라이선스 정규화와 전문 번들 동작은 [보고서 읽는 법](../concepts/reports-explained.ko.md)을 참고하세요.

예시(텍스트):
```
License: Apache-2.0
Components (1):
  - requests@2.31
```

---

## 보안 취약점 보고서 (`--security`)

생성된 SBOM을 Trivy로 스캔해 알려진 취약점(CVE)을 보고합니다. (NVD + OSV + GHSA DB)

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --security --generate-only
```

- `_security.json` — Trivy 원본 JSON. CI나 기계 처리용.
- `_security.md` — severity별 집계 표와 CVE 목록. PR/이슈에 붙이기 좋습니다.
- `_security.html` — severity 배지와 표가 포함된 시각적 보고서.

보고서는 취약점이 있어도 스캔을 실패시키지 않습니다(report-only). 게이트가 필요하면 `_security.json`을 후처리하세요.

Trivy는 컴포넌트를 패키지 PURL로 대조합니다. 펌웨어, 루트 파일 시스템, 바이너리 스캔에서는 패키지 PURL이 없고(PURL이 없거나 `pkg:generic`이거나 `pkg:github`처럼 소스 저장소를 가리키는 경우) CPE가 있는 컴포넌트를 이미지에 들어 있는 NVD CPE 인덱스와도 대조하고, 찾은 CVE를 같은 보고서에 합칩니다. 패키지 데이터베이스가 없는 임베디드 루트 파일 시스템에서 버전 문자열로 식별한 OpenSSL이나 BusyBox 같은 바이너리가 여기에 해당합니다. 인덱스는 오프라인에서 동작합니다.

어떤 검사도 닿지 못한 컴포넌트는 취약점이 없는 것으로 세지 않습니다. 버전이 없거나, 패키지 PURL도 대조한 CPE도 없는 컴포넌트가 있으면 보고서는 "No known vulnerabilities found" 대신 그 개수를 알리고 "Components that could not be checked" 아래에 목록을 보여 줍니다. `_security.json`에도 같은 목록이 `UncheckedComponents`(`Count`, 그리고 `Name`, `Version`, `PURL`, `Reason`을 담은 `Components`. `Reason`은 `no-version` 또는 `no-identifier`)로 남고, 위험 보고서의 취약점 절에도 같은 내용이 나옵니다.

심각도, CVSS, EPSS, KEV 우선순위 신호와 후속 조치 해석은 [보고서 읽는 법](../concepts/reports-explained.ko.md)을 참고하세요.

---

## 정밀 CVE 대조 (`--deep-cve`)

Trivy는 패키지 식별자(PURL) 기준으로 취약점을 대조하므로 생태계 보안 권고 데이터베이스는 잘 다룹니다. 하지만 오래된 Java 라이브러리의 일부 CVE는 NVD에만 CPE 식별자로 기록되어 있어 PURL 기반 스캔으로는 닿지 않습니다. `--deep-cve`는 두 번째 대조를 더합니다. BomLens가 각 Maven 컴포넌트의 groupId로부터 NVD 대조가 가능한 CPE를 만들어 주고(이 보강 단계는 Maven이 대상입니다), grype는 생태계와 무관하게 컴포넌트가 가진 CPE 전부를 내장 NVD 데이터베이스와 대조합니다. 실제로 추가되는 결과 대부분은 여전히 Maven인데, SBOM에 없던 CPE를 보강이 새로 붙여 주는 대상이 Maven이기 때문입니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --deep-cve --generate-only
```

- `--deep-cve`는 `--security`를 자동으로 켭니다. 추가로 찾은 결과는 같은 보안 보고서(`_security.json/.md/.html`)에 `nvd:cpe` 출처 표시와 함께 합쳐집니다.
- 스캔은 grype와 데이터베이스를 내장한 opt-in 이미지 `ghcr.io/sktelecom/bomlens-deep-cve:latest`로 실행되며, 플래그를 켜면 자동으로 내려받습니다(`SBOM_DEEP_CVE_IMAGE`로 지정 가능). 기본 이미지 모드(소스, 이미지, 바이너리, rootfs, SBOM 분석)에 적용되고, 펌웨어와 AI 모델 스캔은 매칭할 패키지 purl도 확장할 보안 보고서도 없어 경고를 출력한 뒤 grype 없이 진행합니다. 소스 스캔은 보안 보고서를 만드는 후처리 단계를 deep-cve 이미지로 실행합니다. 이 이미지를 내려받을 수 없으면(오프라인이거나 `SBOM_PULL=never`) grype 대조 없이 스캔을 이어 가고, 그 사실을 알리며, `bomlens-result.json`에 `deep-cve` 단계를 건너뜀(skipped)으로 기록합니다. `SBOM_SCANNER_IMAGE`가 레지스트리 경로 없는 로컬 빌드(`bomlens:dev`)이거나 1.13.2보다 낮은 버전 또는 BomLens 이름이 아닌 이미지이고 `SBOM_DEEP_CVE_IMAGE`를 지정하지 않았을 때도 같습니다. 같은 빌드의 deep-cve 이미지를 알 수 없으므로 후처리는 지정한 이미지에서 그대로 실행됩니다. 그 이미지에 grype가 있으면(`SBOM_DEEP_CVE=true`로 빌드) 그곳에서 대조를 실행하고 실제 결과대로 기록합니다. deep-cve 이미지에는 scancode가 없으므로, `--deep-license`도 켜면 라이선스 탐지를 먼저 deep-license 이미지에서 실행한 뒤 후처리 단계를 deep-cve 이미지로 실행합니다. 그래서 `_scancode.json`과 `_security_grype.json`이 모두 만들어집니다. 웹 UI도 deep-license 이미지에서 실행 중이면 같은 방식으로 처리합니다. opt-in 이미지는 처음 쓸 때 한 번 내려받으며 docker의 진행 상황을 보여 줍니다. 2분 동안 아무 출력이 없으면 내려받기를 멈추고 그 이미지 없이 스캔을 이어 갑니다.
- 웹 UI(와 데스크톱 앱)에서는 같은 옵션이 스캔 옵션의 **심층 CVE 매칭 (NVD CPE)** 토글입니다. 기본 이미지를 쓰는 모든 스캔 모드(소스, Docker 이미지, rootfs, 패키지 업로드, SBOM 업로드)에서 나타나고, CLI와 마찬가지로 펌웨어와 AI 모델 스캔에서만 숨겨집니다. 켜면 보안 보고서도 함께 켜지고, deep-cve 이미지는 처음 쓸 때 한 번 내려받습니다. UI 자체가 그 이미지에서 실행 중이면 곁들임 컨테이너 없이 바로 처리합니다.
- CPE 대조는 PURL 대조보다 느슨합니다. NVD의 버전 범위가 대략적으로 기록된 경우가 있기 때문입니다. 기본값은 오프라인 동작이라 그런 결과를 버리지 않고 보고서에 **버전 미검증**으로 표시합니다(단검 기호와 각주). 어느 행이 느슨한 버전 대조로 인한 오탐일 수 있는지 읽는 사람이 알 수 있습니다. 더 조이려면 `NVD_API_KEY`와 함께 `SECURITY_NVD_VERIFY=true`를 설정하세요. 각 결과를 NVD 실시간 버전 범위와 대조해 범위 밖 오탐을 걸러냅니다. 이 검증은 네트워크가 필요하고 수 분이 더 걸립니다.
- OS 패키지(rootfs나 이미지 스캔)는 컴포넌트의 `cpe`가 업스트림 버전만 담고, 배포판 자체의 패치 리비전(Debian의 `+deb12u3`, RPM의 `.el9`, Alpine의 `-r0` 등)은 `purl`과 `version`에만 남습니다. 배포판이 이미 백포트로 고친 CVE라도 CPE의 업스트림 버전은 그대로라서, `--deep-cve` 대조가 NVD 버전 범위만 보고 여전히 취약하다고 표시할 수 있습니다. PURL과 OS 컨텍스트로 대조하는 위의 기본 보안 보고서가 배포판 자체의 보안 권고 상태를 이미 반영하므로, OS 패키지의 실제 취약점 여부는 그쪽을 신뢰하세요. OS 패키지에 대한 `--deep-cve` 결과는 버전 미검증 결과와 같은 방식으로, 최종 판정이 아니라 확인해 볼 단서로 읽으면 됩니다.

```bash
SECURITY_NVD_VERIFY=true NVD_API_KEY="your-key" \
  ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --deep-cve --generate-only
```

---

## Go 도달성 (`--reachability`)

Go 모듈의 취약점은 프로그램이 영향받는 코드를 실제로 쓸 때만 문제가 됩니다. `--reachability`는 Go 프로젝트가 직접 만든 점검 도구인 govulncheck에게, 스캔한 Go 프로그램이 어느 보안 권고의 코드에 실제로 도달하는지 묻습니다. 소스 트리는 프로그램의 진입점부터 호출 그래프를 따라가고, Go 실행 파일(`--target ./app`)은 실행 파일의 심볼에서 영향받는 함수를 찾습니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --reachability --generate-only
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./app --reachability --generate-only
```

- SBOM의 컴포넌트에 해당하는 Go 보안 권고마다 CycloneDX VEX 문서인 `_reachability.cdx.json`에 판정이 남습니다. 영향받는 코드에 도달하지 않으면 `analysis.state`는 `not_affected`이고, `analysis.detail`에 이유를 적습니다. 영향받는 패키지가 빌드에 없으면 `justification`은 `code_not_present`, 패키지는 있지만 영향받는 함수를 호출하지 않거나(소스) 링크하지 않았으면(실행 파일) `code_not_reachable`입니다. 도달하면 상태는 `exploitable`이고 detail에 호출 경로나 심볼을 적습니다.
- 보안 보고서는 도달하지 않는 발견 항목을 이유와 함께 별도 절에 싣고 집계에서 뺍니다. 숨기지는 않습니다. 발견 항목은 `_security.json`에 그대로 있고 각각 `bomlens:reachability` 표시가 붙습니다. 도달하는 발견 항목은 발견 표에 이중 단검 기호로 표시합니다. 위험 보고서와 `--fail-on vulnerability=`도 보안 보고서와 같은 방식으로 셉니다.
- `--reachability`는 `--security`를 자동으로 켭니다. Go 소스와 Go 실행 파일에 적용되고, 다른 스캔은 경고를 출력한 뒤 이 옵션 없이 진행합니다. 소스 스캔은 Go 툴체인이 있는 1단계의 Go 이미지 안에서 govulncheck를 실행합니다. 후처리 이미지에는 govulncheck 실행 파일만 들어 있습니다.
- govulncheck는 Go 취약점 데이터베이스(vuln.go.dev)를 네트워크로 읽습니다. 닿지 않으면 `bomlens-result.json`에 이 단계를 건너뜀(`unavailable`)으로 기록하고, 보안 보고서는 이 옵션이 없을 때와 같습니다.
- govulncheck가 볼 수 있는 코드만 판정합니다. 리플렉션이나 플러그인으로 부르는 함수는 호출 그래프에 나타나지 않고, 실행 파일의 심볼은 무엇이 링크됐는지를 보여 줄 뿐 무엇이 실행되는지는 보여 주지 않습니다. `not_affected`는 도구의 판정으로 읽고, 호출 그래프가 보여 주지 않는 방식으로 코드를 불러오는 곳이라면 해당 권고를 열어 두세요.

## 정밀 라이선스 탐지 (`--deep-license`)

기본 고지문은 의존성(3rd-party)의 라이선스를 다룹니다. `--deep-license`는 scancode-toolkit으로 프로젝트 자체 소스코드(1st-party)의 라이선스 헤더까지 탐지합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --deep-license --generate-only
```

scancode는 무겁고 느려서(대형 저장소는 수 분에서 수십 분) 기본 이미지에는 넣지 않았습니다. CLI는 이 옵션을 켜면 소스 스캔의 후처리 단계를 opt-in 이미지 `ghcr.io/sktelecom/bomlens-deep-license:latest`로 실행하며, 이미지는 자동으로 내려받습니다(`SBOM_DEEP_LICENSE_IMAGE`로 지정 가능). 웹 UI에서는 정밀 라이선스 탐지가 생성 옵션 중 하나이며, UI 자체를 이 이미지로 실행해야 합니다.

> ```bash
> SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens-deep-license:latest ./scripts/scan-sbom.sh --ui
> ```

프로젝트 자체 파일만 검사합니다. 의존성 폴더(`node_modules`, `vendor`, 가상 환경), 빌드 결과물, 도구 폴더는 라이선스를 패키지 관리자에서 얻으므로 제외합니다. 검사 대상 파일이 20,000개를 넘는 트리는 검사하지 않고, scancode는 600초가 지나면 멈춥니다. 한도는 `DEEP_LICENSE_MAX_FILES`와 `DEEP_LICENSE_TIMEOUT`으로 바꿀 수 있습니다([Docker 이미지 환경 변수](../reference/docker-image.ko.md#환경-변수)). 어느 경우든 로그와 실행 [결과 매니페스트](../reference/engine-contract.ko.md)에 남습니다.

추가 산출물: `MyApp_1.0.0_scancode.json`

---

## 배포 라이선스 충돌 (`--license`)

프로젝트를 배포하는 라이선스를 선언해, 각 의존성을 그 기준으로 판정하게 합니다. 소스 스캔으로는 알아낼 수 없는 값이라(cdxgen이 maven과 gradle에서 루트 라이선스를 비워 둡니다) 지정하지 않으면 판정하지 않습니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --license Apache-2.0 --all --generate-only
```

선언한 값은 SBOM 루트 컴포넌트에 기록되고, 위험분석보고서에 충돌 절이 생깁니다. SBOM에 이미 있는 루트 라이선스(공급사가 선언한 값)는 덮어쓰지 않습니다. 판정을 읽는 방법은 [보고서 읽는 법](../concepts/reports-explained.ko.md#배포-라이선스-충돌)을 참고하세요.

---

## 결정론적 출력 (`--byte-stable`)

같은 입력이면 항상 동일한 바이트의 SBOM을 생성합니다. CI에서 의미 없는 diff(타임스탬프, 랜덤 ID, 정렬 차이)를 제거하고 재현성을 확보합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --byte-stable --generate-only
```

적용 내용: `metadata.timestamp`를 `1970-01-01T00:00:00Z`로 고정, 랜덤 `serialNumber` 제거, `components`를 purl 기준 정렬, 키 정렬.

---

## SBOM 서명 (`--sign`)

cosign으로 SBOM에 detached 서명을 만들어 공급망 신뢰를 확보합니다. 오프라인 키 기반 서명(`--tlog-upload=false`)이라 네트워크나 OIDC가 필요 없습니다.

```bash
# 1) 키 생성 (최초 1회). 무비밀번호 키는 COSIGN_PASSWORD="" 로 생성
docker run --rm -v "$PWD":/keys -w /keys -e COSIGN_PASSWORD="" \
  --entrypoint cosign ghcr.io/sktelecom/bomlens:latest generate-key-pair

# 2) 서명하며 스캔 (COSIGN_KEY=개인키 경로, COSIGN_PASSWORD=키 비밀번호)
COSIGN_KEY="$PWD/cosign.key" COSIGN_PASSWORD="" \
  ./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --sign --generate-only

# 3) 검증
docker run --rm -v "$PWD":/w -w /w --entrypoint cosign \
  ghcr.io/sktelecom/bomlens:latest \
  verify-blob --key cosign.pub --signature MyApp_1.0.0_bom.json.sig \
  --insecure-ignore-tlog MyApp_1.0.0_bom.json
```

개인키는 컨테이너에 읽기 전용으로 마운트됩니다. 추가 산출물: `MyApp_1.0.0_bom.json.sig`

---

## 트러블슈팅

| 증상 | 원인 / 해결 |
|------|------------|
| `trivy not installed ... skipping` | 구버전 이미지. `docker pull`로 최신 이미지를 받으세요. |
| `--deep-license requested but scancode not in image` | `bomlens-deep-license` 이미지로 실행하세요(`SBOM_SCANNER_IMAGE`에 BomLens 이미지가 아닌 이름, 레지스트리 경로가 없는 짧은 로컬 이름, 1.13.2보다 낮은 버전을 지정하지 않았다면 소스 스캔은 CLI가 자동으로 고릅니다). 직접 빌드하려면 `--build-arg SBOM_DEEP_LICENSE=true`를 쓰세요. |
| UI에서 `Docker is not running` | Docker 엔진(Rancher Desktop/Docker Desktop 등)을 시작한 뒤 다시 실행하세요. |
| 고지문에 `NOASSERTION`이 많음 | 의존성에 라이선스 메타데이터가 없는 경우입니다. `--deep-license`로 보완하거나 수동 확인하세요. |
| 포트 충돌(`--ui`) | `UI_PORT`로 다른 포트를 지정하세요. |
