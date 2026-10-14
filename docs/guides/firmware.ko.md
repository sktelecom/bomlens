---
description: 네트워크 장비 펌웨어 바이너리(.bin, squashfs 등)를 언패킹해 구성요소를 식별하고 SBOM과 라이선스, 취약점을 점검하는 BomLens 펌웨어 분석 방법.
---

# 펌웨어 분석 가이드

네트워크 장비 펌웨어 바이너리(`.bin`, `.img`, squashfs 등)에서 구성요소를 식별하고 SBOM과 라이선스, 취약점을 점검하는 방법을 설명합니다. 협력사에서 받은 펌웨어처럼 소스 없이 바이너리만 있을 때 씁니다.

## 동작 방식

펌웨어는 운영체제와 라이브러리 수십 개가 통째로 압축·밀봉된 파일입니다. 그래서 펌웨어 파일을 그대로 일반 스캔에 넣으면 거의 검출하지 못하고 빈 SBOM이 나옵니다. 펌웨어 분석은 먼저 압축을 풀어 내용물을 꺼낸 뒤 구성요소를 식별합니다.

1. 언팩(unblob, 폴백으로 `unsquashfs`·`7z`·`binwalk`)으로 펌웨어를 풀어 rootfs를 추출합니다.
2. `syft`로 패키지 매니저(opkg, dpkg, apk, rpm)가 설치한 구성요소를 식별합니다. 하나의 이미지가 파일시스템을 여럿 담을 수 있고, rootfs 안이 아니라 옆에 놓인 트리도 함께 식별합니다. 세 가지를 알아보며, 판정 근거는 디렉터리 이름이 아니라 그 안에 무엇이 설치돼 있는지를 적은 기록입니다. 첫째는 컨테이너 이미지 저장소로 Docker가 남기는 이미지 색인으로 알아봅니다(스위치 운영체제에서 흔한 구조로, 실제로 동작하는 것 대부분이 컨테이너 안에 있습니다). 둘째는 자체 패키지 데이터베이스를 가진 또 하나의 파일시스템입니다. 셋째는 Python `site-packages`처럼 인터프리터가 설치한 라이브러리 묶음입니다. rootfs만 읽으려면 `FW_EXTRA_ROOTS=false`로 둡니다. 컨테이너 저장소에서 나온 구성요소에는 어느 컨테이너 이미지에서 나왔는지가 `bomlens:container:image` 속성으로 남고, 이미지 자체도 `container` 구성요소로 들어갑니다. 컨테이너 안에서 `dpkg`로 설치된 패키지는 그 컨테이너가 어떤 배포판을 쓰는지를 자기 계층의 `os-release`에서 읽어 식별하며, 그래야 취약점 단계에서 대조할 대상이 생깁니다. 이렇게 식별한 것에는 `bomlens:purlSource` 속성이 붙습니다. SPDX로 내보내도 이 내용이 남습니다. 이미지와 배포판은 SPDX 패키지가 되고, 소속은 `CONTAINS` 관계로 들어갑니다.
3. `cve-bin-tool`의 시그니처 검사기로 stripped 정적 바이너리(busybox, openssl, dropbear 등)를 식별하고 CPE를 붙입니다.
4. 두 결과를 하나의 SBOM으로 병합한 뒤, 일반 스캔과 동일한 후처리(라이선스, CVE, 서명)를 거칩니다. 패키지 PURL이 없는 컴포넌트의 CVE는 이미지에 들어 있는 NVD CPE 인덱스에서 찾습니다([CVE 대조 방식](#cve-대조-방식) 참고).

## 펌웨어 이미지 준비

펌웨어 분석에는 언팩과 바이너리 식별 도구(unblob, cve-bin-tool 등)가 들어 있는 별도 이미지가 필요합니다. 이 도구들은 GPL 계열이라 경량 기본 이미지에는 넣지 않고, opt-in 펌웨어 이미지로 분리되어 있습니다.

```bash
docker pull ghcr.io/sktelecom/bomlens-firmware:latest
```

기본값이 이 이미지이므로 별도 지정 없이 `--firmware`만 붙여도 받습니다. 다른 태그를 쓰려면 환경변수 `SBOM_FIRMWARE_IMAGE`로 지정합니다.

웹 UI와 데스크톱 앱에서는 이 명령을 직접 칠 필요가 없습니다. 펌웨어 입력에 내려받을 용량과 함께 받기 버튼이 나오고, 받는 동안 레이어 몇 개가 끝났는지 보여 줍니다. 받아 두지 않아도 첫 펌웨어 스캔에서 자동으로 받으므로, 차이는 기다리는 시점이 스캔 전인지 스캔 도중인지입니다.

## 실행하기

펌웨어 분석에는 위의 펌웨어 이미지가 필요합니다. 웹 UI든 CLI든 마찬가지입니다.

### 웹 UI에서

웹 UI를 평소처럼 띄우면 됩니다. 이 이미지를 따로 지정할 필요는 없습니다. Docker 엔진이 켜져
있으면 기본 UI 이미지가 Docker 소켓을 통해 위 펌웨어 이미지를 곁들임 컨테이너로 직접 띄우므로,
펌웨어 업로드 타일이 자동으로 나타납니다.

```bash
./scripts/scan-sbom.sh --ui
#   Windows: sbom-ui.bat을 그대로 더블클릭
```

다른 태그나 사내 미러 레지스트리를 쓰고 싶을 때만 `SBOM_FIRMWARE_IMAGE`로 지정하세요. 실제
환경변수를 설정했을 때만 적용되며, `.bat` 더블클릭이 읽는 설정 파일(`bomlens.settings.txt`)에는
이 항목이 없습니다.

```bash
SBOM_FIRMWARE_IMAGE=<사내 미러>:<태그> ./scripts/scan-sbom.sh --ui
```

프로젝트 이름과 버전을 입력하고, 펌웨어 업로드 타일을 골라 파일을 올린 뒤 스캔을 실행합니다.

### CLI에서

받은 펌웨어 파일을 `--target`에 넘기고 `--firmware`를 붙입니다.

```bash
./scripts/scan-sbom.sh --project device-fw --version 1.0.0 \
  --target "./device.bin" --firmware \
  --all --generate-only
```

- 인식 가능한 확장자(`.bin`, `.img`, `.squashfs`, `.sqsh`, `.ubi`, `.ubifs`, `.trx`, `.chk`, `.fw`, `.rom`, `.dlf`, `.bix`)는 `--firmware` 없이도 자동 감지되지만, 명시를 권장합니다.
- 산출물은 일반 스캔과 같은 3종입니다. 고지문(`_NOTICE`), SBOM(`_bom.json`), 위험분석보고서(`_risk-report`).
- 릴리스 폴더를 그대로 넘겨도 됩니다. `--target`이 최상위에 매니페스트나 빌드 파일이 없는 폴더이고, 바로 아래에 펌웨어 이미지나 압축을 푼 루트 파일시스템을 하나만 담고 있으면(예: `rootfs/`, `install/`, 커널, 이미지 파일이 함께 있는 `images/`) 그 이미지나 루트 파일시스템을 분석하고 무엇을 골랐는지 출력합니다. 펌웨어 이미지는 펌웨어나 파일시스템 시그니처, 또는 펌웨어에 쓰는 확장자(`.bix`, `.trx`, `.chk`, `.dlf`, `.ubi`, `.ubifs`, `.squashfs`, `.sqsh`, `.rom`, `.fw`, `.jffs2`, `.cramfs`)로 판단하며, `.bin`과 `.img`는 시그니처가 있어야 합니다. 최상위에 실행 파일, 공유 라이브러리, `.asar`, `node_modules`, 모델 가중치나 토크나이저 파일이 있거나 최상위 파일이 20개를 넘는 폴더는 소스로 분석합니다. 압축을 푼 데스크톱 앱, 모델 스냅샷, 빌드 결과 스테이징 폴더가 여기에 해당합니다. 여러 개가 있으면 스캔을 멈추고 각각에 쓸 `--target`을 보여 줍니다. 고른 루트 파일시스템에 패키지 데이터베이스가 없으면, 경고에 같은 폴더의 큰 파일(1 MiB 초과, 최대 5개)을 `--target "<파일>" --firmware` 명령으로 함께 보여 줍니다. 폴더 자체를 소스로 분석하려면 `--as-source`를 붙입니다.

## 결과 읽는 법

산출물은 다른 스캔과 같은 고지문, SBOM, 위험분석보고서입니다(일반적인 구성은 [보고서 읽는 법](../concepts/reports-explained.ko.md)과 [산출물 레퍼런스](../reference/artifacts.ko.md) 참고). 다만 펌웨어 SBOM을 읽기 전에 알아둘 점이 하나 있습니다. 일부 컴포넌트는 버전이 아예 없습니다. 바이너리의 버전 문자열이 빌드 과정에서 남지 않은 경우에도, BomLens는 그 라이브러리가 링크돼 있다는 사실만은 기록합니다. 문자열 매칭이 아니라 ELF의 SONAME·NEEDED 항목이라는 구조 자체에서 읽은 것이며, 이런 컴포넌트에는 `bomlens:evidenceGrade = presence-only` 속성이 붙습니다. 버전이 없다고 해서 스캔이 놓친 것이 아니라, 바이너리 자체에 읽을 버전이 없다는 뜻이며 컴포넌트 자체는 실재합니다. 라이선스 의무 판단에는 이것으로 충분하지만(어느 릴리스인지와 무관하게 그 라이브러리는 존재하므로), 버전 기반 CVE 매칭은 이 컴포넌트를 판단할 근거가 없습니다.

언패커는 이미지를 어디까지 열 수 있었는지도 함께 보고하며, BomLens는 이를 결과 옆에 기록합니다. 합계는 펌웨어 컴포넌트의 `bomlens:firmware:*` 속성(`input-bytes`, `recognized-regions`, `unknown-regions`, `unknown-bytes`, `unknown-top-level-percent`, `nested-unknown-regions`, `encrypted-regions`, `extraction-failed`, `extraction-failed-formats`, `missing-extractors`)으로 남고, 열지 못한 부분이 있으면 위험분석보고서에 "펌웨어 분석 범위" 절이 추가됩니다. 이 값은 스캔의 범위로 읽습니다. 식별하지 못한 영역, 암호화된 영역, 스캐너 이미지에 없는 추출 도구가 필요한 영역 안의 컴포넌트는 SBOM에 없으므로, 취약점이 0건이어도 그것은 열어 볼 수 있었던 범위에 대한 결과입니다. 식별하지 못한 비율과 바이트 수는 이미지 최상위 기준이고, 추출된 내용 안의 미식별 영역은 따로 셉니다. 이 절은 BomLens가 직접 실행한 스캔에만 쓰며, 검토용으로 제출받은 SBOM에는 쓰지 않습니다. 합계만 남기며, 언패커의 전체 보고서는 산출물 폴더에 쓰지 않습니다.

syft의 패키지 식별 단계가 실패해도 스캔은 멈추지 않습니다. syft 자체의 오류가 스캔 로그에 남고, SBOM에는 어느 단계가 실패했는지 `bomlens:pipeline-step-failed`로 기록됩니다(메인 rootfs는 `firmware-packages`, 압축 해제 중 함께 발견되는 별도 패키지 소스, 예를 들어 내장된 컨테이너 이미지 저장소나 독자적인 패키지 데이터베이스를 가진 파일시스템은 `firmware-extra-roots`). 예상보다 컴포넌트 수가 적으면 펌웨어에 실제로 그만큼만 있다고 단정하기 전에 스캔 로그에서 이 기록부터 확인하는 편이 좋습니다.

## upstream 저장소 purl

바이너리나 펌웨어의 패키지 데이터베이스에서 읽은 컴포넌트에는 purl이 없거나, `pkg:generic` 또는 `pkg:opkg` purl이 붙습니다. 어느 것도 프로젝트를 가리키지 않으므로, purl로 컴포넌트를 조회하는 도구는 이름과 버전이 맞아도 그 컴포넌트를 식별하지 못합니다. 펌웨어, 루트 파일시스템, 바이너리 스캔에서 BomLens는 프로젝트의 upstream 소스 저장소와 릴리스 태그로 purl을 붙입니다. 예를 들어 `pkg:github/mirror/busybox@1_22_1`, `pkg:github/gregkh/linux@v3.10.18`, `pkg:sourceforge/boa@0.94.13`, `pkg:gnu/readline@5.2`입니다.

변환에는 저장소와 태그 표기를 확인한 프로젝트만 담은 변환표(`docker/lib/upstream-purl-map.json`)를 씁니다. BusyBox, curl, OpenSSL 1.x, OpenSSH, Linux, zlib, U-Boot, Net-SNMP, ncurses, net-tools, libxml2, SQLite, glibc, Dropbear, Mbed TLS, Python, Boa, readline이 들어 있습니다. 컴포넌트는 이름이나 CPE로 찾고, 변환표가 다루는 형식의 버전이 있을 때만 바꿉니다. 이때 `-1` 같은 패키지 재빌드 번호와 커널 빌드 해시는 먼저 떼고, `5.4.0`처럼 적힌 Linux와 glibc의 기본 릴리스는 `5.4`의 태그로 바꿉니다. 변환표에 없는 컴포넌트는 원래 식별자를 그대로 둡니다. 저장소나 태그를 추측하면 다른 버전을 가리키게 되기 때문입니다. 버전, CPE, 식별 근거는 바꾸지 않으므로 이를 근거로 찾은 CVE도 보고서에 그대로 남습니다. 새 purl에는 `bomlens:purlSource = upstream-map`이 붙고, 바꾸기 전 purl은 `bomlens:originalPurl`에 남습니다. 끄려면 `ENRICH_UPSTREAM_PURL=false`를 설정합니다.

## 스캔이 읽지 못한 버전 채우기

`presence-only` 컴포넌트에는 버전이 없어 CVE 조회에도 purl 조회에도 쓸 수 없습니다. 펌웨어, 루트 파일시스템, 바이너리 스캔은 이런 컴포넌트를 콘솔에 보여 주고 `<Project>_<Version>_component-versions.template.csv` 파일로 씁니다. 각 이름 뒤에 제품에 들어간 버전을 적고 그 파일을 다시 넘깁니다.

```bash
./scripts/scan-sbom.sh --project device-fw --version 1.0.0 \
  --target "./device.bin" --firmware \
  --component-versions device-fw_1.0.0_component-versions.template.csv --generate-only
```

파일은 `name,version` 두 열로 된 CSV입니다. `#`으로 시작하는 줄과 버전을 비워 둔 행은 건너뜁니다. 양식 파일은 그 자리에서 채워도 됩니다. 넘긴 파일이 그 양식이면 스캔은 적은 내용을 그대로 두고, 아직 빠진 항목만 알려 줍니다. 채운 버전에는 `bomlens:versionSource = supplier-declared`가 붙고, 위의 upstream purl도 붙습니다. 스캔이 배포 파일에서 버전을 읽었다면 그 버전을 유지하고 두 값을 경고로 보여 줍니다. 소스 트리에는 한 프로젝트의 여러 릴리스가 함께 있을 수 있고, 실제로 들어간 것은 바이너리가 보여 주기 때문입니다. 스캔이 찾지 못한 이름은 `bomlens:identifiedBy = supplier-declared` 컴포넌트로 추가합니다. 256 KiB를 넘는 파일, 두 열이 아닌 행, 영문자와 숫자와 `. _ + ~ -` 밖의 문자가 든 이름이나 버전, 한 이름에 두 버전을 적은 파일은 줄 번호와 함께 거부합니다. 이때 SBOM과 다른 파일은 그 파일의 버전 없이 쓰고, 스캔은 1로 끝납니다. 버전이 `UNKNOWN`인 컴포넌트(메타데이터에 버전이 없는 커널 모듈)는 버전이 없는 것으로 보고 양식에 넣습니다. 이름에 공백 같은 다른 문자가 든 컴포넌트는 양식 대신 콘솔에 따로 보여 줍니다.

## CVE 대조 방식

Trivy는 컴포넌트를 패키지 PURL로 대조하며, 다른 스캔과 마찬가지로 스캔할 때 데이터베이스를 내려받습니다. 패키지 PURL이 없는 컴포넌트(PURL이 없거나 `pkg:generic`, `pkg:opkg`, 또는 `pkg:github`처럼 소스 저장소를 가리키는 경우)는 CPE를 이미지에 들어 있는 NVD CPE 인덱스(`cpe_match.sqlite`)와 대조하고, 찾은 CVE를 같은 보안 보고서에 합칩니다. 이 대조는 펌웨어, 루트 파일시스템, 바이너리 스캔에서 `--security`를 켰을 때 CPE를 붙이는 단계가 모두 끝난 뒤 한 번 실행됩니다. 그래서 시그니처 검사기가 CPE를 붙인 컴포넌트뿐 아니라, BomLens가 관리하는 이름별 CPE 목록(`cpe-name-map.json`)으로 이름과 버전에서 CPE를 얻은 컴포넌트(예: OpenSSH, BusyBox)도 대조합니다. 결과 매니페스트에는 이 단계가 `match-cpe`로 남고 `offered`, `components`, `cves` 개수가 함께 기록됩니다.

인덱스는 이미지를 빌드할 때 NVD 데이터에서 추려 만들므로, 대조에는 네트워크도 NVD API 키도 필요 없고 데이터는 이미지를 빌드한 시점 기준입니다. 최신 데이터가 필요하면 새 이미지를 받습니다. cve-bin-tool은 바이너리 식별에만 쓰며, 취약점 데이터베이스를 내려받거나 읽지 않습니다. `CVE_BIN_TOOL_MODE=components-only`로 두면 식별은 그대로 하고 CPE 대조만 끕니다. `--build-arg SBOM_CPE_INDEX=false`로 빌드한 이미지에는 인덱스가 없으며, 이때 이 단계는 `skipped`(`not_installed`)로 기록됩니다.

버전이 없거나, 패키지 PURL이 없고 인덱스에 대조한 CPE도 없는 컴포넌트는 보안 보고서의 "Components that could not be checked" 목록(`_security.json`의 `UncheckedComponents`)에 나옵니다. 따라서 취약점 표에 항목이 적어도, 그 결과는 대조할 수 있었던 컴포넌트에 대한 것입니다.

스캔은 "This product uses NVD data but is not endorsed or certified by the NVD." 고지를 출력하고, 데이터 출처 고지는 이미지의 `/opt/cve-bin-tool-home/CVE-DATA-NOTICE.txt`에 들어 있습니다. OSV(Open Source Vulnerabilities) 권고는 재배포 이미지에 share-alike 데이터를 넣지 않으려고 번들하지 않습니다.

## 라이선스 주의

펌웨어 이미지에는 GPL 도구(cve-bin-tool, sasquatch, unblob이 의존하는 일부 extractor)가 들어 있습니다. 셸 스크립트는 이 도구들을 별도 프로세스로 호출만 하므로 copyleft가 이 저장소의 코드로 전파되지는 않습니다. 다만 GPL 바이너리를 이미지에 담아 재배포하므로, 라이선스 텍스트 동봉과 소스 오퍼 의무는 그대로 적용됩니다. 상세 인벤토리는 [번들 도구 라이선스](https://github.com/sktelecom/bomlens/blob/main/THIRD_PARTY_LICENSES.ko.md)를 참고하세요. GPL 분석 도구는 이 펌웨어 이미지에만 들어갑니다. 다만 기본 이미지를 포함한 모든 이미지는 Debian 기반이라 GPL 시스템 패키지를 함께 담고 있으며, 그 소스 안내도 같은 문서에 있습니다.

## 한계

- 오픈소스 도구 스택의 검출률은 약 60~85%이며, 펌웨어 종류와 strip 정도, 언팩 성공 여부에 크게 좌우됩니다.
- 함수 수준 바이너리 핑거프린팅이 없어서 strip되거나 인라인된 컴포넌트, 버전 문자열이 제거된 바이너리는 놓칩니다.
- 정적 링크 라이브러리와 벤더가 변형한 squashfs, 암호화·서명된 펌웨어, 사명을 바꾼 라이브러리는 검출하지 못하거나 부정확합니다.
- 결과 SBOM은 완전하지 않은 근사 추정이므로, 법적 라이선스 컴플라이언스의 단일 근거로 사용하지 마세요.

---

> **관련 문서**: [시작하기](../start/first-scan.ko.md) | [시나리오 가이드](../guides/by-input.ko.md) | [CLI 레퍼런스](../reference/cli.ko.md) | [고지문·보안 보고서 가이드](../guides/reports.ko.md)
