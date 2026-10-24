---
description: 자체 실행 파일, 라이브러리, 펌웨어나 벤더가 준 바이너리처럼 스캔이 찾지 못하는 구성요소를 CycloneDX 파일에 적으면, 소스 스캔이 해시와 파일 속성을 채워 SBOM에 넣고 BSI TR-03183-2 기준으로 검사할 수 있습니다.
---

# 자체 구성요소 선언

소스 스캔은 패키지 매니저와 lock 파일을 읽으므로 프로젝트가 의존하는 오픈소스를 찾습니다. 직접 빌드한 구성요소나 손으로 트리에 넣은 구성요소는 찾지 못합니다. 선언 파일에는 이런 구성요소를 적습니다. 소스 스캔은 이 구성요소를 SBOM에 넣고, 지정한 빌드 산출물에서 해시와 파일 속성을 읽어 채우므로 사람이 따로 적을 필요가 없습니다.

`bsi-tr-03183-2` 적합성 프로필이 검사하는 대상도 이 구성요소이고, 자체 구성요소가 purl 없이 제출 검토를 통과하는 근거도 이 파일입니다. 두 가지 모두 이 문서 뒷부분에서 설명합니다.

## 파일에 무엇을 적나?

스캔이 찾지 못하는 것만 적습니다. 보통 다음과 같습니다.

- 직접 만든 실행 파일, 라이브러리, 펌웨어 이미지, 압축 파일(배포하는 프로그램이나 파일마다 구성요소 하나)
- 칩 제조사의 드라이버나 미리 빌드된 라이브러리처럼 벤더가 준 바이너리
- HAL이나 RTOS처럼 패키지 매니저 없이 소스 트리에 복사한 소스

패키지 매니저나 lock 파일로 들어온 오픈소스는 스캔이 찾으므로 이 파일에 적지 않습니다. 선언 파일 없이 한 번 스캔한 뒤, 그 SBOM에 빠진 것만 적습니다. 양쪽에 모두 있는 구성요소는 두 번 남습니다(purl이 같으면 스캔이 경고합니다). C/C++ 소스에 복사된 오픈소스는 [`--identify-vendored`](identify-vendored.ko.md)가 파일 내용으로 일부를 식별할 수 있습니다.

## 파일은 어디에 두나?

소스 스캔은 스캔 대상 루트에 `sbom-declared.cdx.json`이 있으면 읽습니다. 다른 위치에 두거나 여러 파일로 나누려면 `--components <file>`을 씁니다. 파일이 여러 개면 옵션을 반복합니다. 예를 들어 모노레포에서는 모듈마다, 벤더 디렉터리마다 파일을 하나씩 둘 수 있습니다. `--components`를 주면 루트의 파일은 읽지 않습니다.

구성요소를 어느 파일에 적었든 `bomlens:artifact` 경로는 선언 파일이 아니라 스캔 대상 루트를 기준으로 합니다.

`--no-components`는 루트의 파일을 읽지 않게 합니다. 파일이 가리키는 빌드 산출물이 아직 없을 때 하는 스캔에 씁니다. `--components`와 함께 쓸 수 없습니다.

선언 파일은 소스 스캔과 `--target`으로 준 Yocto 빌드 디렉터리에서 읽습니다([Yocto 이미지](#yocto-이미지) 참고). 펌웨어, 이미지, 바이너리 스캔이나 `--analyze`에 `--components`를 주면 오류로 멈춥니다. 웹 UI에는 `--components` 옵션이 없으므로 스캔할 폴더(소스 트리 또는 Yocto 빌드 디렉터리)의 루트에 `sbom-declared.cdx.json`을 둡니다. 결과 품질의 **sbom-declared.cdx.json 읽기** 스위치는 기본으로 켜져 있으며, 끄면 `--no-components`와 같습니다. 파일이 거부되면 실패한 스캔 화면에 사유가 나오고 `_bom.refused.json`을 보거나 내려받을 수 있습니다. 끝난 스캔의 컴포넌트 섹션에서는 선언한 구성요소에 "자체 개발" 또는 "제3자" 배지가 붙습니다. [웹 UI 레퍼런스](../reference/ui.ko.md)를 참고하세요.

## 파일 형식

파일은 `components`(원하면 `dependencies`도)만 담은 CycloneDX 문서입니다. 필드 이름은 CycloneDX 표준 그대로입니다.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "application",
      "name": "media-daemon",
      "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
      "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
      "properties": [
        { "name": "bomlens:origin", "value": "first-party" },
        { "name": "bomlens:artifact", "value": "out/bin/media-daemon" }
      ]
    },
    {
      "type": "library",
      "name": "vendor-hal",
      "version": "4.2.0",
      "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
      "licenses": [ { "license": { "id": "BSD-3-Clause" } } ],
      "properties": [
        { "name": "bomlens:origin", "value": "third-party" }
      ]
    }
  ]
}
```

`bomFormat`은 `CycloneDX`이어야 하고 `components`는 배열이어야 합니다. `specVersion`은 생략할 수 있습니다.

모든 구성요소에 `bomlens:origin` 속성이 한 번 있어야 하며, 값은 `first-party`(직접 만든 것)나 `third-party`(다른 곳에서 받은 것)입니다. 기본값은 없습니다. 기본값이 있으면 표시를 빠뜨린 벤더 바이너리가 자체개발로 잡혀, 아래에서 설명하는 purl 요구를 건너뛸 수 있기 때문입니다.

`version`이 없는 `first-party` 구성요소는 제품 버전(`--version`)을 씁니다. `third-party` 구성요소는 받은 버전을 반드시 적어야 합니다.

`bomlens:artifact`는 빌드 산출물의 경로이며, 스캔 대상 루트 기준 상대 경로를 슬래시(`/`)로 적습니다. 생략할 수 있고, 구성요소가 여러 파일로 배포되면 여러 번 씁니다. 펌웨어에 컴파일되어 들어간 HAL이나 RTOS처럼 자체 파일이 없는 구성요소는 이 속성 없이 적습니다.

`bomlens:distribution-url`도 생략할 수 있습니다. 배포 파일을 받을 수 있는 곳을 http나 https URL, 또는 납품물 안의 상대 경로로 적습니다. 없으면 빌드 산출물의 경로를 씁니다.

`dependencies`도 생략할 수 있습니다. 각 `ref`는 같은 파일의 구성요소여야 하고, `dependsOn`에는 어느 선언 파일의 구성요소든, 스캔이 찾은 구성요소든 `bom-ref`로 적을 수 있습니다. `bom-ref`가 없는 구성요소에는 `declared:<name>@<version>`이 붙습니다.

### 구성요소에 쓸 수 있는 CycloneDX 필드

`name`, `version`, `bom-ref`, `group`, `description`, `copyright`, `cpe`, `purl`, `publisher`, `author`, `mime-type`, `type`, `scope`, `tags`, `supplier`, `manufacturer`, `authors`, `hashes`, `licenses`, `externalReferences`, `properties`입니다. 각 필드는 CycloneDX 1.6 스키마가 정한 모양인지 확인합니다. 그 밖의 필드는 중첩된 `components`를 포함해, 확인 없이 SBOM에 옮기지 않고 이름을 밝혀 거부합니다. 구성요소는 모두 파일의 최상위에 적습니다.

### 라이선스는 어떻게 적나?

라이선스 `id`는 SPDX License List에 있는 식별자여야 합니다. 자체 독점 라이선스처럼 목록에 없는 라이선스는 `name`에 `LicenseRef-`로 시작하는 값을 적습니다. 이 값에는 영문자, 숫자, `.`, `-`만 쓸 수 있으며, 예를 들면 `LicenseRef-ExampleCorp-Proprietary`입니다. `Proprietary` 같은 일반 이름도 스캔은 받아들이지만, BSI 프로필은 SPDX 식별자, 표현식, `LicenseRef-` 이름만 인정합니다. 목록 대신 SPDX `expression` 하나를 적어도 됩니다.

`acknowledgement` 없이 적은 라이선스는 `concluded`로 기록합니다. 구성요소를 배포하는 라이선스라는 뜻이며, BSI TR-03183-2가 요구하는 배포 라이선스가 이것입니다. 파일에 적은 `acknowledgement`는 그대로 둡니다.

## BomLens가 채우는 값

빌드 산출물이 하나인 구성요소에는 그 파일에서 읽은 다음 값을 채웁니다.

- SHA-512와 SHA-256 해시
- 경로를 뺀 파일 이름인 `bsi:component:filename`
- `bsi:component:executable`(ELF 프로그램이나 공유 라이브러리, PE 파일, Mach-O 바이너리면 `executable`), `bsi:component:archive`(zip, tar, gzip, bzip2, xz, zstd, lz4, 7z, rar, ar와 deb, rpm, cpio, ISO 9660이면 `archive`), `bsi:component:structured`(압축한 tar를 포함해 안에 든 파일 목록을 담은 압축 파일이면 `structured`, 일반 프로그램과 펌웨어 이미지와 단일 압축 스트림은 `unstructured`)
- SHA-512를 담은 `distribution` 유형의 `externalReferences` 항목. `url`은 `bomlens:distribution-url`이나 빌드 산출물의 경로입니다

세 `bsi:component:*` 속성 가운데 파일에 값을 적은 것은 빌드 산출물에서 읽은 값 대신 그 값을 씁니다. 파일에 적은 해시는 빌드 산출물과 일치해야 합니다.

빌드 산출물이 여러 개인 구성요소는 산출물마다 `file` 유형의 하위 구성요소를 하나씩 갖고, 각 하위 구성요소에 해시, 속성, `distribution` 항목이 따로 붙습니다. 해시 한 벌로 여러 파일을 나타낼 수 없으므로 상위 구성요소에는 해시를 붙이지 않습니다.

제품은 선언한 각 구성요소에 의존하는 것으로 기록되므로(`dependencies`가 있는 파일에서는 다른 구성요소가 의존하지 않는 구성요소에), 의존성 그래프가 모든 선언 구성요소에 닿습니다. 이렇게 추가한 구성요소에는 모두 `bomlens:declared` `true`가 붙습니다.

## 무엇을 거부하고, 왜 거부하나?

규칙을 어긴 파일은 거부합니다. 스캔은 모든 사유를 파일과 구성요소 이름과 함께 출력하고, SBOM을 정규화하거나 서명하거나 업로드하기 전에 멈추며 1로 종료합니다. 그때까지 만든 SBOM은 `_bom.json`이 아니라 `{Project}_{Version}_bom.refused.json`으로 남습니다. 그래서 `_bom.json`을 가져가는 다음 단계가 불완전한 SBOM을 쓰지 않습니다. 같은 프로젝트와 버전을 다음에 스캔하면 이 파일은 지워집니다.

| 거부하는 경우 | 이유 |
|---|---|
| `bomlens:origin`이 없거나 두 번 있거나 `first-party`, `third-party`가 아님 | 이 값이 없으면 벤더 바이너리가 자체개발로 잡혀 purl 요구를 건너뛸 수 있음 |
| `version`이 없는 `third-party` 구성요소 | 취약점은 받은 버전으로 대조하며, 스캔이 그 버전을 추정할 수 없음 |
| `bomlens:artifact` 파일이 없음 | 파일이 조용히 빠지면 손으로 목록을 적을 때와 같은 누락이 생김. 스캔 루트의 파일을 기본으로 읽은 경우 메시지가 `--no-components`를 안내하고, `--exclude` 경로 아래 파일이면 제외됐다고 알림 |
| `bomlens:artifact` 경로가 절대 경로이거나, `..`나 역슬래시를 담거나, 심볼릭 링크로 밖을 가리키거나, 일반 파일이 아님 | 빌드 산출물은 스캔한 범위 안에 있어야 함 |
| 같은 `name`과 `version`이 한 파일이나 여러 파일에 두 번 나옴 | 구성요소 하나는 한 곳에만 적음 |
| 스캔이 찾은 구성요소가 이미 쓰는 `bom-ref`, 또는 두 번 쓴 `bom-ref` | 참조는 구성요소 하나만 가리켜야 함 |
| 위 목록에 없는 필드, 중첩된 `components`, 모양이 틀린 값 | 외부 입력이므로 확인하지 않은 값은 SBOM에 넣지 않음 |
| SPDX License List에 없는 라이선스 `id` | 대신 `LicenseRef-` 이름을 씀(메시지가 이름을 제안함) |
| 빌드 산출물과 다른 해시, BLAKE3 해시, 빌드 산출물이 여러 개인 구성요소에 적은 해시 | 파일로 확인할 수 없는 해시는 믿지 않음 |
| BSI TR-03183-2가 정한 값이 아닌 `bsi:component:*` 값, 또는 빌드 산출물이 여러 개인 구성요소에 적은 값 | 이 값은 파일 하나를 설명함 |
| http(s) URL도 납품물 안의 상대 경로도 아닌 `bomlens:distribution-url`, 또는 빌드 산출물이 여러 개인 구성요소에 적은 값 | 빌드 산출물마다 자기 경로로 표시함 |
| 선언하지도 않았고 스캔이 찾지도 않은 구성요소를 가리키는 `dependencies` 항목 | 그래프가 끊기지 않아야 함 |
| 4 MiB를 넘거나, 구성요소가 10,000개를 넘거나, UTF-8 JSON이 아니거나, CycloneDX 문서가 아닌 파일 | 스캔이 확인할 수 있는 크기의 CycloneDX 문서여야 함 |

## 자체개발 구성요소에 purl이 필요 없는 경우

자체 빌드 산출물은 패키지 저장소에 올라가지 않으므로 purl이 없습니다. 선언 구성요소가 다음 조건을 모두 만족하면, `skt-submission`을 포함한 모든 적합성 프로필에서 PURL 포함률, "추적 가능한 PURL (pkg:generic 없음)", "upstream purl 없음" 항목에서 빠집니다.

- `bomlens:origin`이 `first-party`임
- 이름이나 URL이 있는 `supplier`가 있음
- SHA-512가 있음. BomLens가 `bomlens:artifact` 파일에서 계산함(하위 파일 구성요소가 있으면 모두에 있어야 함)
- 같은 스캔에서 선언 파일로 추가됨

이런 구성요소는 권고 항목 "purl 대신 공급자와 SHA-512로 식별한 자체개발 구성요소"에 이름이 나옵니다. `third-party` 구성요소에는 여전히 purl이 필요하고, `--analyze`로 점검하는 SBOM은 구성요소에 `first-party`가 적혀 있어도 예외를 받지 않습니다. [적합성 검사 보고서 읽기](supplier-sbom.ko.md#적합성-검사-보고서-읽기)를 참고하세요.

## BSI TR-03183-2 기준 검사

```bash
./scripts/scan-sbom.sh --project MediaBox --version 2.1.0 \
  --conformance-profile bsi-tr-03183-2 --fail-on-conformance \
  --supplier "Example Corp <https://example.com>" \
  --sbom-author "Example Corp <sbom@example.com>" \
  --license LicenseRef-ExampleCorp-Proprietary
```

이 프로필은 BSI TR-03183-2 v2.1.0을 기준으로 검사합니다. CycloneDX 1.6 이상(기본 출력)이어야 하고, 다음을 요구합니다.

- 이메일 주소나 URL이 있는 SBOM 작성자. `--sbom-author "Name <email>"`이 `metadata.authors`에 기록합니다
- 제품(`metadata.component`)의 URL이나 이메일이 있는 제작자(`--supplier "Name <https://...>"` 또는 `"Name <email>"`), 이름, 버전(`--version`), 배포 라이선스(`--license`에 SPDX 식별자, 표현식, `LicenseRef-` 이름 중 하나를 주면 `concluded`로 기록)
- 제품에서 모든 구성요소에 닿는 의존성 그래프. SBOM이 완전성(`compositions`)을 밝히지 않으면 이 항목은 경고입니다
- 선언 구성요소마다 URL이나 연락처 이메일이 있는 supplier 또는 manufacturer, 이름과 버전, SPDX 식별자나 표현식이나 `LicenseRef-` 이름으로 적은 concluded 라이선스
- 빌드 산출물을 지정한 선언 구성요소마다 파일 이름, SHA-512, 세 파일 속성. BomLens가 `bomlens:artifact`에서 채웁니다

자체 파일이 없는(다른 구성요소에 링크된) 선언 `library`나 `framework`는 파일 항목에서 실패하지 않고 권고 항목에 나옵니다. 그 밖의 유형, 예를 들어 application이나 firmware인데 파일이 없으면 파일 항목에서 실패합니다. 스캔이 찾은 구성요소는 권고 항목 하나에서 개수와 구성요소별 누락 필드로 보고하며, 판정에 영향을 주지 않습니다. 이 프로필에서 PURL 포함률은 권고입니다.

항목 하나라도 실패하면 보고서가 "fail"이 되고, `--fail-on-conformance`를 주면 종료 코드 2로 끝납니다. 전체 규칙은 [CLI 레퍼런스](../reference/cli.ko.md#옵션-레퍼런스)의 `--conformance-profile`에 있습니다.

## 플랫폼별 예시

예시에는 `components` 항목만 적었습니다. 위와 같은 모양의 파일에 넣어 씁니다.

### C/C++ 리눅스 애플리케이션

Conan lock 파일이 있는 C/C++ 애플리케이션입니다. 오픈소스는 스캔이 `conan.lock`에서 읽고, 선언 파일에는 빌드가 `out/bin/`에 쓰는 프로그램을 적습니다.

```json
{
  "type": "application",
  "name": "media-daemon",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "out/bin/media-daemon" }
  ]
}
```

스캔이 파일을 읽을 때 `out/bin/media-daemon`이 있어야 하므로 빌드를 먼저 실행합니다.

### Android 기기 빌드

`out/`이 들어 있는 트리를 스캔합니다. 미리 빌드되어 온 벤더 바이너리는 벤더가 준 버전과 함께 `third-party`로, 직접 빌드한 서비스는 `first-party`로 적습니다.

```json
{
  "type": "library",
  "name": "libvendor-camera",
  "version": "3.4.1",
  "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleChipVendor-Binary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "third-party" },
    { "name": "bomlens:artifact", "value": "out/target/product/<device>/vendor/lib64/libvendor-camera.so" }
  ]
},
{
  "type": "application",
  "name": "example-camera-service",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "out/target/product/<device>/vendor/bin/hw/example-camera-service" }
  ]
}
```

`<device>`는 빌드의 제품 이름으로 바꿉니다. 벤더 디렉터리마다 담당이 다르면 디렉터리마다 선언 파일을 두고 각각 `--components`로 넘깁니다.

### Zephyr 애플리케이션

빌드는 펌웨어를 `build/zephyr/zephyr.elf`에 씁니다. 스캔은 `west.yml`을 읽지 않으므로, Zephyr 커널과 `west.yml`이 고정한 모듈은 `west.yml`에 적힌 리비전을 버전으로 삼아 직접 적습니다. 이들은 펌웨어에 컴파일되어 들어가므로 자체 파일이 없습니다.

```json
{
  "type": "firmware",
  "name": "sensor-node-fw",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "build/zephyr/zephyr.elf" }
  ]
},
{
  "type": "library",
  "name": "zephyr",
  "version": "4.1.0",
  "supplier": { "name": "Zephyr Project", "url": ["https://www.zephyrproject.org"] },
  "licenses": [ { "license": { "id": "Apache-2.0" } } ],
  "properties": [ { "name": "bomlens:origin", "value": "third-party" } ]
}
```

벤더 HAL처럼 펌웨어에 들어가는 `west.yml`의 모듈마다 두 번째 항목과 같은 `third-party` 항목을 하나씩 더합니다.

### HAL과 RTOS를 소스로 포함한 베어메탈 펌웨어

벤더 HAL과 RTOS를 소스 트리에 복사해 `build/firmware.bin`으로 컴파일하는 경우입니다. 펌웨어에는 파일을 지정하고, HAL과 RTOS는 `bomlens:artifact` 없는 `third-party` 라이브러리로 적습니다.

```json
{
  "type": "firmware",
  "name": "motor-controller-fw",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "build/firmware.bin" }
  ]
},
{
  "type": "library",
  "name": "freertos-kernel",
  "version": "11.1.0",
  "supplier": { "name": "FreeRTOS", "url": ["https://www.freertos.org"] },
  "licenses": [ { "license": { "id": "MIT" } } ],
  "properties": [ { "name": "bomlens:origin", "value": "third-party" } ]
},
{
  "type": "library",
  "name": "example-mcu-hal",
  "version": "1.8.0",
  "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
  "licenses": [ { "license": { "id": "BSD-3-Clause" } } ],
  "properties": [ { "name": "bomlens:origin", "value": "third-party" } ]
}
```

BSI 프로필에서 두 라이브러리는 자체 파일이 없는 선언 라이브러리 권고 항목에 나옵니다.

### Yocto 이미지

Yocto 빌드는 자체 SPDX 출력에 패키지를 기록하고, BomLens는 빌드 디렉터리에서 그 출력을 읽습니다(공급사 SBOM 가이드의 [Yocto 이미지](supplier-sbom.ko.md#yocto-이미지) 참고). 패키지와 버전, purl, 파일 해시는 이미 들어 있으므로, 선언에는 빌드 산출물 대신 `bomlens:yocto-recipe`에 레시피 이름(PN)을 적고 빌드가 모르는 공급자, 배포 라이선스, 출처만 더합니다.

```json
{
  "type": "application",
  "name": "media-daemon",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:yocto-recipe", "value": "media-daemon" }
  ]
},
{
  "type": "firmware",
  "name": "vendor-dsp",
  "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-Vendor-Binary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "third-party" },
    { "name": "bomlens:yocto-recipe", "value": "vendor-dsp" }
  ]
}
```

```bash
./scripts/scan-sbom.sh --project MediaBox --version 2.1.0 \
  --target build --components sbom-declared.cdx.json \
  --conformance-profile bsi-tr-03183-2
```

이미지가 그 레시피에서 설치한 패키지(예: `media-daemon`, `media-daemon-cli`)는 모두 선언한 유형, 공급자, 라이선스, 출처를 받고, 이름과 버전, purl, CPE는 그대로 둡니다. 빌드가 패키지마다 기록한 파일은 해시와 함께 그 패키지 아래에 들어갑니다(Yocto 6.1부터 SHA-512 포함). 버전은 생략해도 되며, 빌드와 다른 버전을 적으면 거부합니다. 명령줄에서는 Yocto 빌드 디렉터리에 기본 파일이 없으므로 `--components`를 항상 줍니다. 파일을 지정할 수 없는 웹 UI는 디렉터리 입력으로 고른 빌드 디렉터리 최상위의 `sbom-declared.cdx.json`을 읽습니다. `lib32-media-daemon` 같은 멀티립이나 SDK 변형은 별도 레시피이므로 따로 선언합니다. 이미지가 설치하지 않은 레시피나, 설치된 패키지와 같은 이름으로 이름만 적어 추가한 구성요소는 거부합니다.

## CI에서 쓰기

선언 파일은 그 파일이 가리키는 산출물을 만드는 빌드와 함께 저장소에 둡니다. CI 작업은 먼저 빌드하고 나서 스캔합니다. GitHub Actions 예시는 [CI에서 선언 구성요소 사용](ci-cd.ko.md#ci에서-선언-구성요소-사용)에 있습니다.

---

> **관련 문서**: [CLI 레퍼런스](../reference/cli.ko.md) | [산출물](../reference/artifacts.ko.md) | [CI/CD 연동](ci-cd.ko.md) | [공급사 SBOM 검증](supplier-sbom.ko.md)
