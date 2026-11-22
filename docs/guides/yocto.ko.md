---
description: Yocto 빌드 디렉터리에서 빌드가 만든 SPDX나, SPDX가 없을 때 남는 매니페스트를 읽어 이미지에 설치된 패키지만 담은 SBOM을 BomLens로 만드는 방법.
---

# Yocto 빌드 SBOM 가이드

Yocto 빌드 디렉터리에서 SBOM을 만드는 방법을 설명합니다. 빌드 디렉터리를 스캔 대상으로 지정하면 BomLens는 빌드가 만든 이미지 SBOM을 읽고, SPDX가 없는 빌드라면 빌드가 남긴 매니페스트를 대신 읽습니다. 자체 레시피와 공급사 바이너리는 선언 파일에 적어 이미지의 패키지에 반영할 수 있습니다.

## Yocto 빌드를 읽는 방식


Yocto 빌드는 자체 SPDX SBOM을 만들 수 있고, BomLens는 이를 일반 SPDX 경로가 아니라 전용 파서로 읽습니다. Yocto 문서에는 일반 경로가 잃어버리는 정보가 두 가지 들어 있기 때문입니다.

SBOM을 만들려면 `local.conf`에 다음을 넣고 평소대로 빌드합니다.

```
INHERIT += "create-spdx-3.0"
INHERIT += "vex"
```

어떤 SPDX 버전을 만들 수 있는지는 릴리스마다 다릅니다.

| 릴리스 | 기본 SPDX | `create-spdx-3.0` 사용 |
|--------|-----------|------------------------|
| 4.0 Kirkstone (LTS) | 2.2 | **불가**(이 릴리스에는 해당 클래스가 없습니다) |
| 5.0 Scarthgap (LTS) | 2.2 | 가능 |
| 5.1 Styhead 이후 | 3.0 | 가능(기본값) |

Kirkstone에서는 위 설정을 쓸 수 없습니다. 그 빌드는 SPDX 2.2를 만들고, 아래에 적은 방식으로 읽습니다.

그다음 빌드 디렉터리를 그대로 스캔 대상으로 지정합니다. 빌드가 SBOM을 어디에 두었는지 알 필요가 없습니다.

```bash
./scripts/scan-sbom.sh --project my-image --version 1.0.0 \
  --target ~/poky/build --generate-only
```

빌드 디렉터리로 인식하고, 빌드가 만든 이미지 SBOM인 `tmp/deploy/images/<machine>/<image>.rootfs.spdx.json`(OpenEmbedded 빌드는 `tmp-glibc/…`)을 분석합니다. 빌드 트리 자체는 훑지 않습니다. 디렉터리로 스캔하면 이미지에 들어가지 않는 sysroot와 빌드용 도구까지 결과에 섞이기 때문입니다.

머신이나 이미지를 여럿 빌드해 SBOM이 여러 개면 가장 최근에 쓰인 것을 분석하고 후보 전체를 로그에 남깁니다. 다른 것을 고르려면 `--analyze <파일>`로 직접 지정합니다. `DEPLOY_DIR`를 옮겨 이미지를 완전히 다른 위치에 쓰는 빌드도 이 방법으로는 찾지 못하니 같은 방식으로 지정합니다. SBOM 파일 하나만 받은 경우에는 그 파일을 웹 UI에 올리거나 `--analyze`로 넘기면 됩니다.

웹 UI도 같은 폴더를 읽습니다. 폴더 선택 타일로 그 폴더를 고르면 됩니다(`--ui --mount ~/poky/build`로 먼저 마운트하거나 데스크톱 앱의 폴더 추가… 사용). 감지는 명령줄과 똑같이 동작합니다.

빌드 디렉터리 스캔의 적합성 검사 보고서는 빌드가 만든 문서가 아니라 스캔이 쓴 SBOM(`<Project>_<Version>_bom.json`)을 점검합니다. 제출할 파일이 이것이기 때문입니다. 이 SBOM에는 `bomlens:scanMode`로 `YOCTO`가 기록되고, `--conformance-profile skt-submission`에서는 펌웨어 스캔과 같은 방식으로 판정합니다. 의존 관계 그래프가 아니라 설치된 패키지를 기록하기 때문입니다. `--analyze`로 넘긴 Yocto 문서는 적힌 그대로 판정합니다.

이 SBOM은 스캔이 직접 만든 것이므로 다른 스캔이 만든 SBOM과 같은 방식으로 정보를 채웁니다. `--sbom-author`, `--supplier`, `--license`(`concluded`)를 기록하고, 도구 목록에 BomLens를, 수명 주기 단계로 `build`를 적습니다. 이미지는 빌드가 정한 이름을 그대로 두고 `bom-ref`를 받으며, 빌드가 버전을 적지 않았으면 `--version`을 받고, 설치된 모든 패키지에 의존하는 것으로 기록됩니다. 빌드가 생성 시각을 적지 않았으면(매니페스트에는 없음) 스캔 시각을 적습니다. 이 세 옵션을 주면 `bsi-tr-03183-2`의 SBOM 작성자, 의존 관계 그래프, 최상위 구성요소 항목이 통과할 수 있습니다. `--analyze`로 따로 넘긴 Yocto 문서는 다른 사람이 만든 SBOM이므로 이 처리를 하지 않습니다.

## 자체 레시피와 공급사 바이너리

빌드는 설치한 패키지를 모두 기록합니다. 사내 레시피와 칩 제조사의 바이너리 레시피도 여기에 들어 있지만, 어느 것이 자체개발이고 누가 공급했는지는 빌드 기록에 없습니다. 이 정보는 선언 파일에 적어 `--components`로 넘깁니다. 산출물 경로는 머신과 작업 디렉터리마다 다르므로, 구성요소에는 파일 경로 대신 `bomlens:yocto-recipe`에 레시피 이름(버전을 뺀 PN)을 적습니다.

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
        { "name": "bomlens:yocto-recipe", "value": "media-daemon" }
      ]
    }
  ]
}
```

```bash
./scripts/scan-sbom.sh --project my-image --version 1.0.0 \
  --target ~/poky/build --components meta-example/sbom-declared.cdx.json
```

선언은 이미지에 설치된 그 레시피의 패키지 전부(예: `media-daemon`과 `media-daemon-cli`)에 적용됩니다. 각 패키지는 빌드가 기록한 이름, 버전, purl, CPE를 그대로 두고, 선언한 유형, 공급자, 라이선스(`concluded`), `bomlens:origin`을 받으며 `bomlens:declared`로 표시됩니다. SPDX 문서가 그 패키지에 기록한 파일은 해시, 파일 이름과 함께 패키지 아래 하위 구성요소로 들어갑니다. Yocto는 패키지가 아니라 파일 단위로 해시를 냅니다. SPDX 3.0은 SHA-256을, Yocto 6.1부터는 SHA-512도 기록하고, SPDX 2.2는 SHA-1과 SHA-256을 기록하며, 매니페스트에는 파일 목록이 없습니다. BomLens는 패키지 해시를 따로 만들지 않습니다. 그래서 `--conformance-profile bsi-tr-03183-2`에서는 빌드가 기록하지 않은 SHA-512와 파일 이름, Yocto 기록에 없는 파일 속성을 원본 SBOM에 없음으로 보고하고 경고로 표시합니다. `skt-submission`에서 자체개발 구성요소가 PURL 항목에서 빠지려면 SHA-512가 있어야 하므로, 6.1 이전 빌드에서는 자체 패키지에도 purl이 필요합니다(이 패키지의 `pkg:yocto` purl은 upstream 저장소가 없는 purl로 셉니다).

선언한 레시피가 이미지에 패키지를 하나도 설치하지 않았으면 스캔은 레시피 이름을 알리며 실패하고, 그때까지 만든 SBOM을 `<Project>_<Version>_bom.refused.json`으로 남깁니다. 레시피 선언에는 `bomlens:artifact`를 함께 적을 수 없고, 빌드가 정하는 `hashes`, `purl`, `cpe`도 적을 수 없습니다. 레시피도 파일도 없는 구성요소(예: 장치가 실행 중에 불러오는 바이너리)는 소스 스캔과 같은 방식으로 추가됩니다. 다만 이미지에 설치된 패키지와 이름이 같으면 거부하며, 그 패키지는 레시피로 선언합니다.

패키지는 빌드가 기록한 레시피로만 맞춥니다(SPDX 문서, SPDX가 없는 빌드에서는 `license.manifest`). 빌드가 레시피를 기록하지 않은 패키지는 이름이 같아도 맞추지 않으며, 거부 메시지에 그 패키지 이름이 나옵니다. 레시피의 멀티립과 SDK 변형(`lib32-media-daemon`, `nativesdk-media-daemon`)은 별도 레시피이므로 따로 선언하며, 이미지에 설치된 변형이 있으면 로그에 경고가 나옵니다. 선언은 `--target`으로 준 빌드 디렉터리에 적용됩니다. `--analyze`로 준 SBOM은 받은 SBOM이므로 바꾸지 않으며, `--components`와 함께 쓰면 거부합니다. 웹 UI에서는 아직 Yocto 레시피를 선언할 수 없습니다.

공급자만은 빌드에서 가져올 수도 있습니다. SPDX 3.0에서는 레이어에 레시피별로 다음과 같이 지정하고 다시 빌드합니다.

```
SPDX_PACKAGE_SUPPLIER_name:pn-media-daemon = "Example Corp"
SPDX_PACKAGE_SUPPLIER_type:pn-media-daemon = "organization"
```

Yocto는 이 값을 패키지의 `suppliedBy`로 기록하고, BomLens는 이를 공급자로 읽습니다. 다만 이름만 있고 BSI TR-03183-2가 제작자에 요구하는 URL이나 이메일은 없으며, 자체개발 여부도 표시하지 않습니다. 그래서 `bomlens:origin`은 여전히 선언 파일에 적습니다. SPDX 2.2는 `SPDX_SUPPLIER`를 기록하는데, 기본값이 실제 공급자가 아니라 OpenEmbedded이므로 BomLens는 이 값을 읽지 않습니다.

## SPDX를 전혀 만들지 않은 빌드

`create-spdx`를 켜는 것은 빌드 설정을 바꾸는 일이라, 완료된 빌드 디렉터리만 가진 사람은 그렇게 하지 못할 수 있습니다. 빌드는 SPDX가 없어도 무엇을 넣었는지 기록해 두므로, 그 기록을 대신 읽습니다.

| 파일 | 위치 | 얻는 정보 |
|------|------|-----------|
| 이미지 패키지 매니페스트 | `tmp/deploy/images/<machine>/<image>.manifest` | 설치된 패키지와 버전 |
| 라이선스 매니페스트 | `tmp/deploy/licenses/**/license.manifest` | 패키지별 라이선스와 출처 레시피 |
| cve-check 보고서 | `tmp/log/cve/cve-summary.json` | CVE별로 레시피가 패치했는지, 해당 없다고 판정했는지, 남았는지 |

세 가지 입력 중 가장 약한 경로이며, 이유를 알아 둘 만합니다. CPE가 없어 취약점 매칭이 패키지 이름과 버전에만 기댑니다. CVE 판정도 그 빌드가 실행한 `cve-check` 범위까지만 정확합니다(`cve-check`를 돌리지 않은 빌드는 판정이 없다고 보고하며, 없는 판정을 지어내지 않습니다). 적합성 검사 보고서는 다른 빌드 디렉터리 스캔처럼 이 기록에서 읽은 SBOM을 점검합니다. 위의 `local.conf` 두 줄을 넣고 다시 빌드하는 편이 여전히 낫습니다.

Yocto 빌드 디렉터리인데 SPDX 문서도 이미지 매니페스트도 없으면 디렉터리 스캔으로 넘어가지 않고 스캔을 멈춘 뒤 위 설정 두 줄을 안내합니다. 그대로 스캔하면 이미지 내용과 다른 결과가 나오기 때문입니다.

## 일반 스캔과 결과가 다른 점

일반 SBOM 스캔과 결과가 세 가지 면에서 다릅니다.

구성 목록에는 이미지에 설치된 패키지만 담깁니다. Yocto 문서에는 빌드가 사용한 소스 압축 파일도 전부 기록되는데, 출처를 따질 때는 쓸모가 있지만 제품에 실제로 들어간 것과는 다릅니다. 그래서 목록에서 뺍니다.

취약점은 빌드가 판정한 결과를 그대로 씁니다. Yocto는 빌드하면서 CVE 분석을 돌리고 항목마다 판정을 기록하므로 레시피가 패치를 적용했는지 압니다. 그 판정을 빌드에서 패치한 것, 해당 없다고 판정한 것, 아직 남은 것 세 가지로 나눠 보여주고 남은 것만 발견 항목으로 셉니다. 기준 이미지인 `core-image-minimal`에서는 이 차이가 취약점 12255건을 보고하느냐 한 건도 없다고 보고하느냐를 가릅니다. 전부 빌드에서 이미 닫혔기 때문입니다.

컴포넌트에는 펌웨어 스캔과 같이 upstream 저장소 purl이 붙습니다. 패키지를 만든 레시피나, SPDX 2.2라면 레시피의 소스 내려받기 주소로 BomLens가 프로젝트를 알아낼 수 있는 경우입니다. 어떤 프로젝트를 다루는지는 [upstream 저장소 purl](firmware.ko.md#upstream-저장소-purl)을 참고하세요.

## 한계

시작하기 전에 알아 둘 한계가 두 가지 있습니다.

SPDX 2.2도 읽지만 담기는 정보가 적습니다. Yocto 4.0 Kirkstone과 5.0 Scarthgap은 기본값이 SPDX 2.2인데, 이 형식은 문서 하나가 아닙니다. deploy 디렉터리에는 `<image>.spdx.tar.zst` 하나만 놓이고, 그 안에 이미지 문서와 설치 패키지별 문서, 레시피별 문서가 들어 있습니다. BomLens는 이 아카이브를 직접 읽습니다. 공개된 Yocto 5.0.14 `core-image-minimal`로 확인한 결과, 이미지 매니페스트가 나열한 36개 패키지를 라이선스와 CPE까지 그대로 얻었습니다.

없는 것은 빌드의 CVE 판정입니다. 레시피가 어떤 CVE를 패치했는지는 SPDX 3.0에만 기록되므로, `--security`를 켜면 취약점을 이미지에 들어 있는 NVD CPE 인덱스와 CPE로 대조합니다(벤더가 `*`인 CPE는 모든 벤더에서 제품명으로 찾으므로, 다른 프로젝트와 제품명이 같으면 그 프로젝트의 CVE도 나올 수 있음). 그래서 빌드가 이미 패치한 CVE가 열린 것으로 보일 수 있습니다. 아카이브에서 이미지 문서만 꺼내 따로 올리면 결과가 거의 비는데, 이때는 깨끗한 스캔처럼 보이게 두지 않고 그 사실을 알려 줍니다. 빌드 디렉터리에 두 형식이 함께 있으면 2.2 쪽이 더 최근이더라도 SPDX 3.0 문서를 분석합니다. `--analyze`로 넘긴 아카이브는 적합성 검사 보고서를 만들지 않습니다. 아카이브는 제출된 문서가 아니라 문서 묶음이라, 제출 기준과 대조할 대상이 아니기 때문입니다. 빌드 디렉터리에서 찾은 아카이브라면 거기서 읽은 SBOM을 대신 점검합니다.

PURL에 기대는 적합성 항목은 실패합니다. Yocto는 패키지를 PURL이 아니라 CPE로 식별하므로 PURL 적용률과 거기서 파생되는 항목은 통과할 수 없습니다. 보고서에는 몇 개가 CPE로 식별됐는지 함께 적히고, 그 행 아래에 두 식별자를 모두 인정하는 기준(BSI TR-03183-2, 미국 SBOM 최소 요소)이 표시됩니다. 즉 이 판정은 기준이 아니라 제출 요구사항의 것입니다. 기본 취약점 매칭이 PURL을 키로 쓰기 때문에 여기서는 PURL을 요구합니다.

필수 항목 하나가 더 실패하는데, 도구가 아니라 문서 쪽 사정입니다. 최상위 컴포넌트가 버전이 없어 실패합니다. bitbake가 이미지 패키지에 이름만 쓰고 `software_packageVersion`을 넣지 않습니다(기준 이미지 `core-image-minimal`에서 확인). 빌드 디렉터리를 스캔하면 이미지가 대신 `--version`을 받습니다.

업로드 크기는 100MB까지 받습니다. 참고로 기준 이미지인 `core-image-minimal` 문서는 설치 패키지 35개에 15.8MB입니다. `--target`으로 빌드 디렉터리를 스캔할 때는 디스크에서 파일을 읽으므로 이 제한이 적용되지 않습니다.
