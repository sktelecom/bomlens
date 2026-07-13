---
description: 네트워크 장비 펌웨어 바이너리(.bin, squashfs 등)를 언패킹해 구성요소를 식별하고 SBOM과 라이선스, 취약점을 점검하는 BomLens 펌웨어 분석 방법.
---

# 펌웨어 분석 가이드

네트워크 장비 펌웨어 바이너리(`.bin`, `.img`, squashfs 등)에서 구성요소를 식별하고 SBOM과 라이선스, 취약점을 점검하는 방법을 설명합니다. 협력사에서 받은 펌웨어처럼 소스 없이 바이너리만 있을 때 씁니다.

도구 선정 근거와 내부 동작 설계는 메인테이너용 [펌웨어 분석](https://github.com/sktelecom/sbom-tools/blob/main/docs/maintainers/firmware-analysis.md) 문서를 참고하세요.

## 동작 방식

펌웨어는 운영체제와 라이브러리 수십 개가 통째로 압축·밀봉된 파일입니다. 그래서 펌웨어 파일을 그대로 일반 스캔에 넣으면 거의 검출하지 못하고 빈 SBOM이 나옵니다. 펌웨어 분석은 먼저 압축을 풀어 내용물을 꺼낸 뒤 구성요소를 식별합니다.

1. 언팩(unblob, 폴백 BANG)으로 펌웨어를 풀어 rootfs를 추출합니다.
2. `syft`로 패키지 매니저(opkg, dpkg, apk, rpm)가 설치한 구성요소를 식별합니다.
3. `cve-bin-tool`로 stripped 정적 바이너리(busybox, openssl, dropbear 등)의 버전과 취약점을 찾습니다.
4. 두 결과를 하나의 SBOM으로 병합한 뒤, 일반 스캔과 동일한 후처리(라이선스, CVE, 서명)를 거칩니다.

## 펌웨어 이미지 준비

펌웨어 분석에는 언팩과 바이너리 식별 도구(unblob, cve-bin-tool 등)가 들어 있는 별도 이미지가 필요합니다. 이 도구들은 GPL 계열이라 경량 기본 이미지에는 넣지 않고, opt-in 펌웨어 이미지로 분리되어 있습니다.

```bash
docker pull ghcr.io/sktelecom/bomlens-firmware:latest
```

기본값이 이 이미지이므로 별도 지정 없이 `--firmware`만 붙여도 받습니다. 다른 태그를 쓰려면 환경변수 `SBOM_FIRMWARE_IMAGE`로 지정합니다.

## 실행하기

펌웨어 분석에는 위의 펌웨어 이미지가 필요합니다. 웹 UI든 CLI든 마찬가지입니다.

### 웹 UI에서

펌웨어 이미지에 닿을 수 있으면 웹 UI가 펌웨어 업로드 타일을 보여주고, 그 이미지에서 펌웨어 분석을 실행합니다. UI를 띄우고 파일을 올립니다.

```bash
SBOM_FIRMWARE_IMAGE=ghcr.io/sktelecom/bomlens-firmware:latest ./scripts/scan-sbom.sh --ui
#   Windows: sbom-ui.bat 더블클릭 전에 SBOM_FIRMWARE_IMAGE를 지정
```

프로젝트 이름과 버전을 입력하고, 펌웨어 업로드 타일을 골라 파일을 올린 뒤 스캔을 실행합니다. 온라인 첫 실행에서 CVE 데이터베이스를 받는 동안에는 UI에 다운로드 진행률 바가 표시됩니다.

### CLI에서

받은 펌웨어 파일을 `--target`에 넘기고 `--firmware`를 붙입니다.

```bash
./scripts/scan-sbom.sh --project device-fw --version 1.0.0 \
  --target "./device.bin" --firmware \
  --all --generate-only
```

- 인식 가능한 확장자(`.bin`, `.img`, `.squashfs`, `.ubi`, `.ubifs`, `.trx`, `.chk`, `.fw`, `.rom`)는 `--firmware` 없이도 자동 감지되지만, 명시를 권장합니다.
- 산출물은 일반 스캔과 같은 3종입니다. 고지문(`_NOTICE`), SBOM(`_bom.json`), 위험분석보고서(`_risk-report`).

## CVE 매칭, 온라인과 오프라인

정적 바이너리의 CVE 매칭은 cve-bin-tool과 그 전용 취약점 데이터베이스로 이뤄집니다. 펌웨어 이미지는 하이브리드 방식이라, 같은 이미지로 에어갭 환경과 온라인 환경에서 모두 동작합니다.

- 이미지를 빌드할 때 데이터베이스를 번들하면, 펌웨어 스캔이 스캔 시점에 오프라인으로 CVE를 매칭합니다. 빠르고 에어갭에 적합한 경로입니다.
- 번들 데이터베이스가 없지만 네트워크에 닿을 수 있으면, cve-bin-tool이 실행 중에 NVD에서 데이터베이스를 받습니다. 첫 실행은 느리며, 받는 동안 웹 UI에 다운로드 진행률 바가 표시됩니다.
- 번들 데이터베이스도 네트워크도 없으면, CVE 단계를 조용히 빼는 대신 사유를 로그로 남기고 구성요소 식별만 하는(CVE 없음) 동작으로 낮춥니다.

`CVE_BIN_TOOL_MODE`로 동작을 고릅니다. `auto`(기본값으로, 번들 데이터베이스를 우선하고 없으면 온라인일 때 내려받음), `offline`, `online`, `components-only`입니다.

데이터베이스는 NVD뿐 아니라 여러 출처(NVD, PURL2CPE 등)를 합친 집계 데이터입니다. cve-bin-tool은 "This product uses the NVD API but is not endorsed or certified by the NVD." 고지를 출력합니다.

OSV(Open Source Vulnerabilities) 권고는 재배포 이미지에 share-alike 데이터를 포함하지 않으려고 번들하지 않습니다. 대신 웹 UI에 "Include OSV advisories" opt-in 토글이 있어, 켜면 그 스캔에 한해 osv.dev에서 OSV를 받아옵니다. 데이터가 이미지에 동봉되는 게 아니라 사용자 머신에서 직접 내려받는 방식입니다.

## 라이선스 주의

펌웨어 이미지에는 GPL 도구(cve-bin-tool, BANG, unblob이 의존하는 일부 extractor)가 들어 있습니다. 셸 스크립트는 이 도구들을 별도 프로세스로 호출만 하므로 copyleft가 이 저장소의 코드로 전파되지는 않습니다. 다만 GPL 바이너리를 이미지에 담아 재배포하므로, 라이선스 텍스트 동봉과 소스 오퍼 의무는 그대로 적용됩니다. 상세 인벤토리는 [번들 도구 라이선스](https://github.com/sktelecom/sbom-tools/blob/main/THIRD_PARTY_LICENSES.md)를 참고하세요. GPL 도구는 이 펌웨어 이미지에만 들어가고 기본 이미지는 permissive 라이선스만 유지합니다.

## 한계

- 오픈소스 도구 스택의 검출률은 약 60~85%이며, 펌웨어 종류와 strip 정도, 언팩 성공 여부에 크게 좌우됩니다.
- 함수 수준 바이너리 핑거프린팅이 없어서, 상용 도구와 달리 strip되거나 인라인된 컴포넌트, 버전 문자열이 제거된 바이너리는 놓칩니다.
- 정적 링크 라이브러리와 벤더가 변형한 squashfs, 암호화·서명된 펌웨어, 사명을 바꾼 라이브러리는 검출하지 못하거나 부정확합니다.
- 결과 SBOM은 best-effort 추정이므로, 법적 라이선스 컴플라이언스의 단일 근거로 사용하지 마세요.

---

> **관련 문서**: [시작하기](../start/first-scan.ko.md) | [시나리오 가이드](../guides/by-input.ko.md) | [CLI 레퍼런스](../reference/cli.ko.md) | [고지문·보안 보고서 가이드](../guides/reports.ko.md)
