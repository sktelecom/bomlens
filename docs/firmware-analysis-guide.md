# 펌웨어 분석 가이드

> **관련 문서**: [시작하기](getting-started.md) | [시나리오 가이드](scenarios-guide.md) | [사용 가이드](usage-guide.md) | [고지문·보안 보고서 가이드](notice-and-security.md)

공급사가 제출한 네트워크 장비 펌웨어 바이너리(`.bin`, `.img`, squashfs 등)에서 구성요소를 식별하고 SBOM과 라이선스, 취약점을 점검하는 방법을 설명합니다.

도구 선정 근거와 내부 동작 설계는 메인테이너용 [펌웨어 분석](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/firmware-analysis.md) 문서를 참고하세요.

## 동작 방식

펌웨어는 운영체제와 라이브러리 수십 개가 통째로 압축·밀봉된 파일입니다. 그래서 펌웨어 파일을 그대로 일반 스캔에 넣으면 거의 검출하지 못하고 빈 SBOM이 나옵니다. 펌웨어 분석은 먼저 압축을 풀어 내용물을 꺼낸 뒤 구성요소를 식별합니다.

1. 언팩(unblob, 폴백 BANG)으로 펌웨어를 풀어 rootfs를 추출합니다.
2. `syft`로 패키지 매니저(opkg, dpkg, apk, rpm)가 설치한 구성요소를 식별합니다.
3. `cve-bin-tool`로 stripped 정적 바이너리(busybox, openssl, dropbear 등)의 버전과 취약점을 찾습니다.
4. 두 결과를 하나의 SBOM으로 병합한 뒤, 일반 스캔과 동일한 후처리(라이선스, CVE, 서명)를 거칩니다.

## 펌웨어 이미지 준비

펌웨어 분석에는 언팩과 바이너리 식별 도구(unblob, cve-bin-tool 등)가 들어 있는 별도 이미지가 필요합니다. 이 도구들은 GPL 계열이라 경량 기본 이미지에는 넣지 않고, opt-in 펌웨어 이미지로 분리되어 있습니다.

```bash
docker pull ghcr.io/sktelecom/sbom-scanner-firmware:latest
```

기본값이 이 이미지이므로 별도 지정 없이 `--firmware`만 붙여도 받습니다. 다른 태그를 쓰려면 환경변수 `SBOM_FIRMWARE_IMAGE`로 지정합니다.

## 실행하기

받은 펌웨어 파일을 `--target`에 넘기고 `--firmware`를 붙입니다.

```bash
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh

$SBOM --project device-fw --version 1.0.0 \
  --target "./device.bin" --firmware \
  --all --generate-only
```

- 인식 가능한 확장자(`.bin`, `.img`, `.squashfs`, `.ubi`, `.ubifs`, `.trx`, `.chk`, `.fw`, `.rom`)는 `--firmware` 없이도 자동 감지되지만, 명시를 권장합니다.
- 산출물은 일반 스캔과 같은 3종입니다. 고지문(`_NOTICE`), SBOM(`_bom.json`), 위험분석보고서(`_risk-report`).

> **웹 UI**: 펌웨어 업로드 탭은 펌웨어 이미지에서 UI를 실행할 때만 활성화됩니다.
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/sbom-scanner-firmware:latest $SBOM --ui`

## 라이선스 주의

펌웨어 이미지에는 GPL 도구(cve-bin-tool, BANG, unblob이 의존하는 일부 extractor)가 들어 있습니다. 셸 스크립트가 이들을 별도 프로세스로 호출만 하므로 copyleft가 우리 코드로 전파되지는 않지만, GPL 바이너리를 이미지로 재배포하는 데 따른 라이선스 텍스트 동봉과 소스 오퍼 의무가 있습니다. 상세 인벤토리는 [번들 도구 라이선스](https://github.com/sktelecom/sbom-tools/blob/main/THIRD_PARTY_LICENSES.md)를 참고하세요. GPL 도구는 이 펌웨어 이미지에만 들어가고 기본 이미지는 permissive 라이선스만 유지합니다.

## 한계

- 오픈소스 도구 스택의 검출률은 약 60~85%이며, 펌웨어 종류와 strip 정도, 언팩 성공 여부에 크게 좌우됩니다.
- 함수 수준 바이너리 핑거프린팅이 없어서, 상용 도구와 달리 strip되거나 인라인된 컴포넌트, 버전 문자열이 제거된 바이너리는 놓칩니다.
- 정적 링크 라이브러리와 벤더가 변형한 squashfs, 암호화·서명된 펌웨어, 사명을 바꾼 라이브러리는 검출하지 못하거나 부정확합니다.
- 결과 SBOM은 best-effort 추정이므로, 법적 라이선스 컴플라이언스의 단일 근거로 사용하지 마세요.
