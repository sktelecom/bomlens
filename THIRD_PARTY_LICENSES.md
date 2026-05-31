# Third-Party Licenses

`sbom-tools`(Apache-2.0)는 자체 코드를 셸 스크립트로 두고, SBOM 생성·분석을 위해 여러 오픈소스 도구를 Docker 이미지에 **번들**합니다. 이 문서는 번들 도구의 라이선스 인벤토리와 배포 의무를 정리합니다.

## 컴플라이언스 요지

- `sbom-tools`의 셸 스크립트는 번들 도구를 **별도 프로세스로 호출(exec)** 하며 도구 소스를 수정하지 않습니다. 따라서 GPL/AGPL의 copyleft가 `sbom-tools`의 **Apache-2.0 코드로 전파되지 않습니다**(FSF 기준: 파이프/CLI/exec = 별개 프로그램, 컨테이너 번들 = mere aggregation).
- 다만 도구 바이너리를 이미지로 **재배포**하므로, 각 도구의 라이선스 텍스트와 (GPL 도구의) 대응 소스 접근 경로를 제공합니다(아래 표의 Source URL이 그 경로입니다).
- **AGPL 라이선스 도구는 포함하지 않습니다.** 따라서 웹 UI(`--ui`) 사용 시에도 AGPL §13 네트워크 조항이 트리거되지 않습니다.
- **GPL 도구는 별도 opt-in 이미지(`sbom-scanner-firmware`)에만** 포함되며, **기본 이미지(`sbom-scanner`)는 permissive-only**로 유지됩니다.

## 기본 이미지 — `ghcr.io/sktelecom/sbom-scanner` (permissive-only)

| 도구 | 용도 | 라이선스 (SPDX) | Source |
|------|------|------------------|--------|
| cdxgen (공식 언어 이미지) | 소스 SBOM 생성 | Apache-2.0 | https://github.com/CycloneDX/cdxgen |
| syft | 이미지/바이너리/디렉터리 SBOM | Apache-2.0 | https://github.com/anchore/syft |
| Trivy | 보안 취약점 스캔 | Apache-2.0 | https://github.com/aquasecurity/trivy |
| trivy-db | 취약점 DB | Apache-2.0 | https://github.com/aquasecurity/trivy-db |
| cosign | SBOM 서명 | Apache-2.0 | https://github.com/sigstore/cosign |
| scancode-toolkit | 정밀 라이선스(opt-in) | Apache-2.0 (데이터셋 일부 CC-BY-4.0 등) | https://github.com/aboutcode-org/scancode-toolkit |
| jq | SBOM 가공(헬퍼) | MIT (일부 컴포넌트 BSD/ICU/Lucent) | https://github.com/jqlang/jq |

> 데이터: NVD(취약점 출처)는 public domain이며 "NIST/NVD" 출처 표시가 요구됩니다.

## 펌웨어 이미지 — `ghcr.io/sktelecom/sbom-scanner-firmware` (GPL 포함, opt-in)

> 무거운 언팩·바이너리 분석 도구와 GPL 컴포넌트를 격리하기 위한 별도 opt-in 이미지입니다.
> 빌드: `docker build --build-arg SBOM_FIRMWARE=true -t sbom-scanner-firmware ./docker`.
> 설계는 [docs/firmware-analysis.md](docs/firmware-analysis.md) 참조.

아래 버전은 `docker/Dockerfile`의 빌드 ARG 기본값과 일치합니다(공급망 위생을 위한 핀; ARG로 재정의 가능).

| 도구 | 핀 버전 (ARG) | 용도 | 라이선스 (SPDX) | Copyleft | Source |
|------|------|------|------------------|----------|--------|
| unblob | 26.3.30 (`UNBLOB_VERSION`) | 펌웨어 언팩(주) | MIT | permissive | https://github.com/onekey-sec/unblob |
| binwalk | 2.1.0 (`BINWALK_VERSION`) | 언팩 폴백 | MIT | permissive | https://github.com/ReFirmLabs/binwalk |
| cve-bin-tool | 3.4 (`CVE_BIN_TOOL_VERSION`) | stripped 바이너리 식별+CVE | **GPL-3.0** | strong | https://github.com/intel/cve-bin-tool |
| ubi_reader | 0.8.13 (`UBI_READER_VERSION`) | UBI/UBIFS 추출 | **GPL-3.0** | strong | https://github.com/onekey-sec/ubi_reader |
| squashfs-tools, e2fsprogs, p7zip, unar, cpio, cabextract 등 | (apt 배포 버전) | unblob/binwalk가 호출하는 추출 바이너리 | GPL-2.0+ / 기타 | strong/various | Debian 패키지 |

### 폴백·선택 도구 (기본 미설치)

- **BANG** (GPL-3.0, https://github.com/armijnhemel/binaryanalysis-ng): `scan-firmware.sh`는 `bang-scanner`가 PATH에 있으면 언팩 폴백으로 사용합니다. 의존성이 무거워 기본 이미지에는 포함하지 않으며, 필요 시 별도로 설치하면 자동 인식됩니다(폴백 순서: unblob → BANG → binwalk).
- **sasquatch** (GPL-2.0, https://github.com/onekey-sec/sasquatch): 벤더가 변형한 비표준 squashfs 추출용. 표준 squashfs는 `squashfs-tools`(unsquashfs)로 충분하므로 기본 미포함입니다.

### GPL 소스 오퍼 (펌웨어 이미지)
위 GPL 도구들은 모두 공개 저장소/패키지 레지스트리에서 고정 버전으로 취득됩니다. `sbom-tools`는 이미지에 설치된 것과 **동일한 버전의 대응 소스코드**를 위 Source URL(해당 버전 태그/릴리스)에서 제공받을 수 있도록 보장합니다. 펌웨어 이미지에는 `com.sktelecom.sbom.gpl-source-offer` 라벨로 본 문서 경로가 임베드됩니다. 추가 요청은 프로젝트 저장소 이슈로 문의하십시오.

---

*이 문서는 일반적 컴플라이언스 정리이며 법률 자문이 아닙니다. 라이선스는 각 프로젝트의 최신 LICENSE 파일을 기준으로 합니다.*
