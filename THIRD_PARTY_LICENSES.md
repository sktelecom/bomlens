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

> **구현 예정.** 무거운 언팩·바이너리 분석 도구와 GPL 컴포넌트를 격리하기 위한 별도 이미지입니다. 설계는 [docs/firmware-analysis.md](docs/firmware-analysis.md) 참조.

| 도구 | 용도 | 라이선스 (SPDX) | Copyleft | Source |
|------|------|------------------|----------|--------|
| unblob | 펌웨어 언팩 | MIT | permissive | https://github.com/onekey-sec/unblob |
| binwalk | 언팩(보조) | MIT | permissive | https://github.com/ReFirmLabs/binwalk |
| BANG | 언팩 폴백 | **GPL-3.0** | strong | https://github.com/armijnhemel/binaryanalysis-ng |
| cve-bin-tool | stripped 바이너리 식별+CVE | **GPL-3.0** | strong | https://github.com/intel/cve-bin-tool |
| sasquatch (unblob 의존) | squashfs 추출 | **GPL-2.0** | strong | https://github.com/onekey-sec/sasquatch |
| ubi_reader (unblob 의존) | UBI/UBIFS 추출 | **GPL-3.0** | strong | https://github.com/onekey-sec/ubi_reader |

### GPL 소스 오퍼 (펌웨어 이미지)
위 GPL 도구들은 모두 공개 저장소/패키지 레지스트리에서 고정 버전으로 취득됩니다. `sbom-tools`는 이미지에 설치된 것과 **동일한 버전의 대응 소스코드**를 위 Source URL(해당 버전 태그/릴리스)에서 제공받을 수 있도록 보장합니다. 추가 요청은 프로젝트 저장소 이슈로 문의하십시오.

---

*이 문서는 일반적 컴플라이언스 정리이며 법률 자문이 아닙니다. 라이선스는 각 프로젝트의 최신 LICENSE 파일을 기준으로 합니다.*
