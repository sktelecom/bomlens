# Third-Party Licenses

`sbom-tools`(Apache-2.0)는 자체 코드를 셸 스크립트로 두고, SBOM 생성과 분석에 쓰는 여러 오픈소스 도구를 Docker 이미지에 번들합니다. 이 문서는 번들 도구의 라이선스 인벤토리와 배포 의무를 정리합니다.

## 컴플라이언스 요지

- `sbom-tools`의 셸 스크립트는 번들 도구를 별도 프로세스로 호출(exec)할 뿐 도구 소스를 수정하지 않습니다. 그래서 GPL/AGPL의 copyleft가 `sbom-tools`의 Apache-2.0 코드로 전파되지 않습니다(FSF 기준: 파이프/CLI/exec = 별개 프로그램, 컨테이너 번들 = mere aggregation).
- 다만 도구 바이너리를 이미지로 재배포하므로, 라이선스 전문과 (GPL 도구의) 대응 소스 접근 경로를 제공합니다. SPDX 라이선스 전문(Apache-2.0, MIT, GPL-2.0, GPL-3.0 등)은 이미지 안 `/usr/local/lib/sbom/licenses/`에 동봉되며, 각 도구의 소스는 아래 표의 Source URL에서 받습니다.
- AGPL 라이선스 도구는 포함하지 않습니다. 따라서 웹 UI(`--ui`)를 써도 AGPL §13 네트워크 조항은 트리거되지 않습니다.
- GPL 도구는 별도 opt-in 이미지(`bomlens-firmware`)에만 들어가고, 기본 이미지(`sbom-scanner`)는 permissive-only로 유지됩니다.

## 기본 이미지 — `ghcr.io/sktelecom/sbom-scanner` (permissive-only)

| 도구 | 용도 | 라이선스 (SPDX) | Source |
|------|------|------------------|--------|
| cdxgen (공식 언어 이미지) | 소스 SBOM 생성 | Apache-2.0 | https://github.com/CycloneDX/cdxgen |
| syft | 이미지/바이너리/디렉터리 SBOM | Apache-2.0 | https://github.com/anchore/syft |
| Trivy | 보안 취약점 스캔 | Apache-2.0 | https://github.com/aquasecurity/trivy |
| trivy-db | 취약점 DB | Apache-2.0 | https://github.com/aquasecurity/trivy-db |
| cosign | SBOM 서명 | Apache-2.0 | https://github.com/sigstore/cosign |
| scancode-toolkit | 정밀 라이선스(opt-in) | Apache-2.0 (데이터셋 일부 CC-BY-4.0 등) | https://github.com/aboutcode-org/scancode-toolkit |
| scanoss (scanoss.py) | vendored 오픈소스 식별(기본 포함, 끄려면 `SBOM_SCANOSS=false`) | MIT (동봉 데이터셋 `osadl-copyleft.json`은 CC-BY-4.0) | https://github.com/scanoss/scanoss.py |
| owasp-aibom-generator | AI 모델 SBOM 생성(opt-in `SBOM_AIBOM`, 별도 이미지 `bomlens-aibom`; HuggingFace API 호출) | Apache-2.0 | https://github.com/GenAI-Security-Project/aibom-generator |
| jq | SBOM 가공(헬퍼) | MIT (일부 컴포넌트 BSD/ICU/Lucent) | https://github.com/jqlang/jq |

> 데이터: NVD(취약점 출처)는 public domain이며 "NIST/NVD" 출처 표시가 요구됩니다.

### vendored 오픈소스 식별과 OSSKB API (opt-in)

`--identify-vendored`는 클라이언트 `scanoss.py`(MIT)만 번들합니다. 이 클라이언트는 기본 빌드에 포함되며, 빼려면 `docker build --build-arg SBOM_SCANOSS=false`로 빌드합니다. SBOM 매칭을 수행하는 SCANOSS Engine(GPL-2.0)은 **포함하지 않으며**, 호스팅 OSSKB API(`api.osskb.org`)를 호출합니다. 그래서 firmware 이미지의 GPL 도구와 달리 base 이미지에 둘 수 있습니다(MIT). 동봉 데이터셋 `osadl-copyleft.json`은 코드가 아닌 CC-BY-4.0 데이터로, 출처 표기만 요구됩니다.

OSSKB API(운영: Software Transparency Foundation) 이용 시 약관 제약:

- 전송되는 것은 소스 코드가 아니라 **파일 지문(해시)**뿐입니다.
- 반환 데이터는 **소프트웨어 식별 목적으로만** 사용할 수 있고, OSSKB 데이터를 **재배포·별도 DB로 캐싱하는 것은 금지**됩니다. `sbom-tools`는 스캔별 SBOM 컴포넌트로만 결과를 내보내므로 이 범위 안입니다.
- 무료·best-effort이며 **요청 빈도 제한(rate limit)**이 있습니다. 구체적 한도 수치는 공개돼 있지 않고, 약관상 재량적입니다(원문: "STF may limit the number or frequency of transactions per user through the OSSKB"). 스캔은 파일마다 지문을 조회하므로, 큰 소스 트리를 반복 스캔하면 스로틀됩니다 — 1회성 식별용입니다. 대량·반복·전사 운용이나 에어갭 환경에서는 `SCANOSS_API_URL`/`SCANOSS_API_KEY`로 SCANOSS 상용 서비스나 자체 호스팅 엔드포인트를 지정하세요.
- 결과는 "사람 검토가 필요한 식별 힌트"로 제공됩니다(정확도 무보증).
- 약관 원문: https://www.softwaretransparency.org/terms

## 펌웨어 이미지 — `ghcr.io/sktelecom/bomlens-firmware` (GPL 포함, opt-in)

> 무거운 언팩·바이너리 분석 도구와 GPL 컴포넌트를 격리하기 위한 별도 opt-in 이미지입니다.
> 빌드: `docker build --build-arg SBOM_FIRMWARE=true -t bomlens-firmware ./docker`.
> 설계는 [docs/internal/firmware-analysis.md](docs/internal/firmware-analysis.md) 참조.

아래 버전은 `docker/Dockerfile`의 빌드 ARG 기본값과 일치합니다(공급망 위생을 위한 핀; ARG로 재정의 가능).

| 도구 | 핀 버전 (ARG) | 용도 | 라이선스 (SPDX) | Copyleft | Source |
|------|------|------|------------------|----------|--------|
| unblob | 26.3.30 (`UNBLOB_VERSION`) | 펌웨어 언팩(주) | MIT | permissive | https://github.com/onekey-sec/unblob |
| cve-bin-tool | 3.4 (`CVE_BIN_TOOL_VERSION`) | stripped 바이너리 식별+CVE | **GPL-3.0** | strong | https://github.com/intel/cve-bin-tool |
| ubi_reader | 0.8.13 (`UBI_READER_VERSION`) | UBI/UBIFS 추출 | **GPL-3.0** | strong | https://github.com/onekey-sec/ubi_reader |
| squashfs-tools(unsquashfs) | (apt 배포 버전) | 표준 squashfs 추출 폴백 | GPL-2.0+ | strong | https://github.com/plougher/squashfs-tools |
| e2fsprogs, p7zip, unar, cpio, cabextract, jefferson 등 | (apt 배포 버전) | unblob가 호출하는 추출 바이너리 | GPL-2.0+ / 기타 | strong/various | Debian 패키지 |

### 폴백·선택 도구 (기본 미설치)

- BANG (GPL-3.0, https://github.com/armijnhemel/binaryanalysis-ng): `scan-firmware.sh`는 `bang-scanner`가 PATH에 있으면 언팩 폴백으로 사용합니다. 의존성이 무거워 기본 이미지에는 넣지 않으며, 필요할 때 따로 설치하면 자동으로 인식합니다. 언팩 폴백은 unblob, BANG, unsquashfs(squashfs), binwalk 순으로 시도합니다.
- binwalk: PyPI `binwalk` 2.x 배포본이 손상(`binwalk.core` 누락)되어 이미지에 설치하지 않습니다. `scan-firmware.sh`는 PATH에 정상 `binwalk`가 있으면 최후 폴백으로 쓰지만, 표준 squashfs는 그 전 단계인 unsquashfs가 처리합니다.
- sasquatch (GPL-2.0, https://github.com/onekey-sec/sasquatch): 벤더가 변형한 비표준 squashfs 추출용으로 unblob 핸들러가 사용합니다. 표준 squashfs는 `squashfs-tools`(unsquashfs) 폴백으로 충분하므로 기본 이미지에는 넣지 않습니다.

### GPL 소스 코드 제공 (펌웨어 이미지)
펌웨어 이미지에 들어가는 GPL 도구는 모두 공개 저장소나 패키지 레지스트리에서 버전을 고정해 받습니다. **GPL 라이선스 전문(GPL-2.0, GPL-3.0)은 이미지 안 `/usr/local/lib/sbom/licenses/`에 함께 배포됩니다.** 이미지에 설치된 것과 같은 버전의 소스 코드는 위 표의 Source URL(해당 버전 태그/릴리스)에서 그대로 받을 수 있고, 펌웨어 이미지에는 이 문서의 위치가 `com.sktelecom.sbom.gpl-source-offer` 라벨로 박혀 있습니다. 소스가 더 필요하면 저장소 이슈로 요청해 주세요.

---

*이 문서는 일반적 컴플라이언스 정리이며 법률 자문이 아닙니다. 라이선스는 각 프로젝트의 최신 LICENSE 파일을 기준으로 합니다.*
