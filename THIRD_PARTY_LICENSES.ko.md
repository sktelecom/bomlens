# Third-Party Licenses

> **English**: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)

BomLens(Apache-2.0)는 자체 코드를 셸 스크립트로 두고, SBOM 생성과 분석에 쓰는 여러 오픈소스 도구를 Docker 이미지에 번들합니다. 이 문서는 번들 도구의 라이선스 인벤토리와 배포 의무를 정리합니다.

## 컴플라이언스 요지

- BomLens의 셸 스크립트는 번들 도구를 별도 프로세스로 호출(exec)할 뿐 도구 소스를 수정하지 않습니다. 그래서 GPL/AGPL의 copyleft가 BomLens의 Apache-2.0 코드로 전파되지 않습니다(FSF 기준: 파이프/CLI/exec = 별개 프로그램, 컨테이너 번들 = mere aggregation).
- 다만 도구 바이너리를 이미지로 재배포하므로, 라이선스 전문과 (GPL 도구의) 대응 소스 접근 경로를 제공합니다. SPDX 라이선스 전문(Apache-2.0, MIT, GPL-2.0, GPL-3.0 등)은 이미지 안 `/usr/local/lib/sbom/licenses/`에 동봉되며, 각 도구의 소스는 아래 표의 Source URL에서 받습니다.
- BomLens 자신의 이용 조건도 배포물에 함께 나갑니다. 이미지에서는 `/usr/local/lib/sbom/notices/`에 `LICENSE`와 `NOTICE`, 이 문서가 들어 있고, 릴리스 번들에서는 압축을 풀면 최상위에, 데스크톱 설치본에서는 앱 리소스 폴더에 있습니다. 이미지나 번들을 다시 배포하실 때 이 파일들을 함께 전달하시면 Apache-2.0 §4의 요구가 충족됩니다.
- AGPL 라이선스 도구는 포함하지 않습니다. 따라서 웹 UI(`--ui`)를 써도 AGPL §13 네트워크 조항은 트리거되지 않습니다.
- GPL 도구는 별도 opt-in 이미지(`bomlens-firmware`)에만 들어가고, 기본 이미지(`bomlens`)는 permissive-only로 유지됩니다. 다른 opt-in 이미지(`bomlens-aibom`, `bomlens-deep-cve`)도 permissive 도구만 담습니다.

## 기본 이미지 — `ghcr.io/sktelecom/bomlens` (permissive-only)

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

### 웹 UI npm 패키지

웹 UI(`--ui`)는 React 단일 페이지 애플리케이션입니다. 빌드 결과에 npm 패키지 코드가 함께 들어가고 그 결과물이 기본 이미지와 데스크톱 설치본으로 배포되므로, MIT와 ISC가 요구하는 저작권·허가 고지가 배포물에 함께 있어야 합니다.

정본은 빌드 시 생성되는 `third-party-licenses.txt`입니다. 번들에 실제로 들어간 패키지만 골라 각 패키지의 라이선스 전문을 그대로 담으며, 웹 UI에서 `/third-party-licenses.txt`로 열 수 있고 이미지 안에서는 `/usr/local/lib/sbom-web/dist/third-party-licenses.txt`에 있습니다. `package.json`의 선언 목록이 아니라 번들 그래프에서 뽑는 이유는 두 목록이 다르기 때문입니다. 선언된 의존성 중 tailwindcss나 typescript처럼 빌드에만 쓰이는 것은 배포물에 들어가지 않고, 반대로 선언되어 설치까지 되었지만 아무 곳에서도 가져다 쓰지 않아 번들에서 빠지는 것도 있습니다.

아래는 현재 번들에 들어가는 23개 패키지입니다. 모두 permissive이며 copyleft는 없습니다.

| 패키지 | 용도 | 라이선스 (SPDX) |
|--------|------|------------------|
| react, react-dom, scheduler | UI 렌더링 | MIT |
| @radix-ui/react-label, react-progress, react-slot, react-primitive, react-context, react-compose-refs | 접근성 있는 기본 컴포넌트 | MIT |
| cytoscape, cytoscape-dagre, dagre, graphlib, lodash | 의존성 그래프 시각화와 배치 | MIT |
| i18next, react-i18next, i18next-browser-languagedetector | 한국어·영어 전환 | MIT |
| class-variance-authority | 컴포넌트 변형 정의 | Apache-2.0 |
| clsx, tailwind-merge | 클래스 이름 결합 | MIT |
| lucide-react | 아이콘 | ISC |
| @fontsource/inter, @fontsource/jetbrains-mono | 글꼴(아래 절 참고) | OFL-1.1 |

목록이 낡지 않도록 `npm run notices:check`가 생성 파일을 검사합니다. 라이선스를 선언하지 않은 패키지, 전문을 찾지 못한 패키지, copyleft 라이선스가 하나라도 있으면 CI가 실패합니다.

### 웹 UI 컴포넌트 (shadcn/ui에서 가져와 고친 코드)

shadcn/ui는 패키지로 설치하는 라이브러리가 아니라 컴포넌트 코드를 프로젝트에 복사해 쓰는 방식입니다. 그래서 npm 의존성 목록에는 나타나지 않지만 코드는 저장소 안에 있습니다. `docker/web/frontend/src/components/ui/`의 다음 7개 파일이 shadcn/ui의 컴포넌트를 가져와 디자인 토큰과 접근성 요구에 맞게 고친 것입니다.

| 파일 | 원본 |
|------|------|
| `badge.tsx`, `button.tsx`, `card.tsx`, `input.tsx`, `label.tsx`, `progress.tsx`, `tabs.tsx` | shadcn/ui (MIT, Copyright (c) 2023 shadcn), https://github.com/shadcn-ui/ui |

일곱 파일에는 원본의 MIT 고지와 우리 수정분의 저작권 표기가 함께 들어 있고, 파일 라이선스는 `SPDX-License-Identifier: Apache-2.0 AND MIT`로 표기했습니다. MIT 전문은 이미지 안 `/usr/local/lib/sbom/licenses/MIT.txt`에 있습니다.

같은 디렉터리의 `barlist.tsx`, `select.tsx`, `state.tsx`, `switch.tsx`는 직접 작성한 것이라 Apache-2.0 단독입니다. `switch.tsx`는 shadcn/ui의 겉모양(트랙과 손잡이 크기)을 참고했을 뿐 구현은 네이티브 체크박스로 따로 작성했습니다.

### 웹 UI 폰트

웹 UI(`--ui`)는 타이포그래피 일관성과 오프라인·데스크톱(Electron) 동작을 위해 두 글꼴을 `@fontsource`로 번들합니다. 글꼴 파일(woff2)은 빌드 시 웹 SPA에 포함되어 기본 이미지로 함께 배포되며, 외부 폰트 CDN을 호출하지 않습니다.

| 글꼴 | 용도 | 라이선스 (SPDX) | Source |
|------|------|------------------|--------|
| Inter | 본문·UI 서체 | OFL-1.1 | https://github.com/rsms/inter |
| JetBrains Mono | 코드·고정폭 서체 | OFL-1.1 | https://github.com/JetBrains/JetBrainsMono |

SIL Open Font License 1.1은 출처(저작권) 표시를 요구하며, 두 글꼴 모두 원본을 수정 없이 그대로 번들합니다.

- Inter: Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter)
- JetBrains Mono: Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono)

OFL-1.1 전문은 위 Source의 각 저장소 `OFL.txt`에서 받을 수 있습니다.

### vendored 오픈소스 식별과 OSSKB API (opt-in)

`--identify-vendored`는 클라이언트 `scanoss.py`(MIT)만 번들합니다. 이 클라이언트는 기본 빌드에 포함되며, 빼려면 `docker build --build-arg SBOM_SCANOSS=false`로 빌드합니다. SBOM 매칭을 수행하는 SCANOSS Engine(GPL-2.0)은 **포함하지 않으며**, 호스팅 OSSKB API(`api.osskb.org`)를 호출합니다. 그래서 firmware 이미지의 GPL 도구와 달리 base 이미지에 둘 수 있습니다(MIT). 동봉 데이터셋 `osadl-copyleft.json`은 코드가 아닌 CC-BY-4.0 데이터로, 출처 표기만 요구됩니다.

OSSKB API(운영: Software Transparency Foundation) 이용 시 약관 제약:

- 전송되는 것은 소스 코드가 아니라 **파일 지문(해시)**뿐입니다.
- 반환 데이터는 **소프트웨어 식별 목적으로만** 사용할 수 있고, OSSKB 데이터를 **재배포·별도 DB로 캐싱하는 것은 금지**됩니다. BomLens는 스캔별 SBOM 컴포넌트로만 결과를 내보내므로 이 범위 안입니다.
- 무료로 제공되며 품질을 보장하지 않고, 요청 빈도 제한이 있습니다. 구체적 한도 수치는 공개돼 있지 않고 약관상 재량 사항입니다(원문: "STF may limit the number or frequency of transactions per user through the OSSKB"). 스캔은 파일마다 지문을 조회하므로 큰 소스 트리를 반복해서 스캔하면 제한에 걸립니다. 한 번 식별해 보는 용도로 쓰시고, 대량으로 반복하거나 전사에서 운용하거나 외부 통신이 막힌 환경이라면 `SCANOSS_API_URL`과 `SCANOSS_API_KEY`로 SCANOSS 상용 서비스나 자체 호스팅 엔드포인트를 지정하세요.
- 결과는 "사람 검토가 필요한 식별 힌트"로 제공됩니다(정확도 무보증).
- 약관 원문: https://www.softwaretransparency.org/terms

## 펌웨어 이미지 — `ghcr.io/sktelecom/bomlens-firmware` (GPL 포함, opt-in)

> 무거운 언팩·바이너리 분석 도구와 GPL 컴포넌트를 격리하기 위한 별도 opt-in 이미지입니다.
> 빌드: `docker build --build-arg SBOM_FIRMWARE=true -t bomlens-firmware ./docker`.
> 설계는 [docs/maintainers/firmware-analysis.md](docs/maintainers/firmware-analysis.md) 참조.

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

## deep-cve 이미지 — `ghcr.io/sktelecom/bomlens-deep-cve` (permissive, opt-in)

> `--deep-cve`용 별도 opt-in 이미지입니다. grype의 CPE 매처로 Trivy가 놓치는 NVD 전용 Maven CVE를 찾습니다. 취약점 DB가 커서(약 1.8 GB) 기본 이미지에서 분리했으며, 필요할 때 자동으로 내려받습니다.
> 빌드: `docker build --build-arg SBOM_DEEP_CVE=true -t bomlens-deep-cve ./docker`.

아래 버전은 `docker/Dockerfile`의 빌드 ARG 기본값과 일치합니다(핀; ARG로 재정의 가능).

| 도구 | 핀 버전 (ARG) | 용도 | 라이선스 (SPDX) | Copyleft | Source |
|------|------|------|------------------|----------|--------|
| grype | v0.112.0 (`GRYPE_VERSION`) | CPE 기반 NVD CVE 매칭 | Apache-2.0 | permissive | https://github.com/anchore/grype |

> 데이터: 빌드 시 이미지에 굽는 grype 취약점 DB는 Anchore가 공개 취약점 출처를 모아 만든 것입니다 — NVD(public domain), GitHub Security Advisories(CC-BY-4.0), 배포판 보안 DB(각 배포판 조건). DB는 `GRYPE_DB_AUTO_UPDATE=false`로 고정되어 스캔 중 네트워크를 쓰지 않습니다.

## Android SDK 이미지 — `ghcr.io/sktelecom/bomlens-android-sdk<API>`

cdxgen은 Android SDK를 담은 이미지를 제공하지 않고 Android를 전이 의존성 미지원으로 표시하므로, Android 프로젝트는 cdxgen에 그대로 넘길 수 없습니다. 그래서 cdxgen java 이미지 위에 Android SDK 플랫폼을 얹은 이미지를 `compileSdk`별로 하나씩(API 30~35) 둡니다. `scan-sbom.sh`가 프로젝트의 `compileSdk`를 찾아 맞는 태그를 받아 쓰고, `ANDROID_IMAGE_PREFIX`로 받아올 곳을 바꿀 수 있습니다. 옛 이름 `sbom-scanner-android-sdk<API>`는 같은 다이제스트를 가리킵니다.

이 이미지에는 BomLens 코드가 들어 있지 않아 우리 Apache-2.0 허락의 대상이 아닙니다. 들어 있는 것은 다음과 같습니다.

| 구성요소 | 출처 | 조건 |
|----------|------|------|
| cdxgen java 이미지(`cdxgen-temurin-java21`, 다이제스트 고정) | https://github.com/CycloneDX/cdxgen | Apache-2.0 |
| Android SDK 명령줄 도구, platform-tools, `platforms;android-<API>`, `build-tools;<API>.0.0` | `sdkmanager`가 https://dl.google.com/android/repository/ 에서 설치 | Android Software Development Kit License Agreement, https://developer.android.com/studio/terms |

Android SDK는 오픈소스가 아니며 Apache-2.0이 아닙니다. 약관은 Android 애플리케이션 개발 목적의 사용을 재실시권 없이 허락하고(3.1절), 제3자 라이선스가 요구하는 경우를 빼면 SDK나 그 일부의 복제와 재배포를 제한합니다(3.4절). 이 이미지를 받아 쓰시는 분은 Google 약관을 직접 적용받으며, 이미지를 쓰는 것이 약관 수락을 대신하지 않습니다.

SDK 각 구성요소의 `NOTICE.txt`는 이미지 안 `/opt/android-sdk/` 아래에 그대로 들어 있고, SDK 내용물의 제3자 고지는 거기에 있습니다. `/opt/android-sdk/licenses/`의 파일들은 라이선스 전문이 아니라 `sdkmanager`가 남긴 수락 표시입니다.

---

*이 문서는 일반적 컴플라이언스 정리이며 법률 자문이 아닙니다. 라이선스는 각 프로젝트의 최신 LICENSE 파일을 기준으로 합니다.*
