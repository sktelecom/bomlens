---
description: 패키지 매니저가 없는 C/C++ 임베디드 소스에 소스째 포함(vendored)된 오픈소스를 식별합니다. 거의 빈 SBOM이 버전·CVE를 갖춘 컴포넌트 목록으로 바뀝니다.
---

# 내장 오픈소스 식별 (C/C++)

C/C++ 임베디드 소스를 스캔했는데 BomLens가 거의 아무것도 못 찾을 때 사용합니다.

## 언제 필요한가

일반 스캔은 패키지 매니저(npm, Maven, pip, Go, Conan 등)를 읽어 프로젝트가 어떤 오픈소스를 쓰는지 파악합니다. C/C++ 임베디드 펌웨어에는 대개 패키지 매니저가 없고, 오픈소스가 소스 트리에 그대로 복사돼 있습니다. 예를 들어 `third_party/` 아래에 openssl·zlib·liblfds 사본이 들어가는 식인데, 이를 소스째 포함(vendored)이라고 합니다. cdxgen은 이런 파일의 이름을 알 수 없어, SBOM이 거의 비고 각 파일이 식별 안 된 `pkg:generic` 항목으로만 나옵니다.

이 상황이 되면 BomLens가 이 옵션을 권하는 한 줄 안내를 출력하고, 웹 UI도 스캔 후 같은 안내를 보여줍니다. 사용자가 직접 상황을 알아챌 필요는 없습니다.

![희소한 C/C++ 스캔에서 identify-vendored를 권하는 결과 배너](../images/web-ui-vendored-banner-en.png)

`--identify-vendored`는 소스 파일의 지문을 공개 OSSKB 지식 베이스와 대조해, 일치한 항목을 이름·버전·PURL을 갖춘 컴포넌트로 기록합니다. 그러면 복사돼 들어간 오픈소스가 SBOM에 드러나고, 알려진 CVE가 있는 라이브러리는 보안 보고서에도 나타납니다.

## 무엇이 전송되나

OSSKB 서비스로는 파일 **지문(해시)**만 전송됩니다. 소스 코드는 기기를 떠나지 않습니다. 공급사는 계약 전에 자기 환경에서 그대로 실행할 수 있습니다.

## 패키지 매니저가 있는 프로젝트에서는

이 옵션은 패키지 매니저가 없는 소스를 위한 것입니다. npm·Maven·pip·Go 등을 쓰는 프로젝트라면 일반 스캔이 이미 의존성을 해석하므로 필요하지 않습니다. 그래도 켜면 BomLens가 결과를 정합화합니다. 의존성·빌드 디렉터리(`node_modules`, `vendor`, `dist` 등)는 건너뛰고, 패키지 매니저 컴포넌트가 이미 가진 이름과 겹치는 매치는 그 권위 있는 식별을 우선해 제거합니다. 그래서 관리 프로젝트에서 켜도 알려진 의존성이 중복되거나 취약점 수가 부풀지 않으며, 기껏해야 패키지 매니저가 못 본 진짜 복사된 소스만 추가됩니다.

매치는 출처와 신뢰도가 태깅된 채 읽기 전용으로 기록됩니다. BomLens는 accept/reject 같은 audit 워크플로를 제공하지 않습니다. 매치를 확정하거나 triage해야 하면 SBOM을 취약점 관리 시스템(Dependency-Track, TRUSCA 등)에 올려 거기서 처리하세요.

## 준비

발행된 `bomlens` 이미지(v1.4.0 이상)에는 SCANOSS 클라이언트가 이미 포함돼 있어 별도 설정이 필요 없습니다. 이미지를 최소 구성으로 직접 빌드하는 경우에만 build arg를 추가합니다.

```bash
docker build --build-arg SBOM_SCANOSS=true -t bomlens ./docker
```

## 실행

```bash
scan-sbom.sh --project trelay --version 26.4.0 --target ./src \
  --identify-vendored --all --generate-only
```

웹 UI에서는 **고급**을 펼쳐 **내장 오픈소스 식별**을 켭니다. 이 옵션은 소스 스캔이면서 이미지가 지원할 때만 보입니다.

![고급 섹션의 내장 오픈소스 식별 토글](../images/web-ui-identify-vendored-en.png)

## 결과

- 복사된 오픈소스가 버전을 가진 컴포넌트로 SBOM에 나타나며, 각 항목에 `vendored` 표시(`bomlens:layer=vendored` 속성)가 붙습니다.
- 알려진 제품으로 매핑되는 컴포넌트에는 CPE가 붙어, Trivy 보안 보고서에 해당 CVE가 나열됩니다. 예를 들어 vendored된 `openssl 1.1.1w`는 관련 취약점과 함께 나타납니다.
- 취약점 데이터베이스에 기록이 없는 흔치 않은 라이브러리(예: `liblfds`, `libaes`, `djbdns`)는 이름과 버전까지 식별됩니다. 보고할 CVE가 없을 뿐이며, 이는 스캔이 아니라 공개 데이터의 한계입니다.

파일 단위 전체 일치만 컴포넌트가 됩니다. 부분(스니펫) 일치는 노이즈가 커서 제외하므로 보고서가 깔끔하게 유지됩니다.

![vendored 표시와 일치도가 달린 컴포넌트 표](../images/web-ui-vendored-badge-en.png)

## 엔드포인트와 제한

기본 엔드포인트는 무료 OSSKB API로, 요청 빈도 제한이 있고 식별 전용입니다. 대량 사용이나 에어갭 환경에서는 SCANOSS 상용·자체 호스팅 엔드포인트를 지정하세요.

```bash
SCANOSS_API_URL=https://your-scanoss-endpoint \
SCANOSS_API_KEY=your-key \
scan-sbom.sh --project trelay --version 26.4.0 --target ./src --identify-vendored --all --generate-only
```

버전은 근사값입니다. 파일 매치는 그 파일 내용이 처음 등장한 릴리스를 버전으로 보고하므로, 같은 라이브러리라도 파일마다 버전이 조금씩 다르게 나오거나 실제보다 한 단계 어긋난 릴리스로 보고될 수 있습니다. 버전(과 그로부터 도출된 CVE)은 최종 판정이 아니라 검토의 출발점으로 삼으세요.

귀속(어느 프로젝트인지)도 틀릴 수 있습니다. 여러 프로젝트가 흔히 복사하는 파일(예: zlib의 `deflate.c`)은 정식 upstream이 아니라 그것을 vendored한 다운스트림 프로젝트로 매치될 수 있습니다. 이 노이즈를 줄이기 위해 BomLens는 **최소 두 개 이상의 파일이 지지하는 라이브러리만 보고**하고(`SCANOSS_MIN_FILES`로 조정, `1`이면 모두 유지) 버전·PURL은 그 파일들의 **다수결**로 정합화합니다. 그래서 단발성 포크 매치는 떨어지고, 여러 포크로 흩어진 라이브러리는 하나의 컴포넌트로 합쳐집니다. 다만 완전한 해결은 아니며, 실제 사본이 여전히 다른 이름으로 보고되고 그 CVE를 놓칠 수 있습니다. 이는 지식 베이스의 랭킹·커버리지 한계이며 무료 OSSKB에서 더 두드러집니다. 더 정확한 귀속이 필요하면 `SCANOSS_API_URL`을 SCANOSS 상용·자체 호스팅 엔드포인트로 지정하세요. 또한 공개 저장소에 이미 게시된 소스를 스캔하면 그 저장소로 매치됩니다(자기 1st-party 파일이 자기 공개 프로젝트로 매치) — 의도한 용도인 비공개 공급사 소스에서는 발생하지 않습니다.

결과는 사람 검토가 도움이 되는 best-effort 추정입니다. OSSKB 약관과 라이선스 설명은 [THIRD_PARTY_LICENSES.md](https://github.com/sktelecom/sbom-tools/blob/main/THIRD_PARTY_LICENSES.md)를 참조하세요.
