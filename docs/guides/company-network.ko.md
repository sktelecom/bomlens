---
description: 사내 패키지 저장소에서 의존성을 받는 프로젝트를 스캔하는 방법을 설명합니다. 프로젝트가 이미 빌드되는 곳에서 스캔하거나, 빌드 없이 lock 파일을 읽거나, 빌드로 만든 SBOM을 분석합니다. 프록시와 사내 인증서 설정은 보조 수단입니다.
---

# 사내 패키지 저장소가 필요한 프로젝트는 어떻게 스캔하나요?

소스 스캔은 컨테이너 안에서 패키지 관리자를 실행해 의존성을 해석합니다. 프로젝트가 쓰는 정확한 버전은 그 프로젝트를 빌드하는 환경에서 나옵니다. 사내 저장소 로그인, 미러, VPN이 그 환경에 있습니다. 스캔 컨테이너에는 이것들이 다 갖춰져 있지 않습니다. 그래서 사내 저장소가 필요한 프로젝트는 이미 빌드가 되는 곳에서 스캔하고, 아래의 프록시와 인증서 설정은 보조 수단으로 씁니다.

## 어디에서 스캔해야 하나요?

아래에서 맞는 첫 번째 방법을 고릅니다.

1. 프로젝트에 완전한 lock 파일이 있는 경우입니다. `--detection static`을 쓰면 BomLens가 lock 파일을 읽고 빌드를 하지 않으므로 사내 저장소에 접근할 필요가 없습니다. `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock`, `gradle.lockfile` 중 하나가 트리 전체를 덮으면 `auto`가 알아서 이 방식을 씁니다. lock 파일에 없는 라이선스는 공개 레지스트리에서 채우므로, 사내 패키지의 라이선스는 비어 있을 수 있습니다. lock 파일을 커밋하지 않았더라도 이 컴퓨터에서 설치한 Node.js 프로젝트는 npm이나 pnpm이 `node_modules` 아래에 써 둔 lock 파일을 읽으므로, 레지스트리 없이 전체 의존성 그래프를 해석합니다. 이 lock에는 한 컴퓨터의 설치 결과만 담기므로 이 스캔은 여전히 빌드합니다([Node.js](../reference/ecosystems.ko.md#nodejs)).
2. 빌드에서 SBOM을 이미 만들거나 만들 수 있는 경우입니다. 프로젝트를 빌드하는 기계에서 SBOM을 만든 뒤(예: Maven용 CycloneDX 플러그인 `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom`, 또는 `npx @cyclonedx/cyclonedx-npm --output-file bom.json`) `--analyze bom.json`으로 검증하고 분석합니다. 검사 항목과 얻는 보고서는 [공급사 SBOM 검증 가이드](supplier-sbom.ko.md)에 있습니다. BomLens는 입력한 SBOM을 바꾸지 않습니다.
3. CI 러너나 빌드 기계에서 BomLens를 실행할 수 있는 경우입니다. 빌드가 이미 설정을 갖춘 그 자리에서 스캔합니다. Docker가 없는 러너를 포함한 방법은 [CI/CD 연동](ci-cd.ko.md)을 참고합니다.
4. 위 방법을 모두 쓸 수 없는 경우입니다. 본인 기계에서 아래의 프록시와 인증서 설정으로 스캔합니다. Maven과 Gradle 설정 파일은 스캔에 전달됩니다([Maven 가이드](java-maven.ko.md#사내-저장소도-되나요)). 이 컴퓨터에서 빌드한 Maven 프로젝트는 스캔이 사내 저장소에 접속하지 못해도 사용자의 Maven 로컬 저장소(`~/.m2/repository`, 또는 `settings.xml`의 `<localRepository>`, 읽기 전용)에서 해석합니다([Java (Maven)](../reference/ecosystems.ko.md#java-maven)). 이 컴퓨터에서 빌드한 Gradle 프로젝트는 스캔이 사내 저장소에 접속하지 못해도 사용자의 Gradle 캐시(`~/.gradle/caches`, 읽기 전용)에서 해석합니다([Java (Gradle)](../reference/ecosystems.ko.md#java-gradle)). 이 컴퓨터의 가상 환경(`.venv/`, `venv/`)에 의존성을 설치해 둔 Python 프로젝트는 스캔이 패키지 저장소를 쓰지 못하면 그 환경을 읽기 전용으로 읽어 해석합니다([Python](../reference/ecosystems.ko.md#python)). npm과 pip 설정 파일, 그리고 미러 변수는 전달되지 않으므로, 로그인이 있어야 해석되는 npm 프로젝트와 가상 환경이 폴더에 없는 pip 프로젝트는 이 방식에서 결과가 적게 나오는 것이 보통입니다.

구성요소 개수를 본인 빌드가 보고하는 개수와 비교합니다. 훨씬 적으면 해석이 실패한 것입니다. 패키지 저장소가 일부 다운로드의 로그인을 거부한 채 SBOM이 만들어졌으면 스캔 로그에 `[WARN]` 한 줄이 나오고, SBOM에 `bomlens:registry-refused`가 기록되며, 웹 UI 개요에 "일부 의존성이 빠졌을 수 있습니다" 경고가 나타납니다([산출물](../reference/artifacts.ko.md)).

lock 파일이 없는 Node.js 프로젝트는 프로젝트 `.npmrc`가 가리키는 레지스트리에서 npm install로 해석합니다. 스캔은 먼저 그 레지스트리에 로그인 정보 없이 한 번 응답을 요청합니다. 응답이 없거나 TLS 인증서를 신뢰할 수 없으면 npm의 재시도를 기다리지 않습니다. npm은 캐시만으로 해석하고, 스캔은 몇 초 안에 끝나며, `node_modules`나 그 캐시에 있는 것만 목록에 올리고, 실패한 단계 `npm-registry:network` 또는 `npm-registry:tls-trust`를 기록합니다. 스캔 로그에는 레지스트리와 원인이 남습니다([Node.js](../reference/ecosystems.ko.md#nodejs)). 캐시에 의존성이 모두 있었다면 실패한 단계를 지우고 대신 `bomlens:prep-step-applied`에 `npm-offline-cache`를 기록합니다. CLI는 `[INFO]` 줄을, 웹 UI 개요는 안내를 보여 줍니다. 두 곳 모두 버전이 `package.json`이 허용하는 범위에서 캐시에 있는 가장 새 버전이라 최신 릴리스가 아닐 수 있다고 알립니다.

## 프록시는 어떻게 설정하나요?

`scan-sbom.sh`를 실행하는 셸의 `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`(소문자 이름 포함)는 이름 그대로 스캔 컨테이너에 전달됩니다. 이 기계의 루프백 주소(`127.0.0.1`, `localhost`)에 있는 프록시는 전달하지 않습니다. 컨테이너 안에서 그 주소는 컨테이너 자신이기 때문입니다. 이때는 Docker 자체의 프록시 설정이 적용됩니다. 데스크톱 앱은 프록시 변수를 전달하지 않으므로, 그쪽에서는 Docker 엔진에 프록시를 설정합니다.

## 사내 인증서는 어떻게 신뢰하게 하나요?

HTTPS를 검사하는 프록시는 사내 인증기관(CA)으로 다시 서명하고, 스캔 컨테이너는 그 인증기관을 믿지 않습니다. 호스트마다 검사 여부가 달라서 한 저장소는 실패하고 다른 저장소는 되는 경우도 있습니다. 인증기관을 PEM 파일로 BomLens에 줍니다.

```bash
SBOM_EXTRA_CA_CERTS=/path/to/company-ca.pem ./scripts/scan-sbom.sh --target ./my-project --generate-only
```

이 파일은 스캔 컨테이너의 시스템 저장소, Node.js, Java 신뢰 저장소에 추가됩니다. 신뢰할 수 없는 인증서 때문에 스캔이 실패하면 이 옵션을 알려 주는 `[WARN]` 줄이 출력됩니다. npm은 cdxgen 로그에 `SELF_SIGNED_CERT_IN_CHAIN`으로 보고하며, 그런 저장소를 상대로 의존성 단계가 진행 없이 몇 분씩 이어지는 것도 같은 원인을 가리킵니다. Windows에서 데스크톱 앱은 `SBOM_EXTRA_CA_CERTS`를 환경 변수로 읽고, 배치 실행 파일은 `bomlens.settings.txt`에서 읽습니다([설정 파일](../start/no-cli.ko.md#설정-파일-명령줄-불필요)).

## Docker 엔진 자체의 프록시와 인증서는 어떻게 하나요?

이미지 내려받기는 BomLens가 아니라 Docker 엔진이 하므로, 셸에 설정한 프록시나 인증기관은 여기에 효과가 없습니다. 첫 스캔이 이미지 내려받기에서 멈추면 다음을 순서대로 확인합니다.

- 터미널에서 `docker pull hello-world`를 실행합니다. 같은 방식으로 실패하면 BomLens가 아니라 엔진 설정의 문제입니다.
- 사용하는 Docker 제품의 프록시 설정입니다. Docker Desktop은 `Settings > Resources > Proxies`, Windows의 Rancher Desktop은 `Preferences > WSL > Proxy`에 있습니다.
- 엔진이 사내 인증기관을 신뢰하는지 확인합니다. HTTPS를 검사하는 프록시는 내려받기 오류에 `x509: certificate signed by unknown authority`로 나타납니다. 인증기관을 추가하는 방법은 제품과 호스트 시스템마다 달라서 해당 제품의 문서를 따릅니다. `SBOM_EXTRA_CA_CERTS`는 이미지 내려받기에는 적용되지 않습니다.
- 어떤 저장소에도 닿지 않는 호스트는 파일에서 이미지를 불러올 수 있습니다. [CLI 레퍼런스](../reference/cli.ko.md)의 `SBOM_IMAGE_TAR`와 `SBOM_PULL=never`를 참고합니다.

## 로그와 결과 파일에는 무엇이 남나요?

스캔의 콘솔 출력, 웹 UI 로그, `{Project}_{Version}_cdxgen.log`로 남기는 cdxgen 로그에서는 자격 증명을 가립니다. 가리는 대상은 URL의 사용자와 비밀번호, `Authorization`·`Bearer`·`Basic` 뒤의 값, `token`·`password`·`secret`·`api_key` 같은 이름 뒤의 값, `<password>` 요소의 내용입니다. SBOM에는 URL의 사용자와 비밀번호가 들어가지 않습니다. 가리기는 패턴으로 동작하므로, 이름 없이 줄에 토큰만 적힌 경우처럼 어느 패턴에도 맞지 않는 형태는 가려지지 않습니다. cdxgen 로그는 다른 사람에게 보내기 전에 직접 읽어 봅니다.
